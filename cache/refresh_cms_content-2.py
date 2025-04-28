# refresh_all_caches.py (Corrected to use 'course_announcement' key without extra data)

import os
import hashlib
import pickle
import logging
import json
import sys
import requests
from urllib.parse import unquote, urlparse, urlunparse
import redis
from selectolax.parser import HTMLParser
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import urllib3
import concurrent.futures
from time import perf_counter
from datetime import datetime  # Added for sorting

# Disable insecure request warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Append parent directory if needed ---
try:
    # Assumes scrape_course_announcements returns {"announcements_html": "..."} on success
    from api.scraping import scrape_course_announcements
except ImportError:
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from api.scraping import scrape_course_announcements
    except ImportError:
        logging.error(
            "Could not import scrape_course_announcements from api.scraping. Using dummy function.",
            exc_info=True,
        )

        def scrape_course_announcements(
            username,
            password,
            course_url,
            max_retries=2,
            retry_delay=1,
        ):
            logging.warning("Using dummy scrape_course_announcements function.")
            # Simulate returning the structure expected by fetch_announcements
            # return {"announcements_html": "<p>Dummy Announcement</p>"}
            return {"error": "Dummy function: Overall announcement section not found"}


# --- Import NTLM and Adapter/Retry ---
try:
    from requests_ntlm import HttpNtlmAuth
except ImportError:
    HttpNtlmAuth = None
    logging.warning("requests_ntlm not installed.")
try:
    from urllib3.util import Retry
    from requests.adapters import HTTPAdapter
except ImportError:
    Retry = None
    HTTPAdapter = None
    logging.warning("urllib3/adapters not available.")

# Load environment variables
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("refresh_all_caches")

# --- Redis Setup ---
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = None
try:
    redis_client = redis.Redis.from_url(
        redis_url, socket_connect_timeout=15, socket_timeout=15, decode_responses=False
    )
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {redis_url}.")
except Exception as e:
    logger.critical(f"Failed to connect to Redis at {redis_url}: {e}. Aborting.")
    redis_client = None
    # sys.exit(1) # Optional: Exit if Redis is critical

# --- Encryption Setup ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable must be set")
try:
    fernet = Fernet(ENCRYPTION_KEY.encode())
except Exception as e:
    raise ValueError(f"Invalid ENCRYPTION_KEY format: {e}")

# --- Config ---
CACHE_EXPIRY = 14400  # 4 hours
VERIFY_SSL = os.environ.get("VERIFY_SSL", "True").lower() == "true"
BASE_CMS_URL = "https://cms.guc.edu.eg"


# --- URL Normalization & Cache Key (Keep as before) ---
def normalize_course_url(course_url):
    if not course_url:
        return ""
    try:
        decoded = unquote(course_url).strip().lower()
        parsed = urlparse(decoded)
        if not parsed.scheme:
            parsed = parsed._replace(scheme="https")
        if not parsed.netloc:
            if "cms.guc.edu.eg" in parsed.path:
                domain_start_index = parsed.path.find("cms.guc.edu.eg")
                new_netloc = parsed.path[domain_start_index:].split("/")[0]
                new_path = "/" + "/".join(
                    parsed.path[domain_start_index:].split("/")[1:]
                )
                parsed = parsed._replace(
                    netloc=new_netloc, path=new_path if new_path != "/" else ""
                )
            else:
                # If domain cannot be inferred, return original or handle error
                logger.warning(
                    f"Could not reliably normalize URL missing domain: {course_url}"
                )
                return course_url
        if "courseviewstn" in parsed.path and not parsed.path.endswith(".aspx"):
            parsed = parsed._replace(path=parsed.path + ".aspx")
        return urlunparse(parsed)
    except Exception as e:
        logger.error(f"Error normalizing URL '{course_url}': {e}")
        return course_url


def generate_cache_key(username, course_url):
    normalized_url = normalize_course_url(course_url)
    key_string = f"{username}:{normalized_url}"
    hash_value = hashlib.md5(key_string.encode("utf-8")).hexdigest()
    return f"cms_content:{hash_value}"


# --- Caching Functions (Keep as before) ---
def set_in_cache(key, value):
    if not redis_client:
        return False
    try:
        pickled_value = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        redis_client.setex(key, CACHE_EXPIRY, pickled_value)
        logger.info(f"Set cache for key {key} with expiry {CACHE_EXPIRY} seconds")
        return True
    except Exception as e:
        logger.error(f"Error setting cache for key {key}: {e}")
        return False


def get_from_cache(key):
    if not redis_client:
        return None
    try:
        data_bytes = redis_client.get(key)
        if data_bytes:
            try:
                logger.info(f"Cache hit for key {key}")
                return pickle.loads(data_bytes)
            except Exception as e:
                logger.error(f"Error unpickling cache for key {key}: {e}")
                # Optionally delete corrupted key
                # try: redis_client.delete(key) except: pass
                return None
        else:
            logger.info(f"Cache miss for key {key}")
            return None
    except Exception as e:
        logger.error(f"Error getting cache for key {key}: {e}")
        return None


# --- Session Management (Keep as before) ---
def get_session(username, password):
    session = requests.Session()
    if username and password and HttpNtlmAuth:
        session.auth = HttpNtlmAuth(f"{username}", password)
    elif username and password and not HttpNtlmAuth:
        logger.error("NTLM auth requested but requests_ntlm not installed.")
    if Retry and HTTPAdapter:
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(
            pool_connections=16, pool_maxsize=16, max_retries=retry_strategy
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    else:
        logger.warning("Retry/Adapter libs not found.")
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
    )
    session.timeout = (15, 30)  # (connect, read)
    return session


# --- Content Parsing Functions (Keep as before) ---
def parse_content_item(card):
    title_div = card.css_first("[id^='content']")
    if not title_div:
        return None
    title_text = (
        title_div.text(strip=True, separator=" ")
        .replace("\n", " ")
        .replace("\r", "")
        .strip()
    )
    download_link_node = card.css_first("a#download")
    download_url = None
    if download_link_node:
        href = download_link_node.attributes.get("href")
        if href:
            if href.startswith("/"):
                download_url = BASE_CMS_URL + href
            elif href.startswith("http"):
                download_url = href
            else:
                logger.warning(f"Unusual href: {href}")
    return {"title": title_text, "download_url": download_url}


def parse_single_week(week_div):
    week_title_tag = week_div.css_first("h2.text-big")
    if not week_title_tag:
        return None
    week_name = week_title_tag.text(strip=True)
    week_data = {
        "week_name": week_name,
        "announcement": "",
        "description": "",
        "contents": [],
    }
    p3_div = week_div.css_first("div.p-3")
    if p3_div:
        info_divs = p3_div.css("div")
        for div in info_divs:
            strong_tag = div.css_first("strong")
            if strong_tag:
                header_text = strong_tag.text(strip=True).lower()
                next_node = div.next
                para_text = ""
                while next_node:
                    if next_node.tag == "p" and "m-2" in next_node.attributes.get(
                        "class", ""
                    ):
                        para_text = (
                            next_node.text(strip=True, separator=" ")
                            .replace("\n", " ")
                            .replace("\r", "")
                            .strip()
                        )
                        break
                    # Stop condition: next strong header or content card section
                    if next_node.tag == "div" and (
                        next_node.css_first("strong")
                        or next_node.css_first(".card.mb-4")
                    ):
                        break
                    next_node = next_node.next
                if "announcement" in header_text:
                    # Check if the announcement div itself is hidden
                    if "display:none" not in div.attributes.get("style", "").replace(
                        " ", ""
                    ):
                        week_data["announcement"] = para_text
                elif "description" in header_text:
                    week_data["description"] = para_text
                elif "content" in header_text:
                    # Found the content section, no need to check further divs for announcement/description
                    break
    content_cards = week_div.css("div.p-3 .card.mb-4")
    if content_cards:
        contents = [parse_content_item(card) for card in content_cards]
        week_data["contents"] = [c for c in contents if c]
    return week_data


def fast_parse_content(html_content):
    if not html_content:
        return []
    try:
        parser = HTMLParser(html_content)
        week_divs = parser.css(".weeksdata")
        if not week_divs:
            logger.warning("No '.weeksdata' elements found.")
            return []
        weeks = [parse_single_week(div) for div in week_divs]
        valid_weeks = [w for w in weeks if w]
        try:
            # Sort weeks by date (newest first)
            def get_week_date(week_dict):
                name = week_dict.get("week_name", "")
                try:
                    # Assumes format "Week: YYYY-MM-DD"
                    date_str = name.split(":")[-1].strip()
                    return datetime.strptime(date_str, "%Y-%m-%d")
                except (ValueError, IndexError):
                    # Return a very old date for weeks without a parsable date
                    return datetime.min

            valid_weeks.sort(key=get_week_date, reverse=True)
        except Exception as sort_err:
            logger.warning(f"Could not sort weeks: {sort_err}")
        return valid_weeks
    except Exception as e:
        logger.exception(f"Error parsing HTML: {e}")
        return []


# --- Fetch Functions ---
def fetch_cms_content(username, password, course_url):
    # Returns list of week dicts, or None on failure
    start_time = perf_counter()
    normalized_url = normalize_course_url(course_url)
    logger.info(f"Fetching CMS content for {username} - {normalized_url}")
    session = get_session(username, password)
    try:
        response = session.get(
            normalized_url, timeout=session.timeout, verify=VERIFY_SSL
        )
        if response.status_code == 401:
            logger.error(f"Auth failed (401) for {username} - {normalized_url}")
            return None  # Indicate failure
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        html_content = response.text
        if not html_content:
            logger.warning(f"Empty HTML for {username} - {normalized_url}")
            return None  # Indicate failure

        # Quick check for login page redirection
        temp_parser = HTMLParser(html_content)
        page_title_node = temp_parser.css_first("title")
        page_title = page_title_node.text().lower() if page_title_node else ""
        if "login" in page_title or "sign in" in page_title:
            # More robust check: look for a login form
            if temp_parser.css_first("form[action*='login']"):
                logger.error(
                    f"Auth failed (login redirect) for {username} - {normalized_url}"
                )
                return None  # Indicate failure

        content = fast_parse_content(html_content)
        # Check if content parsing actually returned something meaningful
        if content is None:  # Parsing error occurred
            logger.warning(f"Content parsing failed for {username} - {normalized_url}.")
            return None  # Indicate failure
        # If parsing succeeded but found nothing, content will be []
        # We might still want to cache this empty result if announcements were found.

        logger.info(
            f"Parsed content for {username} - {normalized_url} in {(perf_counter() - start_time)*1000:.2f} ms"
        )
        return content  # Return list (possibly empty)
    except requests.exceptions.Timeout as e:
        logger.error(
            f"Timeout fetching CMS content for {username} - {normalized_url}: {e}"
        )
        return None
    except requests.exceptions.HTTPError as e:
        logger.error(
            f"HTTP error {e.response.status_code} fetching CMS content for {username} - {normalized_url}: {e}"
        )
        return None
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Network error fetching CMS content for {username} - {normalized_url}: {e}"
        )
        return None
    except Exception as e:
        logger.exception(
            f"Unexpected error fetching/parsing CMS content for {username} - {normalized_url}: {e}"
        )
        return None


def fetch_announcements(username, password, course_url):
    # Returns dict {"announcements_html": "..."} or None on failure/empty
    # The calling function (refresh_all_caches) will transform this.
    start_time = perf_counter()
    normalized_url = normalize_course_url(course_url)
    logger.info(f"Fetching announcements for {username} - {normalized_url}")
    try:
        # Assuming scrape_course_announcements returns {"announcements_html": "..."} on success
        # or {"error": "..."} on failure.
        announcements_result = scrape_course_announcements(
            username,
            password,
            normalized_url,
            max_retries=2,
            retry_delay=1,
        )

        # Check if the result is a dictionary and contains the expected key
        if (
            isinstance(announcements_result, dict)
            and "announcements_html" in announcements_result
        ):
            html = announcements_result["announcements_html"]
            if html and html.strip():  # Ensure HTML is not just whitespace
                logger.info(
                    f"Fetched announcements for {username} - {normalized_url} in {(perf_counter() - start_time)*1000:.2f} ms"
                )
                # Return the dict as received from scrape_course_announcements
                return announcements_result
            else:
                logger.warning(
                    f"Empty or whitespace-only announcement HTML for {username} - {normalized_url}"
                )
                return None  # Treat empty HTML as failure for caching purposes
        elif isinstance(announcements_result, dict) and "error" in announcements_result:
            logger.error(
                f"Announce scrape failed for {username} - {normalized_url}: {announcements_result['error']}"
            )
            return None  # Indicate failure
        else:
            # Handle cases where scrape_course_announcements might return None or unexpected types
            logger.warning(
                f"No valid announcements found or unexpected return type ({type(announcements_result)}) for {username} - {normalized_url}"
            )
            return None  # Indicate failure
    except Exception as e:
        logger.exception(
            f"Error fetching announcements for {username} - {normalized_url}: {e}"
        )
        return None  # Indicate failure


# --- Refresh All Caches ---
def refresh_all_caches():
    """Iterates through users and courses, fetches data, and updates cache
    WITH Mock Week included in the correct position, using 'course_announcement' key.
    """
    if not redis_client:
        logger.critical("Redis client is not available. Aborting cache refresh.")
        return

    logger.info("Starting full cache refresh for all users...")
    try:
        stored_users = redis_client.hgetall("user_credentials")
    except Exception as e:
        logger.critical(
            f"Failed to retrieve user credentials from Redis: {e}. Aborting."
        )
        return

    if not stored_users:
        logger.info("No stored users found in 'user_credentials'.")
        return

    total_users = len(stored_users)
    processed_users = 0
    logger.info(f"Found {total_users} users to process.")

    # --- Define Mock Week Once ---
    mock_week = {
        "week_name": "Mock Week",
        "announcement": "",
        "description": "Placeholder for layout",
        "contents": [],
    }

    for username_bytes, encrypted_pw in stored_users.items():
        processed_users += 1
        username = username_bytes.decode("utf-8", "ignore")
        logger.info(f"Processing user {processed_users}/{total_users}: {username}")

        # Skip seif.elkady user
        if username.lower() == "seif.elkady":
            logger.info(f"Skipping user {username} as requested")
            continue

        try:
            password = fernet.decrypt(encrypted_pw).decode().strip()
        except Exception as e:
            logger.error(
                f"Error decrypting credentials for {username}: {e}. Skipping user."
            )
            continue

        course_list_key = f"cms:{username}"
        try:
            course_data_bytes = redis_client.get(course_list_key)
            if not course_data_bytes:
                logger.warning(
                    f"No course list for {username} under key '{course_list_key}'. Skipping."
                )
                continue

            # Try parsing as JSON list of dicts first
            try:
                courses_raw = json.loads(course_data_bytes.decode("utf-8"))
                if not isinstance(courses_raw, list):
                    raise TypeError("Course data is not a list")
                # Ensure all items are either strings (URLs) or dicts with 'course_url'
                courses = []
                for item in courses_raw:
                    if isinstance(item, dict) and "course_url" in item:
                        courses.append(item)
                    elif isinstance(item, str):
                        # Convert old string format to new dict format for consistency
                        courses.append({"course_name": item, "course_url": item})
                    else:
                        logger.warning(
                            f"Skipping invalid course entry for {username}: {item!r}"
                        )
                if not courses:
                    logger.warning(
                        f"No valid course entries found after parsing for {username}"
                    )
                    continue

            except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as json_err:
                # Fallback to comma-separated string list (old format)
                logger.debug(
                    f"Failed to parse course list as JSON for {username}, falling back to string split: {json_err}"
                )
                try:
                    courses_str = course_data_bytes.decode("utf-8")
                    courses = [
                        {"course_name": url.strip(), "course_url": url.strip()}
                        for url in courses_str.split(",")
                        if url.strip()
                    ]
                    if not courses:
                        logger.warning(
                            f"No valid course URLs found after string split for {username}"
                        )
                        continue
                except Exception as decode_err:
                    logger.error(
                        f"Cannot parse course data for {username} (both JSON and string split failed): {decode_err}"
                    )
                    continue

        except Exception as e:
            logger.error(f"Error getting/parsing course list for {username}: {e}")
            continue

        logger.info(f"User {username} has {len(courses)} courses.")
        for course_entry in courses:
            course_url = None
            course_name = "Unknown"
            try:
                # Extract URL and Name consistently
                if isinstance(course_entry, dict):
                    course_url = course_entry.get("course_url")
                    course_name = course_entry.get(
                        "course_name", course_url or "Unknown"
                    )
                elif isinstance(
                    course_entry, str
                ):  # Should not happen with conversion above, but keep for safety
                    course_url = course_entry
                    course_name = course_url
                else:
                    logger.error(
                        f"Invalid course entry type for {username}: {type(course_entry)} - {course_entry!r}"
                    )
                    continue

                if (
                    not course_url
                    or not isinstance(course_url, str)
                    or not course_url.startswith("http")
                ):
                    logger.error(
                        f"Invalid or missing URL for {username}: {course_entry!r}"
                    )
                    continue

                normalized_url = normalize_course_url(course_url)
                if not normalized_url:  # Normalization failed
                    logger.error(
                        f"Skipping course due to normalization failure: {course_url}"
                    )
                    continue

                cache_key = generate_cache_key(username, normalized_url)

                logger.debug(
                    f"Refreshing cache for {username} - {course_name} ({normalized_url})"
                )

                # Fetch new data concurrently
                new_content_list = (
                    None  # Expected: list of week dicts, or None on failure
                )
                # Fetches {"announcements_html": "..."} or None
                announcement_fetch_result = None
                fetch_success = False  # Track if *any* part succeeded

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="FetchCourse"
                ) as executor:
                    content_future = executor.submit(
                        fetch_cms_content, username, password, normalized_url
                    )
                    announcement_future = executor.submit(
                        fetch_announcements, username, password, normalized_url
                    )
                    try:
                        new_content_list = content_future.result()
                        # fetch_cms_content returns [] for success but no weeks, None for failure
                        if new_content_list is not None:
                            fetch_success = True
                    except Exception as e:
                        logger.error(
                            f"Content fetch future error for {normalized_url}: {e}",
                            exc_info=True,
                        )
                    try:
                        announcement_fetch_result = announcement_future.result()
                        # fetch_announcements returns dict on success, None on failure/empty
                        if announcement_fetch_result is not None:
                            fetch_success = True
                    except Exception as e:
                        logger.error(
                            f"Announcement fetch future error for {normalized_url}: {e}",
                            exc_info=True,
                        )

                if not fetch_success:
                    logger.warning(
                        f"Both content and announcement fetch failed for {username} - {course_name} ({normalized_url}). Cache not updated."
                    )
                    continue  # Skip caching if both fetches failed

                # --- Assemble data WITH Mock Week for caching ---
                # The final structure should be: [CourseAnnouncementDict?, MockWeekDict, WeekDict1, WeekDict2, ...]
                combined_data_for_cache = []
                course_announcement_dict_to_add = None  # The dict to potentially add

                # 1. Transform Announcement (if fetch was successful)
                if announcement_fetch_result and isinstance(
                    announcement_fetch_result, dict
                ):
                    html_content = announcement_fetch_result.get("announcements_html")
                    if html_content and html_content.strip():
                        # *** Create the new dict with the desired key 'course_announcement' ***
                        course_announcement_dict_to_add = {
                            "course_announcement": html_content
                        }
                        combined_data_for_cache.append(course_announcement_dict_to_add)
                    else:
                        # Log if HTML was present but empty/whitespace
                        if html_content is not None:
                            logger.info(
                                f"Overall announcement HTML was empty/whitespace for {normalized_url}"
                            )
                elif (
                    announcement_fetch_result is not None
                ):  # Log unexpected format from fetch_announcements
                    logger.warning(
                        f"fetch_announcements returned unexpected format: {announcement_fetch_result!r}"
                    )

                # 2. Add Mock Week
                combined_data_for_cache.append(mock_week)

                # 3. Add Actual Weeks (only if fetch was successful and returned a list)
                if (
                    new_content_list is not None
                ):  # Check for None (failure), allow empty list []
                    if isinstance(new_content_list, list):
                        combined_data_for_cache.extend(new_content_list)
                    else:
                        logger.warning(
                            f"fetch_cms_content returned unexpected format: {new_content_list!r}"
                        )
                # --- End Assembly ---

                # --- Log exactly what is being prepared for cache ---
                cached_item_summary = []
                for item in combined_data_for_cache:
                    if isinstance(item, dict):
                        # *** Check for the new key 'course_announcement' ***
                        if "course_announcement" in item:
                            cached_item_summary.append("Overall Course Announcement")
                        elif "week_name" in item:
                            cached_item_summary.append(f"Week: {item['week_name']}")
                        else:
                            cached_item_summary.append("Unknown Dict Item")
                    else:
                        cached_item_summary.append(f"Unknown Item Type: {type(item)}")

                logger.debug(
                    f"Data prepared for cache key {cache_key} (Items: {len(combined_data_for_cache)}): {cached_item_summary}"
                )
                # --- End Logging ---

                # Update cache only if we have more than just Mock Week,
                # OR if we have exactly Mock Week AND the course announcement dict.
                has_announcement = course_announcement_dict_to_add is not None
                has_content_weeks = isinstance(new_content_list, list) and bool(
                    new_content_list
                )

                if has_announcement or has_content_weeks:
                    if set_in_cache(cache_key, combined_data_for_cache):
                        logger.info(
                            f"Successfully refreshed cache for {username} - {course_name}"
                        )
                    else:
                        logger.error(
                            f"Failed to set cache for {username} - {course_name}"
                        )
                else:
                    logger.warning(
                        f"Skipped cache update for {username} - {course_name} - resulted in only Mock Week and no announcement."
                    )

            except Exception as course_err:
                logger.exception(
                    f"Error processing course {course_entry!r} for user {username}: {course_err}"
                )

    logger.info("Finished full cache refresh.")


# --- Main Execution ---
if __name__ == "__main__":
    start = perf_counter()
    try:
        refresh_all_caches()
        end = perf_counter()
        logger.info(f"Cache refresh script finished in {end - start:.2f} seconds.")
    except KeyboardInterrupt:
        logger.info("Script interrupted by user. Exiting gracefully.")
    except Exception as e:
        logger.exception(f"Unexpected error in main execution: {e}")
        end = perf_counter()
        logger.info(
            f"Cache refresh script terminated with error after {end - start:.2f} seconds."
        )
