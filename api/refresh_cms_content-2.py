# refresh_all_caches.py (Reflecting API fixes)

from datetime import datetime
import os
import hashlib
import pickle
import logging
import json
import sys
import requests
from urllib.parse import unquote, urlparse, urlunparse  # Added for normalization
import redis
from selectolax.parser import HTMLParser
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import urllib3
import concurrent.futures  # Added for parsing concurrency
from time import perf_counter  # Added for timing

# Disable insecure request warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Append parent directory if needed ---
try:
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
            verify_ssl=True,  # Added verify_ssl
        ):
            logging.warning("Using dummy scrape_course_announcements function.")
            return {"error": "Dummy function: Overall announcement section not found"}


# --- Import NTLM and Adapter/Retry ---
try:
    from requests_ntlm import HttpNtlmAuth
except ImportError:
    HttpNtlmAuth = None
    logging.warning("requests_ntlm not installed. NTLM authentication will not work.")
try:
    from urllib3.util import Retry
    from requests.adapters import HTTPAdapter
except ImportError:
    Retry = None
    HTTPAdapter = None
    logging.warning(
        "urllib3 or requests.adapters not available. Using default session settings."
    )

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
        redis_url,
        socket_connect_timeout=15,  # Increased timeout
        socket_timeout=15,
        decode_responses=False,  # Crucial for pickle
    )
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {redis_url}.")
except redis.exceptions.ConnectionError as e:
    logger.error(
        f"Failed to connect to Redis at {redis_url}: {e}. Cache refresh will fail."
    )
    redis_client = None  # Ensure it's None if connection fails
except Exception as e:
    logger.error(
        f"An unexpected error occurred during Redis setup: {e}. Cache refresh will fail.",
        exc_info=True,
    )
    redis_client = None

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
BASE_CMS_URL = "https://cms.guc.edu.eg"  # Added Base URL


# --- URL Normalization Helper (Copied from fixed API) ---
def normalize_course_url(course_url):
    """Normalizes the course URL for consistent caching and requests."""
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
                logger.debug(
                    f"Attempted normalization for URL missing domain: {urlunparse(parsed)}"
                )
            else:
                logger.warning(
                    f"Could not reliably normalize URL missing domain: {course_url}"
                )
                return course_url

        if "courseviewstn" in parsed.path and not parsed.path.endswith(".aspx"):
            parsed = parsed._replace(path=parsed.path + ".aspx")

        return urlunparse(parsed)
    except Exception as e:
        logger.error(f"Error normalizing URL '{course_url}': {e}", exc_info=True)
        return course_url


# --- Unified Cache Key Generator (Copied from fixed API) ---
def generate_cache_key(username, course_url):
    """Generates a consistent cache key based on username and normalized URL."""
    normalized_url = normalize_course_url(course_url)
    key_string = f"{username}:{normalized_url}"
    hash_value = hashlib.md5(key_string.encode("utf-8")).hexdigest()
    # Match the API's key prefix
    return f"cms_content:{hash_value}"


# --- Caching Functions (Adapted from fixed API) ---
def set_in_cache(key, value):
    """Stores data in Redis cache with expiry."""
    if not redis_client:
        logger.debug("Redis client unavailable, skipping cache set.")
        return False
    try:
        # Use highest protocol for potentially better efficiency/compatibility
        pickled_value = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        redis_client.setex(key, CACHE_EXPIRY, pickled_value)
        logger.info(f"Set cache for key {key} with expiry {CACHE_EXPIRY} seconds")
        return True
    except redis.exceptions.TimeoutError:
        logger.warning(f"Redis timeout setting cache for key {key}")
        return False
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Redis connection error setting cache for key {key}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error setting cache for key {key}: {e}", exc_info=True)
        return False


def get_from_cache(key):
    """Retrieves data from Redis cache."""
    if not redis_client:
        logger.debug("Redis client unavailable, skipping cache get.")
        return None
    try:
        data_bytes = redis_client.get(key)
        if data_bytes:
            try:
                logger.info(f"Cache hit for key {key}")
                return pickle.loads(data_bytes)
            except pickle.UnpicklingError as e:
                logger.error(
                    f"Error unpickling cache data for key {key}: {e}. Ignoring cache."
                )
                try:
                    redis_client.delete(key)  # Remove corrupted data
                except Exception as del_e:
                    logger.error(f"Failed to delete corrupted cache key {key}: {del_e}")
                return None
            except Exception as e:
                logger.error(
                    f"Unexpected error unpickling cache for key {key}: {e}",
                    exc_info=True,
                )
                return None
        else:
            logger.info(f"Cache miss for key {key}")
            return None
    except redis.exceptions.TimeoutError:
        logger.warning(f"Redis timeout getting cache for key {key}")
        return None
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Redis connection error getting cache for key {key}: {e}")
        return None
    except Exception as e:
        logger.error(f"Generic error getting cache for key {key}: {e}", exc_info=True)
        return None


# --- Session Management (Adapted from fixed API's create_optimized_session) ---
def get_session(username, password):
    """Creates a requests session with NTLM auth and optimizations."""
    session = requests.Session()
    if username and password and HttpNtlmAuth:
        # Adjust domain prefix if necessary (e.g., 'GUC\\')
        session.auth = HttpNtlmAuth(
            f"{username}", password
        )  # Simplified, adjust if domain needed
    elif username and password and not HttpNtlmAuth:
        logger.error("NTLM auth requested but requests_ntlm not installed.")
        # Depending on requirements, might want to raise an error here

    # Configure retries and pooling
    if Retry and HTTPAdapter:
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(
            pool_connections=16,  # Suitable for a sequential script
            pool_maxsize=16,
            max_retries=retry_strategy,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    else:
        logger.warning(
            "Retry/Adapter libraries not found, using default session settings."
        )

    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
    )
    session.timeout = (15, 30)  # (connect timeout, read timeout)
    return session


# --- Content Parsing Functions (Copied/Adapted from fixed API) ---
def parse_content_item(card):
    """Parses a single content item card."""
    title_div = card.css_first("[id^='content']")
    if not title_div:
        logger.debug("Could not find title div in content card.")
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
                logger.warning(
                    f"Found unusual href format: {href} for title: {title_text}"
                )

    return {"title": title_text, "download_url": download_url}


def parse_single_week(week_div):
    """Parses a single week's data, including description and announcement."""
    week_title_tag = week_div.css_first("h2.text-big")
    if not week_title_tag:
        logger.debug("Could not find week title (h2.text-big).")
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
                    if next_node.tag == "div" and (
                        next_node.css_first("strong")
                        or next_node.css_first(".card.mb-4")
                    ):
                        break
                    next_node = next_node.next

                if "announcement" in header_text:
                    parent_style = div.attributes.get("style", "")
                    if "display:none" not in parent_style.replace(" ", ""):
                        week_data["announcement"] = para_text
                elif "description" in header_text:
                    week_data["description"] = para_text
                elif "content" in header_text:
                    break  # Stop after finding content header

    content_cards = week_div.css("div.p-3 .card.mb-4")
    if content_cards:
        # Sequential parsing might be fine here if not too many items per week
        contents = [parse_content_item(card) for card in content_cards]
        week_data["contents"] = [c for c in contents if c]

    return week_data


def fast_parse_content(html_content):
    """Parses the main content area for weeks using selectolax."""
    if not html_content:
        logger.warning("HTML content provided to fast_parse_content was empty.")
        return []
    try:
        parser = HTMLParser(html_content)
        week_divs = parser.css(".weeksdata")
        if not week_divs:
            logger.warning(
                "No elements found with selector '.weeksdata'. Check CMS page structure or URL."
            )
            return []

        # Process sequentially in refresh script unless performance is an issue
        weeks = [parse_single_week(div) for div in week_divs]
        valid_weeks = [w for w in weeks if w]

        try:

            def get_week_date(week_dict):
                name = week_dict.get("week_name", "")
                try:
                    date_str = name.split(":")[-1].strip()
                    return datetime.strptime(date_str, "%Y-%m-%d")
                except (ValueError, IndexError):
                    return datetime.min

            valid_weeks.sort(key=get_week_date, reverse=True)
        except Exception as sort_err:
            logger.warning(
                f"Could not sort weeks based on date: {sort_err}. Returning in parsed order."
            )

        return valid_weeks
    except Exception as e:
        logger.exception(f"Error during HTML content parsing: {e}")
        return []


# --- Fetch Functions ---
def fetch_cms_content(username, password, course_url):
    """Fetches and parses week content."""
    start_time = perf_counter()
    normalized_url = normalize_course_url(course_url)
    logger.info(f"Fetching CMS content for {username} - {normalized_url}")
    session = get_session(username, password)
    try:
        response = session.get(
            normalized_url, timeout=session.timeout, verify=VERIFY_SSL
        )

        if response.status_code == 401:
            logger.error(
                f"Authentication failed (401) for {username} - {normalized_url}"
            )
            return None  # Indicate auth failure
        response.raise_for_status()  # Raise HTTPError for other bad responses (4xx or 5xx)

        html_content = response.text
        if not html_content:
            logger.warning(
                f"Received empty HTML content for {username} - {normalized_url}"
            )
            return None  # Treat empty content as failure

        # Check for login page again after potential redirects
        temp_parser = HTMLParser(html_content)
        page_title_node = temp_parser.css_first("title")
        page_title = page_title_node.text().lower() if page_title_node else ""
        if "login" in page_title or "sign in" in page_title:
            login_form = temp_parser.css_first("form[action*='login']")
            if login_form:
                logger.error(
                    f"Authentication failed (redirect to login) for {username} - {normalized_url}"
                )
                return None  # Indicate auth failure

        content = fast_parse_content(html_content)
        # We consider empty parsed content a failure for caching purposes here
        if not content:
            logger.warning(
                f"Parsed content is empty for {username} - {normalized_url}. Check page structure."
            )
            return None
        logger.info(
            f"Successfully parsed content for {username} - {normalized_url} in {(perf_counter() - start_time)*1000:.2f} ms"
        )
        return content
    except requests.exceptions.Timeout as e:
        logger.error(
            f"Timeout fetching CMS content for {username} - {normalized_url}: {e}"
        )
        return None
    except requests.exceptions.HTTPError as e:
        logger.error(
            f"HTTP error {e.response.status_code} fetching CMS content for {username} - {normalized_url}: {e}"
        )
        return None  # Indicate failure
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
    """Fetches overall course announcements."""
    start_time = perf_counter()
    normalized_url = normalize_course_url(course_url)
    logger.info(f"Fetching announcements for {username} - {normalized_url}")
    try:
        # Pass verify_ssl to the imported function
        announcements_result = scrape_course_announcements(
            username,
            password,
            normalized_url,
            max_retries=2,
            retry_delay=1,
        )

        # Check the structure of the result
        if (
            isinstance(announcements_result, dict)
            and "announcements_html" in announcements_result
        ):
            html = announcements_result["announcements_html"]
            if html:  # Ensure HTML is not empty
                logger.info(
                    f"Successfully fetched announcements for {username} - {normalized_url} in {(perf_counter() - start_time)*1000:.2f} ms"
                )
                return announcements_result  # Return the dict { "announcements_html": "..." }
            else:
                logger.warning(
                    f"Empty announcement HTML found for {username} - {normalized_url}"
                )
                return None
        elif isinstance(announcements_result, dict) and "error" in announcements_result:
            logger.error(
                f"Announcement scraping failed for {username} - {normalized_url}: {announcements_result['error']}"
            )
            return None
        else:
            logger.warning(
                f"No valid announcements found or unexpected result for {username} - {normalized_url}"
            )
            return None
    except Exception as e:
        logger.exception(
            f"Error fetching announcements for {username} - {normalized_url}: {e}"
        )
        return None


# --- Refresh All Caches ---
def refresh_all_caches():
    """Iterates through users and courses, fetches data, and updates cache."""
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

    for username_bytes, encrypted_pw in stored_users.items():
        processed_users += 1
        username = username_bytes.decode("utf-8", "ignore")
        logger.info(f"Processing user {processed_users}/{total_users}: {username}")

        try:
            password = fernet.decrypt(encrypted_pw).decode().strip()
        except Exception as e:
            logger.error(
                f"Error decrypting credentials for {username}: {e}. Skipping user."
            )
            continue

        # Get user's course list (adjust key if needed)
        course_list_key = f"cms:{username}"  # Key storing the list of course URLs/dicts
        try:
            course_data_bytes = redis_client.get(course_list_key)
            if not course_data_bytes:
                logger.warning(
                    f"No course list found for user {username} under key '{course_list_key}'. Skipping user."
                )
                continue

            # Attempt to decode as JSON list of dicts, fallback to comma-separated string
            try:
                courses_raw = json.loads(course_data_bytes.decode("utf-8"))
                if not isinstance(courses_raw, list):
                    logger.error(
                        f"Course data for {username} is not a list. Skipping. Data: {courses_raw!r}"
                    )
                    continue
                courses = courses_raw
            except (json.JSONDecodeError, UnicodeDecodeError):
                try:
                    # Fallback: Assume comma-separated URLs
                    courses = [
                        url.strip()
                        for url in course_data_bytes.decode("utf-8").split(",")
                        if url.strip()
                    ]
                    logger.warning(
                        f"Interpreted course data for {username} as comma-separated URLs."
                    )
                except Exception as decode_err:
                    logger.error(
                        f"Could not decode/parse course data for {username}: {decode_err}. Skipping user."
                    )
                    continue

        except Exception as e:
            logger.error(
                f"Error retrieving course list for {username} from key '{course_list_key}': {e}. Skipping user."
            )
            continue

        logger.info(f"User {username} has {len(courses)} courses.")
        for course_entry in courses:
            course_url = None
            course_name = "Unknown Course"
            try:
                if isinstance(course_entry, dict):
                    course_url = course_entry.get("course_url")
                    course_name = course_entry.get(
                        "course_name", course_url or "Unknown"
                    )
                elif isinstance(course_entry, str):
                    course_url = course_entry
                    course_name = course_url  # Use URL as name if only URL is stored

                if not course_url or not course_url.startswith("http"):
                    logger.error(
                        f"Invalid or missing course URL for {username}: {course_entry!r}. Skipping course."
                    )
                    continue

                normalized_url = normalize_course_url(course_url)
                cache_key = generate_cache_key(
                    username, normalized_url
                )  # Use normalized URL for key

                logger.debug(
                    f"Refreshing cache for {username} - {course_name} ({normalized_url})"
                )

                # Get existing cache to preserve parts if needed
                existing_cache_list = get_from_cache(cache_key)
                existing_announcement_dict = None
                existing_content_list = []
                if isinstance(existing_cache_list, list) and existing_cache_list:
                    if "course_announcement" in existing_cache_list[0]:
                        existing_announcement_dict = existing_cache_list[0]
                        existing_content_list = existing_cache_list[1:]
                    else:
                        existing_content_list = existing_cache_list

                # Fetch new data
                # Use concurrent futures to fetch content and announcements simultaneously
                new_content_list = None
                new_announcement_dict = None
                fetch_success = False

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
                        new_content_list = (
                            content_future.result()
                        )  # Returns list of weeks or None
                        if new_content_list is not None:
                            fetch_success = True
                    except Exception as e:
                        logger.error(
                            f"Exception in content fetch future for {username} - {normalized_url}: {e}"
                        )

                    try:
                        new_announcement_dict = (
                            announcement_future.result()
                        )  # Returns dict or None
                        if new_announcement_dict is not None:
                            fetch_success = True
                    except Exception as e:
                        logger.error(
                            f"Exception in announcement fetch future for {username} - {normalized_url}: {e}"
                        )

                # Decide what to cache based on success and existing data
                if not fetch_success:
                    logger.warning(
                        f"Both content and announcement fetch failed for {username} - {course_name}. Cache not updated."
                    )
                    continue  # Skip cache update if both failed

                # Prepare combined data for caching
                combined_data_for_cache = []

                # Use new announcement if available, else keep old one
                final_announcement = (
                    new_announcement_dict
                    if new_announcement_dict is not None
                    else existing_announcement_dict
                )
                if final_announcement:
                    combined_data_for_cache.append(final_announcement)

                # Use new content if available, else keep old one
                final_content = (
                    new_content_list
                    if new_content_list is not None
                    else existing_content_list
                )
                if final_content:  # Ensure final_content is not empty list
                    combined_data_for_cache.extend(final_content)

                # Only update cache if we have *some* data to store
                if combined_data_for_cache:
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
                        f"Skipped cache update for {username} - {course_name} - resulted in empty data."
                    )

            except Exception as course_err:
                logger.exception(
                    f"Error processing course {course_entry!r} for user {username}: {course_err}"
                )

    logger.info("Finished full cache refresh.")


if __name__ == "__main__":
    start = perf_counter()
    refresh_all_caches()
    end = perf_counter()
    logger.info(f"Cache refresh script finished in {end - start:.2f} seconds.")
