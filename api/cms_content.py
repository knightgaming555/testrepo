# cms_content_api.py (Rewritten and Corrected)

import os
import hashlib
import pickle
import logging
import json
import threading
import concurrent.futures
from urllib.parse import unquote, urlparse, urlunparse
import sys
from time import perf_counter
from datetime import datetime, timezone
from flask import Flask, request, jsonify, g
from dotenv import load_dotenv
import atexit  # For graceful shutdown
import traceback  # For detailed error logging

# --- Append parent directory if needed ---
# Adjust this path if your 'api' directory is located differently
try:
    # Assuming the script is run from the directory containing the 'api' folder
    # or that the 'api' folder's parent is already in sys.path
    from api.scraping import scrape_course_announcements
except ImportError:
    # Fallback if the structure is different or import fails
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
        from api.scraping import scrape_course_announcements
    except ImportError:
        logging.error(
            "Could not import scrape_course_announcements from api.scraping. Using dummy function.",
            exc_info=True,
        )

        # Provide a dummy function if the import fails
        def scrape_course_announcements(
            username, password, course_url, max_retries=2, retry_delay=1
        ):
            logging.warning("Using dummy scrape_course_announcements function.")
            # Return an error structure similar to what the real function might return on failure
            return {"error": "Dummy function: Overall announcement section not found"}


# --- Import necessary libraries ---
try:
    import redis
    import requests
    from selectolax.parser import HTMLParser

    # Import NTLM auth if used
    try:
        from requests_ntlm import HttpNtlmAuth
    except ImportError:
        HttpNtlmAuth = None  # Define as None if not installed
        logging.warning(
            "requests_ntlm not installed. NTLM authentication will not work."
        )
    # Import requests adapters if available
    try:
        from urllib3.util import Retry
        from requests.adapters import HTTPAdapter
    except ImportError:
        Retry = None
        HTTPAdapter = None
        logging.warning(
            "urllib3 or requests.adapters not available. Using default session settings."
        )

except ImportError as e:
    logging.critical(
        f"Missing required library: {e}. Please install requirements.", exc_info=True
    )
    sys.exit(f"Missing required library: {e}")

# Load environment variables
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s",
)
logger = logging.getLogger("cms_content_api")

# --- Redis Setup ---
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = None
try:
    redis_client = redis.Redis.from_url(
        redis_url,
        socket_connect_timeout=5,
        socket_timeout=5,
        decode_responses=False,  # Use bytes for pickle
    )
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {redis_url}.")
except redis.exceptions.ConnectionError as e:
    logger.error(
        f"Failed to connect to Redis at {redis_url}: {e}. Cache will be disabled."
    )
    redis_client = None
except Exception as e:
    logger.error(
        f"An unexpected error occurred during Redis setup: {e}. Cache will be disabled.",
        exc_info=True,
    )
    redis_client = None

# --- Config ---
CACHE_EXPIRY = 14400  # 4 hours for combined content+announcements
BASE_CMS_URL = "https://cms.guc.edu.eg"  # Base URL for relative links


# --- URL Normalization Helper ---
def normalize_course_url(course_url):
    """Normalizes the course URL for consistent caching and requests."""
    if not course_url:
        return ""
    try:
        decoded = unquote(course_url).strip().lower()
        parsed = urlparse(decoded)

        # Ensure scheme and netloc are present
        if not parsed.scheme:
            parsed = parsed._replace(scheme="https")
        if not parsed.netloc:
            # Try to fix common case where domain is in path
            if "cms.guc.edu.eg" in parsed.path:
                # Find the start of the domain in the path
                domain_start_index = parsed.path.find("cms.guc.edu.eg")
                new_netloc = parsed.path[domain_start_index:].split("/")[
                    0
                ]  # Extract domain
                new_path = "/" + "/".join(
                    parsed.path[domain_start_index:].split("/")[1:]
                )  # Get remaining path
                parsed = parsed._replace(
                    netloc=new_netloc, path=new_path if new_path != "/" else ""
                )
                logger.info(
                    f"Attempted normalization for URL missing domain: {urlunparse(parsed)}"
                )
            else:
                logger.warning(
                    f"Could not reliably normalize URL missing domain: {course_url}"
                )
                return course_url  # Return original if unsure

        # Ensure path ends correctly
        if "courseviewstn" in parsed.path and not parsed.path.endswith(".aspx"):
            parsed = parsed._replace(path=parsed.path + ".aspx")

        # Remove redundant query parameters if necessary (e.g., sid if not needed for caching)
        # query_params = parse_qs(parsed.query)
        # query_params.pop('sid', None) # Example: remove sid
        # parsed = parsed._replace(query=urlencode(query_params, doseq=True))

        return urlunparse(parsed)
    except Exception as e:
        logger.error(f"Error normalizing URL '{course_url}': {e}", exc_info=True)
        return course_url  # Return original on error


# --- Unified Cache Key Generator ---
def generate_cache_key(username, course_url):
    """Generates a consistent cache key based on username and normalized URL."""
    normalized_url = normalize_course_url(course_url)
    key_string = f"{username}:{normalized_url}"  # User-specific cache
    hash_value = hashlib.md5(key_string.encode("utf-8")).hexdigest()
    return f"cms_content:{hash_value}"


# --- Caching Functions ---
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


def set_in_cache(key, value, expiry=CACHE_EXPIRY):
    """Stores data in Redis cache with expiry."""
    if not redis_client:
        logger.debug("Redis client unavailable, skipping cache set.")
        return False
    try:
        pickled_value = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        redis_client.setex(key, expiry, pickled_value)
        logger.info(f"Set cache for key {key} with expiry {expiry} seconds")
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


# --- Session Management ---
thread_local = threading.local()


def get_session(username, password):
    """Gets or creates a thread-local requests session."""
    current_auth = (username, password)
    session = getattr(thread_local, "session", None)
    session_auth = getattr(thread_local, "session_auth", None)

    if session is None or session_auth != current_auth:
        logger.info(f"Creating new session for user {username}")
        thread_local.session = create_optimized_session(username, password)
        thread_local.session_auth = current_auth
    return thread_local.session


def create_optimized_session(username, password):
    """Creates a requests session with NTLM auth and optimizations."""
    session = requests.Session()
    if username and password and HttpNtlmAuth:
        # Adjust domain prefix if necessary (e.g., 'GUC\\')
        session.auth = HttpNtlmAuth(
            f"{username}", password
        )  # Simplified, adjust if domain needed
    elif username and password and not HttpNtlmAuth:
        logger.error("NTLM auth requested but requests_ntlm not installed.")
        # Consider raising an error or returning None depending on desired behavior
        # raise ImportError("requests_ntlm is required for authentication but not installed.")

    # Configure retries and pooling
    if Retry and HTTPAdapter:
        retry_strategy = Retry(
            total=2,  # Reduced retries
            backoff_factor=0.5,  # Slightly longer backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(
            pool_connections=16,  # Reduced pool size
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
            "Connection": "keep-alive",  # Explicitly keep-alive
        }
    )
    session.timeout = (15, 30)  # (connect timeout, read timeout) in seconds
    return session


# --- Content Parsing Functions ---
def parse_content_item(card):
    """Parses a single content item card."""
    title_div = card.css_first("[id^='content']")
    if not title_div:
        logger.debug("Could not find title div in content card.")
        return None

    # Extract title text cleanly
    title_text = (
        title_div.text(strip=True, separator=" ")
        .replace("\n", " ")
        .replace("\r", "")
        .strip()
    )

    # Find download link (handle both potential structures)
    download_link_node = card.css_first("a#download")
    download_url = None
    if download_link_node:
        href = download_link_node.attributes.get("href")
        if href:
            # Make URL absolute if relative
            if href.startswith("/"):
                download_url = BASE_CMS_URL + href
            elif href.startswith("http"):
                download_url = href
            else:
                logger.warning(
                    f"Found unusual href format: {href} for title: {title_text}"
                )
                # Optionally try to resolve relative to course URL if needed

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
        "announcement": "",  # Initialize
        "description": "",  # Initialize
        "contents": [],
    }

    # --- Extract Week Description and Announcement ---
    p3_div = week_div.css_first("div.p-3")
    if p3_div:
        # Find all potential description/announcement divs (those containing a <strong> tag)
        info_divs = p3_div.css("div")  # Get all divs inside p-3
        current_key = None
        for div in info_divs:
            strong_tag = div.css_first("strong")
            if strong_tag:
                header_text = strong_tag.text(strip=True).lower()
                # Find the associated <p> tag immediately following this div
                next_node = div.next
                para_text = ""
                while next_node:
                    # Check if it's a <p> tag (common case)
                    if next_node.tag == "p" and "m-2" in next_node.attributes.get(
                        "class", ""
                    ):
                        para_text = (
                            next_node.text(strip=True, separator=" ")
                            .replace("\n", " ")
                            .replace("\r", "")
                            .strip()
                        )
                        break  # Found the paragraph
                    # Stop if we hit the next section header or the content area
                    if next_node.tag == "div" and (
                        next_node.css_first("strong")
                        or next_node.css_first(".card.mb-4")
                    ):
                        break
                    next_node = next_node.next  # Move to the next sibling

                if "announcement" in header_text:
                    # Check if the parent div is hidden
                    parent_style = div.attributes.get("style", "")
                    if "display:none" not in parent_style.replace(" ", ""):
                        week_data["announcement"] = para_text
                elif "description" in header_text:
                    week_data["description"] = para_text
                # Stop looking for description/announcement once we hit 'Content'
                elif "content" in header_text:
                    break  # Assume content follows

    # --- Extract Contents ---
    content_cards = week_div.css("div.p-3 .card.mb-4")  # More specific selector
    if content_cards:
        # Use fewer workers for potentially I/O bound parsing
        num_workers = min(len(content_cards), (os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=num_workers, thread_name_prefix="ContentParse"
        ) as executor:
            contents = list(executor.map(parse_content_item, content_cards))
        week_data["contents"] = [c for c in contents if c]  # Filter out None results

    return week_data


def fast_parse_content(html_content):
    """Parses the main content area for weeks using selectolax and concurrency."""
    if not html_content:
        logger.warning("HTML content provided to fast_parse_content was empty.")
        return []
    try:
        parser = HTMLParser(html_content)
        # Target the specific container holding the weeks if possible
        # If weeksdata are direct children of app-main__inner, this is fine.
        # If nested deeper, adjust selector e.g., "#ContentPlaceHolderright_ContentPlaceHoldercontent_Panelweeks .weeksdata"
        week_divs = parser.css(".weeksdata")
        if not week_divs:
            logger.warning(
                "No elements found with selector '.weeksdata'. Check CMS page structure or URL."
            )
            return []

        # Process weeks sequentially first to avoid excessive thread overhead for small numbers
        if len(week_divs) < 5:
            weeks = [parse_single_week(div) for div in week_divs]
        else:
            num_workers = min(
                len(week_divs), (os.cpu_count() or 1) * 2
            )  # Adjust as needed
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=num_workers, thread_name_prefix="WeekParse"
            ) as executor:
                weeks = list(executor.map(parse_single_week, week_divs))

        valid_weeks = [w for w in weeks if w]  # Filter out None results

        # Sort weeks by name (descending, assuming format "Week: YYYY-MM-DD")
        try:
            # Attempt to parse date from week_name for robust sorting
            def get_week_date(week_dict):
                name = week_dict.get("week_name", "")
                try:
                    date_str = name.split(":")[-1].strip()
                    return datetime.strptime(date_str, "%Y-%m-%d")
                except (ValueError, IndexError):
                    return datetime.min  # Fallback for unexpected formats

            valid_weeks.sort(key=get_week_date, reverse=True)
        except Exception as sort_err:
            logger.warning(
                f"Could not sort weeks based on date: {sort_err}. Returning in parsed order."
            )

        return valid_weeks
    except Exception as e:
        logger.exception(f"Error during HTML content parsing: {e}")
        return []


# --- Combined CMS Scraper Function ---
def cms_scraper(username, password, course_url, force_fetch=False):
    """Fetches and parses CMS content and announcements, using cache."""
    normalized_url = normalize_course_url(course_url)
    if not normalized_url:
        return {"error": "Invalid course URL provided."}

    key = generate_cache_key(username, normalized_url)
    mock_week = {
        "week_name": "Mock Week",
        "announcement": "",
        "description": "Placeholder for layout",
        "contents": [],
    }

    # 1. Try cache first (unless forced)
    if not force_fetch:
        cached_data = get_from_cache(key)
        if cached_data:
            logger.info(
                f"Returning cached CMS data for {username} and course {normalized_url}"
            )
            # Structure: cached_data might be [overall_announcement_dict, week1, week2,...]
            # or just [week1, week2,...] if no overall announcement was found/cached.
            final_result = []
            if (
                cached_data
                and isinstance(cached_data[0], dict)
                and "course_announcement" in cached_data[0]
            ):
                final_result.append(cached_data[0])  # Add overall announcement
                final_result.append(mock_week)  # Add mock week
                final_result.extend(cached_data[1:])  # Add actual weeks
            else:
                final_result.append(mock_week)  # Add mock week
                final_result.extend(
                    cached_data
                )  # Add actual weeks (no overall announcement)
            return final_result

    logger.info(f"Fetching fresh CMS data for {username} and course {normalized_url}")
    session = get_session(username, password)

    # 2. Fetch fresh data
    try:
        response = session.get(
            normalized_url, timeout=session.timeout
        )  # Use normalized URL
        response.raise_for_status()

        html_content = response.text
        if not html_content:
            logger.error(f"Received empty content for {normalized_url}")
            return {"error": "Received empty content from CMS."}

        # Basic check for login page redirection
        temp_parser = HTMLParser(html_content)
        page_title_node = temp_parser.css_first("title")
        page_title = page_title_node.text().lower() if page_title_node else ""
        if "login" in page_title or "sign in" in page_title:
            # More robust check: look for login form elements
            login_form = temp_parser.css_first(
                "form[action*='login']"
            )  # Example selector
            if login_form:
                logger.warning(
                    f"Authentication likely failed for {username} - redirected to login page for {normalized_url}"
                )
                return {"error": "Authentication failed or session expired."}

        # 3. Parse content and announcements (concurrently)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="Scrape"
        ) as executor:
            # Submit week parsing
            content_future = executor.submit(fast_parse_content, html_content)
            # Submit overall announcement scraping
            announcements_future = executor.submit(
                scrape_course_announcements,
                username,
                password,
                normalized_url,  # Use normalized URL here too
                max_retries=2,
                retry_delay=1,
            )
            # Retrieve results
            content_weeks = (
                content_future.result()
            )  # This now contains week descriptions/announcements
            announcements_result = announcements_future.result()

        overall_announcements_html = None
        announcement_error = None
        if isinstance(announcements_result, dict):
            if "announcements_html" in announcements_result:
                overall_announcements_html = announcements_result["announcements_html"]
            elif "error" in announcements_result:
                announcement_error = announcements_result["error"]
                logger.error(
                    f"Error scraping overall announcements: {announcement_error}"
                )
        else:
            logger.warning(
                f"Unexpected result from scrape_course_announcements: {type(announcements_result)}"
            )

        # 4. Combine results and check if anything was found
        if not overall_announcements_html and not content_weeks:
            error_detail = "Failed to find any course content (weeks) or overall announcements on the page."
            if announcement_error:
                error_detail += f" Announcement scraping failed: {announcement_error}."
            error_detail += " Check the URL, course structure, or user permissions."
            logger.warning(
                f"No content or announcements parsed for {normalized_url}. Details: {error_detail}"
            )
            return {"error": error_detail}

        # 5. Cache combined data (structure: [optional_overall_announcement_dict] + [week_dicts])
        combined_data_for_cache = []
        if overall_announcements_html:
            combined_data_for_cache.append(
                {"course_announcement": overall_announcements_html}
            )
        combined_data_for_cache.extend(content_weeks)

        if combined_data_for_cache:  # Only cache if we actually got something
            set_in_cache(key, combined_data_for_cache)

        # 6. Prepare final result with mock week
        final_result = []
        if overall_announcements_html:
            final_result.append({"course_announcement": overall_announcements_html})
        final_result.append(
            mock_week
        )  # Add mock week regardless of overall announcement
        final_result.extend(content_weeks)

        return final_result

    except requests.exceptions.Timeout as e:
        logger.error(
            f"Timeout fetching CMS data for {username} at {normalized_url}: {e}"
        )
        return {"error": f"Request timed out accessing CMS: {e}"}
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        logger.error(
            f"HTTP error fetching CMS content for {username} at {normalized_url}: {status_code} - {e}"
        )
        if status_code in [401, 403]:
            return {
                "error": f"Authentication failed ({status_code}). Check username/password or permissions."
            }
        elif status_code == 404:
            return {"error": f"Course URL not found ({status_code}). Check the URL."}
        else:
            return {"error": f"CMS server error: Received status {status_code}"}
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Network error fetching CMS data for {username} at {normalized_url}: {e}"
        )
        return {"error": f"Network error connecting to CMS: {e}"}
    except Exception as e:
        logger.exception(
            f"Unexpected error in cms_scraper for {username} at {normalized_url}: {e}"
        )
        return {"error": f"An unexpected internal error occurred: {e}"}


# --- Async Redis Logging Setup ---
API_LOG_KEY = "api_logs:cms_content"  # Specific key for this API
MAX_LOG_ENTRIES = 5000
log_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=5, thread_name_prefix="LogThread"
)


def _log_to_redis_task(log_entry_dict):
    """Task to push a log entry to Redis list."""
    if not redis_client:
        # Log locally if Redis is down
        logger.warning(f"Redis unavailable. Local log: {log_entry_dict}")
        return
    try:
        log_entry_json = json.dumps(log_entry_dict)
        # Ensure key and value are bytes if decode_responses=False
        log_key_bytes = API_LOG_KEY.encode("utf-8")
        log_entry_bytes = log_entry_json.encode("utf-8")

        pipe = redis_client.pipeline()
        pipe.lpush(log_key_bytes, log_entry_bytes)
        pipe.ltrim(log_key_bytes, 0, MAX_LOG_ENTRIES - 1)
        pipe.execute()
    except redis.exceptions.TimeoutError:
        logger.error("Redis timeout during async logging.")
    except redis.exceptions.ConnectionError as e:
        logger.error(f"Redis connection error during async logging: {e}")
    except TypeError as e:
        logger.error(
            f"Log serialization error: {e}. Log entry: {log_entry_dict}", exc_info=True
        )
    except Exception as e:
        logger.error(f"Unexpected async log error: {e}", exc_info=True)


# --- Flask App Setup ---
app = Flask(__name__)


# --- Request Hooks for Logging ---
@app.before_request
def before_request_func():
    """Initialize request context."""
    g.start_time = perf_counter()
    g.request_time = datetime.now(timezone.utc)
    g.username = None  # Will be set in endpoint if available
    g.log_outcome = "unknown"
    g.log_error_message = None


@app.after_request
def after_request_handler(response):
    """Logs request details asynchronously and adds CORS headers."""
    # Standard paths to skip logging
    if request.method == "OPTIONS" or request.path in [
        "/api/logs",
        "/api/test_form",
        "/favicon.ico",
    ]:
        # Still add CORS headers for OPTIONS preflight requests
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PUT, DELETE, OPTIONS"
        )
        response.headers["Access-Control-Max-Age"] = "86400"
        return response

    # --- User-Agent Handling ---
    raw_ua_header = request.headers.get("User-Agent", "Unknown")
    final_user_agent = raw_ua_header[:250]  # Limit length

    # --- Logging ---
    elapsed_ms = (perf_counter() - g.start_time) * 1000
    log_entry = {
        "username": getattr(g, "username", None),  # Get username set in endpoint
        "endpoint": request.path,
        "method": request.method,
        "status_code": response.status_code,
        "outcome": getattr(g, "log_outcome", "unknown"),
        "error_message": getattr(g, "log_error_message", None),
        "time_elapsed_ms": round(elapsed_ms, 2),
        "request_timestamp_utc": getattr(
            g, "request_time", datetime.now(timezone.utc)
        ).isoformat(),
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "ip_address": request.headers.get("X-Forwarded-For", request.remote_addr)
        or "Unknown",
        "user_agent": final_user_agent,
        "request_args": {
            k: ("********" if k == "password" else v) for k, v in request.args.items()
        },
    }

    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        logger.error(f"Error submitting log task to executor: {e}", exc_info=True)

    # --- CORS Headers ---
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"

    return response


# --- API Endpoints ---
@app.route("/api/cms_content", methods=["GET"])
def get_cms_content():
    """API endpoint to get CMS content and announcements."""
    start_time = perf_counter()  # Track time specifically for this endpoint

    # --- Bot Health Check ---
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logger.info("Received bot health check request for CMS Content API.")
        g.log_outcome = "bot_check_success"
        return (
            jsonify(
                {
                    "status": "Success",
                    "message": "CMS Content API route is up!",
                    "data": None,
                }
            ),
            200,
        )

    # --- Get Parameters ---
    username = request.args.get("username")
    password = request.args.get("password")
    course_url = request.args.get("course_url")
    force_fetch = request.args.get("force_fetch", "false").lower() == "true"

    # --- Input Validation ---
    missing_params = []
    if not username:
        missing_params.append("username")
    if not password:
        missing_params.append("password")
    if not course_url:
        missing_params.append("course_url")

    if missing_params:
        error_msg = f"Missing required parameters: {', '.join(missing_params)}."
        g.log_outcome = "validation_error"
        g.log_error_message = error_msg
        g.username = username or "unknown"
        logger.warning(f"Validation error for user {g.username}: {error_msg}")
        return jsonify({"error": error_msg}), 400

    g.username = username  # Set for logging

    # --- Call Scraper ---
    logger.info(
        f"Processing request for user {username}, course: {course_url}, force_fetch: {force_fetch}"
    )
    result = cms_scraper(username, password, course_url, force_fetch=force_fetch)

    # --- Handle Result ---
    if isinstance(result, dict) and "error" in result:
        error_msg = result["error"]
        logger.error(
            f"Scraper failed for user {username}, course {course_url}: {error_msg}"
        )
        g.log_error_message = error_msg
        # Determine status code and outcome based on error message
        if "Authentication failed" in error_msg:
            status_code = 401
            g.log_outcome = "auth_error"
        elif (
            "not found" in error_msg.lower()
            or "Failed to find any course content" in error_msg
        ):
            status_code = 404
            g.log_outcome = "not_found"
        elif "timed out" in error_msg.lower() or "Network error" in error_msg.lower():
            status_code = 504  # Gateway Timeout
            g.log_outcome = "timeout_or_network_error"
        elif (
            "parsing failed" in error_msg.lower()
            or "Failed to parse" in error_msg.lower()
        ):
            status_code = 502  # Bad Gateway
            g.log_outcome = "parsing_error"
        else:
            status_code = 500  # Internal Server Error (default)
            g.log_outcome = "internal_error"
        return jsonify({"error": error_msg}), status_code
    else:
        # Success case
        g.log_outcome = "success"
        logger.info(
            f"Successfully processed request for user {username}, course: {course_url} in {(perf_counter() - start_time)*1000:.2f} ms"
        )
        return jsonify(result), 200


@app.route("/api/test_form", methods=["GET"])
def test_form():
    """Provides a simple HTML form for testing the API."""
    # Logging skipped by after_request hook
    return """
    <!DOCTYPE html>
    <html>
    <head><title>CMS Content API Test</title></head>
    <body>
    <h1>Test CMS Content API</h1>
    <form action="/api/cms_content" method="get" target="_blank">
    <div>Username: <input type="text" name="username" required></div>
    <div>Password: <input type="password" name="password" required></div>
    <div>Course URL: <input type="url" name="course_url" size="100" required placeholder="e.g., https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=..."></div>
    <div>Force Fetch: <input type="checkbox" name="force_fetch" value="true"> (Check to bypass cache)</div>
    <div><input type="submit" value="Get Content"></div>
    </form>
    <h2>Example URLs</h2>
    <ul>
    <li><code>https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=450&sid=65</code></li>
    <li><code>https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=17&sid=65</code></li>
    </ul>
    </body>
    </html>
    """


@app.route("/api/logs", methods=["GET"])
def api_logs_new():
    """Retrieves the last N API logs from Redis."""
    g.username = "log_viewer"  # Indicate log access
    if not redis_client:
        g.log_outcome = "redis_error"
        g.log_error_message = "Redis client is not available."
        return jsonify({"error": "Log storage (Redis) is currently unavailable."}), 503

    try:
        log_key_bytes = API_LOG_KEY.encode("utf-8")
        log_entries_bytes = redis_client.lrange(log_key_bytes, 0, MAX_LOG_ENTRIES - 1)
        logs = []
        for entry_bytes in log_entries_bytes:
            try:
                entry_json = entry_bytes.decode("utf-8")
                logs.append(json.loads(entry_json))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(
                    f"Error decoding/parsing log entry from Redis: {e}. Entry preview: {entry_bytes[:100]!r}"
                )
                logs.append(
                    {
                        "error": "Failed to parse log entry",
                        "raw_preview": repr(entry_bytes[:100]),
                    }
                )

        g.log_outcome = "success"
        return jsonify(logs), 200
    except redis.exceptions.ConnectionError as e:
        g.log_outcome = "redis_error"
        g.log_error_message = f"Redis connection error: {e}"
        logger.error(f"Error retrieving logs from Redis (connection): {e}")
        return jsonify({"error": "Failed to connect to log storage"}), 503
    except Exception as e:
        g.log_outcome = "internal_error"
        g.log_error_message = f"Error retrieving logs: {e}"
        logger.exception(f"Error retrieving logs from Redis: {e}")
        return jsonify({"error": "Failed to retrieve logs from storage"}), 500


# --- Graceful Shutdown ---
def shutdown_log_executor():
    logger.info("Shutting down log executor...")
    log_executor.shutdown(wait=True)
    logger.info("Log executor shut down.")


atexit.register(shutdown_log_executor)

# --- Main Execution ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Changed default port slightly
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(
        f"Starting Flask app (CMS Content API) on port {port} with debug mode: {debug_mode}"
    )
    # Use host='0.0.0.0' for Docker/external access.
    # waitress-serve is recommended for production instead of app.run(debug=False)

    # Run with Flask's built-in server for debugging
    app.run(debug=True, host="0.0.0.0", port=port, use_reloader=True)
