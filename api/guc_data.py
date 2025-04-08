import re
import json
import logging
import requests
from requests.exceptions import RequestException
from time import perf_counter
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, g
from datetime import datetime, timezone
import redis
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import pycurl
from io import BytesIO
import traceback
import sys
import concurrent.futures
import threading
import atexit # Added for shutdown hook

# --- Append parent directory if needed ---
# Adjust or remove if unnecessary for your project structure
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    # Ensure this import path is correct for your structure
    from api.scraping import authenticate_user
except ImportError:
    logging.warning("Could not import authenticate_user. Check PYTHONPATH or script location. Using dummy function.")
    def authenticate_user(username, password):
        logging.warning("Using dummy authenticate_user function.")
        # Simulate success for testing if real function is unavailable
        return True

# --- Basic Logging Setup ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s"
)

# Load environment variables
load_dotenv()

# --- Initialize Redis, Fernet, Constants ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logging.critical("ENCRYPTION_KEY environment variable not set. Exiting.")
    raise ValueError("ENCRYPTION_KEY environment variable not set")
fernet = Fernet(ENCRYPTION_KEY.encode())

# --- Logging Specific Constants ---
API_LOG_KEY = "api_logs" # Specific Redis key for these logs
MAX_LOG_ENTRIES = 5000

# --- Thread Pool for Background Logging ---
log_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix='LogThread')

# --- Configuration ---
class Config:
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    # ENCRYPTION_KEY already loaded
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )
    # Ensure these are the correct URLs needed by scrape_guc_data_fast
    GUC_DATA_URLS = [
        os.environ.get("GUC_INDEX_URL", "https://apps.guc.edu.eg/student_ext/index.aspx"),
        os.environ.get("GUC_NOTIFICATIONS_URL", "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx"),
    ]

config = Config() # Initialize config object

# --- Default Announcement Configuration ---
DEFAULT_DEV_ANNOUNCEMENT = {
    "body": "Hello Unisight user,\n\nThank you for choosing Unisight. Our development team is working to improve your experience. We invite you to rate our app and share your feedback. Please use the link below to let us know your thoughts:\nhttps://forms.gle/Fm8sRmJbVx6utgFu8\n\nThank you for your support.",
    "date": "4/4/2025", # Consider updating or making dynamic
    "email_time": "2025-03-27T00:00:00",
    "id": "150999",
    "importance": "High",
    "staff": "Unisight Team",
    "subject": "We'd love your feedback on Unisight",
    "title": "Rate our app"
}
REDIS_DEV_ANNOUNCEMENT_KEY = "dev_announcement"

# --- Announcement Functions ---
def get_dev_announcement():
    try:
        announcement_json = redis_client.get(REDIS_DEV_ANNOUNCEMENT_KEY)
        if announcement_json:
            try:
                return json.loads(announcement_json)
            except json.JSONDecodeError as json_err:
                logging.error(f"Error parsing announcement JSON from Redis: {json_err}. Using default.")
                set_dev_announcement(DEFAULT_DEV_ANNOUNCEMENT)
                return DEFAULT_DEV_ANNOUNCEMENT
        else:
            logging.info(f"No announcement found in Redis key '{REDIS_DEV_ANNOUNCEMENT_KEY}'. Storing and using default.")
            set_dev_announcement(DEFAULT_DEV_ANNOUNCEMENT)
            return DEFAULT_DEV_ANNOUNCEMENT
    except redis.exceptions.ConnectionError as e:
         logging.error(f"[Redis] Connection error getting dev announcement: {e}")
         return DEFAULT_DEV_ANNOUNCEMENT
    except Exception as e:
        logging.error(f"Error getting dev announcement: {e}")
        return DEFAULT_DEV_ANNOUNCEMENT

def set_dev_announcement(announcement):
    try:
        redis_client.set(
            REDIS_DEV_ANNOUNCEMENT_KEY,
            json.dumps(announcement, ensure_ascii=False)
        )
        logging.info(f"Stored dev announcement to Redis key '{REDIS_DEV_ANNOUNCEMENT_KEY}'.")
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error setting dev announcement: {e}")
    except Exception as e:
        logging.error(f"Error setting dev announcement: {e}")


# --- Cache Utilities ---
DATA_CACHE_EXPIRY = 600  # 10 minutes

def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached)
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Cache] Redis connection error on get '{key}': {e}", file=sys.stderr)
        g.log_outcome = "cache_error_connection"
        g.log_error_message = f"Redis connection error getting key '{key}'"
    except json.JSONDecodeError as e:
         logging.error(f"[Cache] Error decoding JSON for key '{key}': {e}. Cache data might be corrupted.", file=sys.stderr)
         g.log_outcome = "cache_error_decode"
         g.log_error_message = f"Error decoding cache for key '{key}'"
    except Exception as e:
        logging.error(f"[Cache] Error getting key '{key}': {e}", file=sys.stderr)
        g.log_outcome = "cache_error_unknown"
        g.log_error_message = f"Unknown error getting cache for key '{key}'"
    return None

def set_to_app_cache(key, value, timeout=DATA_CACHE_EXPIRY):
    try:
        redis_client.setex(key, timeout, json.dumps(value, ensure_ascii=False))
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Cache] Redis connection error on set '{key}': {e}", file=sys.stderr)
    except TypeError as e:
        logging.error(f"[Cache] Failed to serialize value to JSON for key '{key}': {e}", file=sys.stderr)
    except Exception as e:
        logging.error(f"[Cache] Error setting key '{key}': {e}", file=sys.stderr)

# --- Fast Scraping Functions (pycurl based) ---
def multi_fetch(urls, userpwd):
    multi = pycurl.CurlMulti()
    handles = []
    buffers = {}
    start_time = perf_counter()

    for url in urls:
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
        c.setopt(c.USERPWD, userpwd)
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.FOLLOWLOCATION, True)
        c.setopt(c.TIMEOUT, 15)
        c.setopt(c.SSL_VERIFYPEER, 0) # GUC site might require this
        c.setopt(c.SSL_VERIFYHOST, 0) # GUC site might require this
        # Optionally set a common user agent
        c.setopt(c.USERAGENT, "UnisightApp/Client (Python-PycURL)") # Example User-Agent
        multi.add_handle(c)
        handles.append(c)
        buffers[url] = buffer

    num_handles = len(handles)
    while num_handles:
        ret, num_handles = multi.perform()
        if ret != pycurl.E_CALL_MULTI_PERFORM:
             pass
        if num_handles:
            multi.select(1.0)

    end_time = perf_counter()
    logging.debug(f"pycurl multi_fetch for {len(urls)} URLs took {end_time - start_time:.3f}s")

    results = {}
    errors = {}
    for i, c in enumerate(handles):
        url = urls[i]
        http_code = c.getinfo(pycurl.HTTP_CODE)
        effective_url = c.getinfo(pycurl.EFFECTIVE_URL)
        logging.debug(f"Request to {url} (effective: {effective_url}) completed with status code: {http_code}")

        if http_code >= 200 and http_code < 300:
            try:
                results[url] = buffers[url].getvalue().decode("utf-8", errors="replace")
            except Exception as decode_err:
                logging.error(f"Error decoding response for {url} (Status {http_code}): {decode_err}")
                errors[url] = f"Decode error: {decode_err}"
                results[url] = ""
        else:
            error_msg = f"HTTP status code {http_code}"
            try:
                 error_body_preview = buffers[url].getvalue()[:200].decode("utf-8", errors="replace")
                 error_msg += f" - Body preview: {error_body_preview}"
            except Exception:
                 pass
            logging.warning(f"Request failed for {url}: {error_msg}")
            errors[url] = error_msg
            results[url] = ""

        multi.remove_handle(c)
        c.close()

    multi.close()
    return results, errors

def parse_student_info(html):
    soup = BeautifulSoup(html, "lxml")
    info = {}
    prefix = "ContentPlaceHolderright_ContentPlaceHoldercontent_Label"
    mapping = {
        "FullName": "fullname", "UniqAppNo": "uniqappno", "UserCode": "usercode",
        "Mail": "mail", "sg": "sg",
    }
    found_any = False
    for label, key in mapping.items():
        element = soup.find(id=f"{prefix}{label}")
        if element:
            info[key] = element.get_text(" ", strip=True).replace("\r", "").replace("\n", " ")
            found_any = True
        else:
            info[key] = ""
            logging.debug(f"Student info field '{label}' not found in HTML.")

    if not found_any and html:
         logging.warning("Failed to parse any student info fields. HTML might have unexpected structure.")
         # logging.debug(f"HTML snippet for student info parsing failure: {html[:500]}")

    return info

def parse_notifications(html):
    soup = BeautifulSoup(html, "lxml")
    notifications = []
    table = soup.find(id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata")
    if table:
        rows = table.find_all("tr")[1:]
        for idx, row in enumerate(rows):
            cells = row.find_all("td")
            if len(cells) < 6:
                logging.warning(f"Skipping notification row {idx+1}: expected at least 6 cells, found {len(cells)}")
                continue
            try:
                notif = {}
                notif["id"] = cells[0].get_text(" ", strip=True).replace("\r", "").replace("\n", "")
                # Extract title, ensuring it's treated as text content
                title_cell = cells[2]
                notif["title"] = title_cell.get_text(" ", strip=True).replace("\r", "").replace("\n", " ")

                notif["date"] = cells[3].get_text(" ", strip=True).replace("\r", "").replace("\n", "")
                notif["staff"] = cells[4].get_text(" ", strip=True).replace("\r", "").replace("\n", " ")
                notif["importance"] = cells[5].get_text(" ", strip=True).replace("\r", "").replace("\n", "")

                button = cells[1].find("button")
                if button:
                    email_time_str = button.get("data-email_time", "")
                    notif["email_time"] = datetime.now(timezone.utc).isoformat() # Default
                    if email_time_str:
                        try:
                            email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                            notif["email_time"] = email_time.isoformat()
                        except ValueError as e:
                            logging.warning(f"Error parsing email_time '{email_time_str}' for notif ID {notif.get('id', 'N/A')}: {e}. Using default.")
                        except Exception as e:
                            logging.warning(f"Unexpected error parsing email_time '{email_time_str}': {e}")

                    subject = button.get("data-subject_text", "").replace("Notification System:", "").strip().replace("\r", "").replace("\n", " ")
                    body = button.get("data-body_text", "").replace("------------------------------", "").strip().replace("\r", "").replace("\n", "\n") # Keep body newlines
                    notif["subject"] = subject
                    notif["body"] = body
                else:
                    logging.warning(f"Notification button not found for row with ID {notif.get('id', 'N/A')}.")
                    notif["email_time"] = datetime.now(timezone.utc).isoformat()
                    notif["subject"] = "Subject not found"
                    notif["body"] = "Body not found"

                notifications.append(notif)
            except Exception as e:
                logging.error(f"Error processing notification row {idx+1}: {e}", exc_info=True)

    else:
        if html and "Login Failed!" not in html and "Object moved" not in html:
             logging.warning("Notifications table '...GridViewdata' not found in HTML.")
             # logging.debug(f"HTML snippet for notification parsing failure: {html[:500]}")
        elif not html:
             logging.warning("Notifications HTML was empty.")

    try:
        notifications.sort(key=lambda x: x.get("email_time", ""), reverse=True)
    except Exception as sort_err:
         logging.error(f"Failed to sort notifications: {sort_err}")

    return notifications

def scrape_guc_data_fast(username, password, urls):
    userpwd = f"GUC\\{username}:{password}"
    data = None
    try:
        results, errors = multi_fetch(urls, userpwd)

        if len(errors) == len(urls):
             is_auth_error = all('401' in msg for msg in errors.values()) or \
                             all('Login.aspx' in msg for msg in errors.values())
             if is_auth_error:
                  logging.warning(f"Scraping failed for {username}: Likely authentication error based on fetch results.")
                  return {"error": "Authentication failed on GUC site"}
             else:
                  logging.error(f"Scraping failed for {username}: All URL fetches failed. Errors: {errors}")
                  return {"error": f"All URL fetches failed: {'; '.join(errors.values())}"}

        student_html = results.get(urls[0], "")
        notif_html = results.get(urls[1], "")

        if "Login Failed!" in student_html or "Object moved to <a href=\"../External/Login.aspx\">" in student_html:
            logging.warning(f"Detected 'Login Failed!' or redirect to login page in student info response for {username}.")
            return {"error": "Authentication failed (detected in response)"}

        student_info = parse_student_info(student_html)
        notifications = parse_notifications(notif_html)

        student_info_valid = any(v for k, v in student_info.items())
        if not notifications and not student_info_valid:
             if not errors:
                logging.warning(f"Scraping for {username} resulted in no valid student info and no notifications. Parsing might have failed.")
                return {"error": "Parsing failed to extract any data"}
             else:
                 logging.warning(f"Scraping for {username} yielded no data, possibly due to fetch errors: {errors}")
                 return {"error": f"Fetching failed for some URLs, no data extracted: {'; '.join(errors.values())}"}

        data = {"notifications": notifications, "student_info": student_info}
        if errors:
             data["fetch_warnings"] = errors
             logging.warning(f"Scraping for {username} completed with some fetch warnings: {errors}")

        return data

    except pycurl.error as e:
         error_code, error_msg = e.args
         logging.error(f"PycURL error during scraping for {username}: Code {error_code} - {error_msg}", exc_info=True)
         return {"error": f"Network error during scraping: {error_msg}"}
    except Exception as e:
        logging.error(f"Unexpected error in scrape_guc_data_fast for {username}: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred during scraping: {e}"}

# --- Whitelist and Credential Storage ---
def get_all_stored_users():
    try:
        stored = redis_client.hgetall("user_credentials")
        return stored
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored users: {e}")
        return {}
    except Exception as e:
        logging.error(f"Error getting stored users from Redis: {e}")
        return {}

def store_user_credentials(username, password):
    try:
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)
        logging.info(f"Stored/Updated credentials for user: {username}")
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error storing credentials for {username}: {e}")
    except Exception as e:
        logging.error(f"Error storing credentials for user '{username}': {e}")

def get_country_from_ip(ip_address):
    if not ip_address or ip_address in ("127.0.0.1", "::1"):
        logging.debug("Localhost or missing IP; using fallback country 'Localhost'.")
        return "Localhost"
    try:
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get("error"):
             logging.warning(f"IP API error for {ip_address}: {data.get('reason')}")
             return "API Error"
        country = data.get("country_name", "Unknown")
        logging.info(f"Determined country '{country}' for IP {ip_address}")
        return country
    except RequestException as e:
         logging.error(f"Network error determining country for IP {ip_address}: {e}")
    except json.JSONDecodeError as e:
         logging.error(f"JSON decode error determining country for IP {ip_address}: {e}")
    except Exception as e:
        logging.error(f"Error determining country for IP {ip_address}: {e}")
    return "Lookup Failed"

def get_stored_password(username):
    try:
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                decrypted_bytes = fernet.decrypt(encrypted.encode())
                return decrypted_bytes.decode("utf-8")
            except Exception as e:
                logging.error(f"Failed to decrypt password for {username}: {e}")
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored password for {username}: {e}")
    except Exception as e:
         logging.error(f"Error retrieving stored password for {username}: {e}")
    return None

# --- Background Logging Task ---
def _log_to_redis_task(log_entry_dict):
    """Internal task to write logs to Redis."""
    try:
        log_entry_json = json.dumps(log_entry_dict)
        pipe = redis_client.pipeline()
        pipe.lpush(API_LOG_KEY, log_entry_json)
        pipe.ltrim(API_LOG_KEY, 0, MAX_LOG_ENTRIES - 1)
        pipe.execute()
    except redis.exceptions.ConnectionError as e:
        print(f"[{threading.current_thread().name}] Log Error: Redis connection error: {e}", file=sys.stderr)
    except TypeError as e:
         print(f"[{threading.current_thread().name}] Log Error: Failed to serialize log entry to JSON: {e}", file=sys.stderr)
         problematic_items = {k: repr(v) for k, v in log_entry_dict.items() if not isinstance(v, (str, int, float, bool, list, dict, type(None)))}
         print(f"[{threading.current_thread().name}] Log Error: Problematic items: {problematic_items}", file=sys.stderr)
    except Exception as e:
        print(f"[{threading.current_thread().name}] Log Error: Failed to write log to Redis: {e}", file=sys.stderr)
        print(f"[{threading.current_thread().name}] Log Error: Failed entry (partial): user={log_entry_dict.get('username')}, endpoint={log_entry_dict.get('endpoint')}, status={log_entry_dict.get('status_code')}", file=sys.stderr)


# --- Flask App Setup ---
app = Flask(__name__)
app.config.from_object(config)

@app.before_request
def before_request_func():
    """Initialize request context."""
    g.start_time = perf_counter()
    g.request_time = datetime.now(timezone.utc)
    g.username = None
    g.log_outcome = "unknown"
    g.log_error_message = None

@app.after_request
def after_request_logger(response):
    """Logs request details asynchronously, handles User-Agent robustly, and submits the logging task."""
    # Avoid logging OPTIONS requests
    if request.method == 'OPTIONS':
        # The add_cors_headers function should handle CORS for OPTIONS
        return response

    elapsed_ms = (perf_counter() - g.start_time) * 1000

    # --- Robust User-Agent Handling (without excessive debug logs) ---
    ua_string_from_parsed = None
    ua_parse_error = False # Flag to indicate if parsing failed
    raw_ua_header = request.headers.get('User-Agent') # Get raw header safely

    try:
        # Attempt to use the parsed User-Agent object provided by Werkzeug/Flask
        if request.user_agent:
            ua_string_from_parsed = request.user_agent.string
    except Exception as e:
        # Log only if there's an actual error accessing the parsed object's string
        ua_parse_error = True
        # Use the root logger or a specific module logger if defined
        logging.error(f"GUC Data API UA: Error accessing request.user_agent.string: {e}", exc_info=True) # Keep error log

    # Determine the final user_agent string for the log using fallback logic:
    # 1. Try the string from the parsed object.
    # 2. If that failed or was empty, try the raw header string.
    # 3. If both are unavailable, default to "Unknown".
    final_user_agent = ua_string_from_parsed if ua_string_from_parsed else raw_ua_header if raw_ua_header else "Unknown"

    # Handle the edge case where parsing failed AND the raw header was also missing
    if ua_parse_error and not raw_ua_header:
        final_user_agent = "Unknown (Parsing Error)"
    # --- End User-Agent Handling ---


    # --- Prepare Log Entry ---
    username = getattr(g, 'username', None)
    outcome = getattr(g, 'log_outcome', 'unknown')
    error_message = getattr(g, 'log_error_message', None)

    request_args = request.args.to_dict()
    if 'password' in request_args:
        request_args['password'] = '********' # Mask password

    # Get IP address, considering proxies
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or "Unknown"

    log_entry = {
        "endpoint": request.path,
        "error_message": error_message, # Will be None on success
        "ip_address": ip_address,
        "method": request.method,
        "outcome": outcome,
        "request_args": request_args,
        "request_timestamp_utc": g.request_time.isoformat(), # Use start time
        "response_size_bytes": response.content_length, # Get size from response, may be None
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(), # Use end time
        "status_code": response.status_code,
        "time_elapsed_ms": round(elapsed_ms, 2),
        "user_agent": final_user_agent, # Use handled user agent string
        "username": username,
    }
    # --- End Log Entry Preparation ---

    # Submit the logging task to the background executor
    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        # Log locally if submitting the task fails critically
        logging.exception(f"CRITICAL: Failed to submit log task to executor: {e}")

    # Return original response
    # The add_cors_headers function will run after this.
    return response
    
@app.after_request
def add_cors_headers(response):
    """Add CORS headers."""
    # This runs *after* after_request_logger
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# --- API Endpoint: /api/guc_data ---
@app.route("/api/guc_data", methods=["GET"])
def api_guc_data():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Guc Data API route is up!", "data": None}), 200
    start_req_time = perf_counter()

    # --- Parameter Extraction & Validation ---
    username = request.args.get("username")
    password = request.args.get("password")
    req_version = request.args.get("version_number")
    first_time_str = request.args.get("first_time", "false")
    first_time = first_time_str.lower() == "true"

    g.username = username # Set for logging

    if not username or not password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"status": "error", "message": "Missing username or password", "data": None}), 400

    # --- Version Check ---
    current_version = "1.0" # Default
    try:
        version_number_raw = redis_client.get("VERSION_NUMBER")
        if version_number_raw:
             current_version = version_number_raw # Already a string
    except redis.exceptions.ConnectionError as e:
         logging.error(f"[Redis] Connection error getting VERSION_NUMBER: {e}")
         g.log_outcome = "internal_error_redis"
         g.log_error_message = "Failed to get version from Redis"
         return jsonify({"status": "error", "message": "Internal server error (version check)", "data": None}), 500
    except Exception as e:
         logging.error(f"Error getting VERSION_NUMBER: {e}", exc_info=True)
         g.log_outcome = "internal_error_redis"
         g.log_error_message = f"Unknown error getting version from Redis: {e}"
         return jsonify({"status": "error", "message": "Internal server error (version check)", "data": None}), 500

    if req_version != current_version:
        logging.warning(f"Incorrect version for {username}. Required: {current_version}, Got: {req_version}")
        g.log_outcome = "version_error"
        g.log_error_message = f"Incorrect version. Required: {current_version}, Got: {req_version}"
        return jsonify({"status": "error", "message": f"Incorrect version number. Please update the app to version {current_version}.", "data": None}), 403

    # --- Authentication Flow ---
    auth_verified_this_request = False
    stored_password = None # Define before conditional assignment
    password_to_use = None

    if first_time:
        logging.info(f"First time login flow initiated for {username}")
        g.log_outcome = "first_time_auth_attempt"
        try:
            auth_success = authenticate_user(username, password)
            if not auth_success:
                logging.warning(f"First time login failed for {username}: Auth unsuccessful on GUC.")
                g.log_outcome = "first_time_auth_fail"
                g.log_error_message = "Invalid credentials (first time GUC check)"
                return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401

            logging.info(f"First time GUC authentication successful for {username}. Storing credentials.")
            store_user_credentials(username, password)
            auth_verified_this_request = True
            password_to_use = password # Use the provided, now verified, password

            # Store country (best effort)
            try:
                ip_addr = request.remote_addr
                country = get_country_from_ip(ip_addr)
                if country not in ("Lookup Failed", "API Error", "Localhost"):
                     redis_client.hset("user_countries", username, country)
                     logging.info(f"Stored country '{country}' for {username} from IP {ip_addr}")
                else:
                     logging.warning(f"Could not determine/store country for {username} from IP {ip_addr}, result was: {country}")
            except redis.exceptions.ConnectionError as e:
                 logging.error(f"[Redis] Connection error storing country for {username}: {e}")
            except Exception as country_err:
                logging.error(f"Error storing country for {username}: {country_err}", exc_info=True)

        except Exception as auth_err:
            logging.error(f"Error during first time auth check for {username}: {auth_err}", exc_info=True)
            g.log_outcome = "first_time_auth_exception"
            g.log_error_message = f"Authentication check failed: {auth_err}"
            return jsonify({"status": "error", "message": "Authentication check failed due to an internal error", "data": None}), 500
    else:
        # --- Not First Time: Check Stored Credentials ---
        g.log_outcome = "stored_auth_attempt"
        stored_password = get_stored_password(username)

        if not stored_password:
             logging.warning(f"Stored password not found or failed to decrypt for {username}.")
             g.log_outcome = "stored_auth_notfound"
             g.log_error_message = "Credentials not stored or invalid. Use first_time=true."
             return jsonify({"status": "error", "message": "Credentials not found or invalid. Please login again.", "data": None}), 401

        if stored_password.strip() != password.strip():
            logging.warning(f"Invalid password provided for {username} (checked against stored).")
            # Optional: Re-authenticate against GUC here if desired (adds latency)
            # ... (see previous example if you want to add this)
            g.log_outcome = "stored_auth_fail"
            g.log_error_message = "Invalid credentials (stored check)"
            return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401
        else:
             # Stored password matches provided password
             auth_verified_this_request = True
             g.log_outcome = "stored_auth_success"
             password_to_use = stored_password # Use the verified stored password

    # --- Final Auth Sanity Check ---
    if not auth_verified_this_request or not password_to_use:
         logging.error(f"Auth verification failed unexpectedly for {username}. Logic error? AuthVerified={auth_verified_this_request}, PwdToUse={'Set' if password_to_use else 'None'}")
         g.log_outcome = "internal_error_auth_logic"
         g.log_error_message = "Internal authorization logic error"
         return jsonify({"status": "error", "message": "Internal server error", "data": None}), 500

    # --- Cache Check ---
    cache_key = f"guc_data:{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        logging.info(f"Serving guc_data from cache for {username}")
        g.log_outcome = "cache_hit"

        try:
            dev_announcement = get_dev_announcement()
            if isinstance(cached_data.get("notifications"), list):
                 cached_data["notifications"].insert(0, dev_announcement)
            else:
                 logging.warning(f"Cached data for {username} missing 'notifications' list. Creating list for announcement.")
                 cached_data["notifications"] = [dev_announcement]
        except Exception as e:
             logging.error(f"Failed to get or add dev announcement for {username} (cache hit): {e}")

        cache_hit_duration = perf_counter() - start_req_time
        logging.debug(f"Cache hit response for {username} took {cache_hit_duration:.3f}s")
        return jsonify(cached_data), 200

    # --- Scraping (Cache Miss) ---
    logging.info(f"Cache miss. Starting guc_data scraping for {username}")
    g.log_outcome = "scrape_attempt"
    start_scrape_time = perf_counter()

    try:
        scrape_result = scrape_guc_data_fast(username, password_to_use, config.GUC_DATA_URLS)
        scrape_duration = perf_counter() - start_scrape_time
        logging.info(f"Scraping finished for {username} in {scrape_duration:.3f} seconds")

        # --- Handle Scraping Result ---
        if scrape_result and "error" in scrape_result:
             error_msg = scrape_result["error"]
             logging.error(f"Scraping error for user {username}: {error_msg}")
             g.log_error_message = error_msg
             if "Authentication failed" in error_msg:
                 g.log_outcome = "scrape_auth_error"
                 logging.warning(f"Auth failed during scrape attempt for {username}. Stored credentials might be outdated.")
                 return jsonify({"status": "error", "message": f"Authentication failed on GUC: {error_msg}", "data": None}), 401
             elif any(e in error_msg.lower() for e in ["network error", "fetch failed", "timeout", "connection"]):
                 g.log_outcome = "scrape_connection_error"
                 return jsonify({"status": "error", "message": f"Failed to connect to GUC service: {error_msg}", "data": None}), 504
             elif any(e in error_msg.lower() for e in ["parsing failed", "failed to extract"]):
                  g.log_outcome = "scrape_parsing_error"
                  return jsonify({"status": "error", "message": f"Failed to parse GUC data: {error_msg}", "data": None}), 502
             else:
                 g.log_outcome = "scrape_unknown_error"
                 return jsonify({"status": "error", "message": f"An unexpected error occurred during scraping: {error_msg}", "data": None}), 500

        elif not scrape_result:
             logging.error(f"Scraping returned None unexpectedly for user {username}")
             g.log_outcome = "scrape_no_result"
             g.log_error_message = "Scraping function returned None"
             return jsonify({"status": "error", "message": "Failed to fetch GUC data (unexpected empty result)", "data": None}), 500

        else:
             # --- Success ---
             logging.info(f"Successfully scraped guc_data for user: {username}")
             g.log_outcome = "scrape_success"

             # Cache the successful result *before* adding announcement
             set_to_app_cache(cache_key, scrape_result, DATA_CACHE_EXPIRY)
             logging.info(f"Cached fresh guc_data for user: {username}")

             # Add announcement to the data being returned
             try:
                 dev_announcement = get_dev_announcement()
                 if isinstance(scrape_result.get("notifications"), list):
                     scrape_result["notifications"].insert(0, dev_announcement)
                 else:
                     logging.warning(f"Scraped data for {username} missing 'notifications' list. Creating list for announcement.")
                     scrape_result["notifications"] = [dev_announcement]
             except Exception as e:
                  logging.error(f"Failed to get or add dev announcement for {username} (scrape success): {e}")

             total_req_duration = perf_counter() - start_req_time
             logging.debug(f"Scrape success response for {username} took {total_req_duration:.3f}s")
             return jsonify(scrape_result), 200

    except Exception as e:
         # Catch unexpected errors in the main request flow
         logging.exception(f"Unhandled exception during /api/guc_data request for {username}: {e}")
         g.log_outcome = "internal_error_unhandled"
         g.log_error_message = f"Unhandled exception: {e}"
         return jsonify({"status": "error", "message": "An internal server error occurred", "data": None}), 500


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the executor
    def shutdown_executor():
        print("Shutting down log executor...")
        # wait=True ensures pending tasks complete
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_executor)

    # Use Waitress or Gunicorn in production
    logging.info(f"Starting Flask app for guc_data in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5000, threads=8)
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG)