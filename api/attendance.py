import os
import time
import json # Added
import logging # Added for standard logging
import sys # Added
from datetime import datetime, timezone # Added timezone
from time import perf_counter # Added
from flask import Flask, request, jsonify, g # Added g
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor # Keep this one for logging
import threading # Added
import atexit # Added

# --- Setup logging for critical/startup messages ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

# --- Append parent directory (Adjust if necessary) ---
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from api.scraping import (
        authenticate_user,
        scrape_attendance, # Assuming this is your attendance scraping function
    )
except ImportError:
    logging.critical("Failed to import scraping functions. Check path and file names.", exc_info=True)
    # Define dummy functions if needed for testing without imports
    def authenticate_user(u, p): return True
    def scrape_attendance(u, p, url, retries, delay): return {"status": "success", "data": [{"course": "Dummy Attendance", "absences": 1}]} # Example dummy data

load_dotenv()

# --- Configuration and Setup ---
class Config:
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )

config = Config()

if not config.ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
if not config.REDIS_URL:
    raise ValueError("REDIS_URL environment variable not set")

# --- Initialize Redis, Fernet ---
try:
    redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
    redis_client.ping()
    logging.info("Successfully connected to Redis.")
except redis.exceptions.ConnectionError as e:
    logging.critical(f"Failed to connect to Redis at {config.REDIS_URL}: {e}")
    raise ConnectionError(f"Cannot connect to Redis: {e}") from e
except Exception as e:
    logging.critical(f"Error initializing Redis client: {e}", exc_info=True)
    raise

try:
    fernet = Fernet(config.ENCRYPTION_KEY.encode())
except Exception as e:
    logging.critical(f"Failed to initialize Fernet encryption: {e}", exc_info=True)
    raise ValueError("Invalid ENCRYPTION_KEY") from e

# --- Constants ---
BASE_ATTENDANCE_URL = config.BASE_ATTENDANCE_URL_CONFIG
SCRAPE_RETRIES = 3 # Example: Number of retries for scrape_attendance
SCRAPE_DELAY = 2   # Example: Delay between retries

# --- Logging Constants ---
API_LOG_KEY = "api_logs" # Specific Redis key for attendance logs
MAX_LOG_ENTRIES = 5000

# --- Thread Pool for Background Logging ---
log_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix='LogThread')

# --- Background Logging Task ---
def _log_to_redis_task(log_entry_dict):
    """Internal task to write logs to Redis asynchronously."""
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

# --- Request Hooks for Logging ---
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
    """Gathers log info, handles User-Agent robustly, and submits the logging task asynchronously."""
    if request.method == 'OPTIONS':
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
        logging.error(f"Attendance API UA: Error accessing request.user_agent.string: {e}", exc_info=True) # Keep error log

    # Determine the final user_agent string for the log using fallback logic:
    # 1. Try the string from the parsed object.
    # 2. If that failed or was empty, try the raw header string.
    # 3. If both are unavailable, default to "Unknown".
    final_user_agent = ua_string_from_parsed if ua_string_from_parsed else raw_ua_header if raw_ua_header else "Unknown"

    # Handle the edge case where parsing failed AND the raw header was also missing
    if ua_parse_error and not raw_ua_header:
        final_user_agent = "Unknown (Parsing Error)"
    # --- End User-Agent Handling ---


    # Prepare Log Entry using values from `g` and the request/response
    username = getattr(g, 'username', None)
    outcome = getattr(g, 'log_outcome', 'unknown')
    error_message = getattr(g, 'log_error_message', None)

    # Mask password in request arguments
    request_args = request.args.to_dict()
    if 'password' in request_args:
        request_args['password'] = '********'

    # Get IP address, considering proxies
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or "Unknown"

    log_entry = {
        "endpoint": request.path,
        "error_message": error_message,
        "ip_address": ip_address,
        "method": request.method,
        "outcome": outcome,
        "request_args": request_args,
        "request_timestamp_utc": g.request_time.isoformat(),
        "response_size_bytes": response.content_length,
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status_code": response.status_code,
        "time_elapsed_ms": round(elapsed_ms, 2),
        "user_agent": final_user_agent, # Use the robustly determined value
        "username": username,
    }

    # Submit logging task to the background executor
    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        logging.exception(f"CRITICAL: Failed to submit log task to executor: {e}")

    return response
    
@app.after_request
def add_cors_headers(response):
    """Add CORS headers."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

# --- Helper Functions for Credentials ---
# (These are identical to the grades endpoint - consider moving to a shared `utils.py` or `auth.py`)
def get_all_stored_users():
    """Retrieves all stored user credentials."""
    try:
        stored = redis_client.hgetall("user_credentials")
        return stored
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored users: {e}")
        raise ConnectionError("Failed to retrieve credentials due to Redis connection error") from e
    except Exception as e:
        logging.error(f"Error getting stored users from Redis: {e}", exc_info=True)
        raise RuntimeError("Failed to retrieve credentials due to an unexpected error") from e

def store_user_credentials(username, password):
    """Stores encrypted user credentials."""
    try:
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)
        logging.info(f"Stored/Updated credentials for user: {username}")
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error storing credentials for {username}: {e}")
    except Exception as e:
        logging.error(f"Error storing credentials for user '{username}': {e}", exc_info=True)

def get_stored_password(username):
    """Retrieves and decrypts a stored password."""
    try:
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                decrypted_bytes = fernet.decrypt(encrypted.encode())
                return decrypted_bytes.decode("utf-8")
            except Exception as e:
                logging.error(f"Failed to decrypt password for {username}: {e}")
                raise ValueError("Failed to decrypt stored credentials") from e
        else:
            return None
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored password for {username}: {e}")
        raise ConnectionError("Failed to retrieve stored password due to Redis connection error") from e
    except Exception as e:
         logging.error(f"Error retrieving stored password for {username}: {e}", exc_info=True)
         raise RuntimeError("Failed to retrieve stored password due to an unexpected error") from e

# --- API Endpoint: /api/attendance ---
@app.route("/api/attendance", methods=["GET"])
def api_attendance():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Attendance API route is up!", "data": None}), 200

    username = request.args.get("username")
    password = request.args.get("password")
    g.username = username # Set for logging


    
    # --- Validation ---
    if not username or not password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"status": "error", "message": "Missing username or password", "data": None}), 400

    password_to_use = None
    try:
        # --- Authentication Logic ---
        stored_users = get_all_stored_users()

        if username in stored_users:
            g.log_outcome = "stored_auth_attempt"
            stored_pw = get_stored_password(username) # Raises exceptions on failure
            if stored_pw is None:
                 logging.error(f"Inconsistency: User {username} found in keys but hget failed.")
                 g.log_outcome = "internal_error_credential_state"
                 g.log_error_message = "Credential state inconsistency"
                 return jsonify({"status": "error", "message": "Internal server error", "data": None}), 500

            if stored_pw.strip() != password.strip():
                g.log_outcome = "auth_error_stored"
                g.log_error_message = "Invalid credentials (checked against stored)"
                return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401
            else:
                g.log_outcome = "stored_auth_success"
                password_to_use = stored_pw
        else:
            # --- First time user ---
            g.log_outcome = "first_time_auth_attempt"
            logging.info(f"Credentials for {username} not stored. Authenticating against GUC.")
            auth_success = authenticate_user(username, password)
            if not auth_success:
                g.log_outcome = "auth_error_first_time"
                g.log_error_message = "Invalid credentials (first time GUC check)"
                return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401

            g.log_outcome = "first_time_auth_success"
            store_user_credentials(username, password)
            password_to_use = password

    # --- Handle Specific Expected Errors from Auth ---
    except ValueError as e: # Decryption errors
        g.log_outcome = "internal_error_decrypt"
        g.log_error_message = str(e)
        return jsonify({"status": "error", "message": "Error processing credentials", "data": None}), 500
    except (ConnectionError, RuntimeError) as e: # Redis/Runtime errors
        g.log_outcome = "internal_error_credentials"
        g.log_error_message = str(e)
        return jsonify({"status": "error", "message": "Internal server error retrieving credentials", "data": None}), 500
    except Exception as e: # Unexpected auth errors
         logging.exception(f"Unexpected error during authentication phase for {username}: {e}")
         g.log_outcome = "internal_error_auth_unhandled"
         g.log_error_message = f"Unexpected auth error: {e}"
         return jsonify({"status": "error", "message": "Internal server error during authentication", "data": None}), 500

    # --- Scraping (if authentication passed) ---
    if not password_to_use:
         logging.error(f"Internal logic error: password_to_use not set for user {username} after auth checks.")
         g.log_outcome = "internal_error_auth_logic"
         g.log_error_message = "Password for scraping not determined"
         return jsonify({"status": "error", "message": "Internal server error", "data": None}), 500

    logging.info(f"Starting attendance scraping for user: {username}")
    g.log_outcome = "scrape_attempt"
    data = None
    try:
        # Call scrape_attendance synchronously
        # Pass necessary parameters like BASE_ATTENDANCE_URL, retries, delay
        data = scrape_attendance(
            username,
            password_to_use,
            BASE_ATTENDANCE_URL,
            SCRAPE_RETRIES,
            SCRAPE_DELAY
        )

        # --- Handle Scrape Result ---
        # Adapt this based on what scrape_attendance actually returns on error/success
        if isinstance(data, dict) and data.get("status") == "error": # Example: Check status key
             error_msg = data.get("message", "Unknown scraping error")
             logging.warning(f"Scraping function returned error for {username}: {error_msg}")
             g.log_error_message = f"Scrape function error: {error_msg}"
             if "authentication failed" in error_msg.lower():
                 g.log_outcome = "scrape_auth_error"
                 return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
             elif "timeout" in error_msg.lower():
                  g.log_outcome = "scrape_timeout"
                  return jsonify({"status": "error", "message": "Scraping timed out", "data": None}), 504
             else:
                  g.log_outcome = "scrape_returned_error"
                  return jsonify({"status": "error", "message": f"Failed to fetch attendance: {error_msg}", "data": None}), 502

        # Handle cases where scraping might return None or empty list/dict for no data
        if data is None:
             # Decide if None means error or just no data found
             logging.warning(f"Attendance scraping returned None for user: {username}")
             g.log_outcome = "scrape_success_nodata" # Or scrape_error if None indicates failure
             # Return empty list/dict or an error depending on expected behavior
             return jsonify({"status": "success", "message": "No attendance data found", "data": []}), 200 # Example: success but empty

        # Assuming success means non-error data structure is returned
        logging.info(f"Successfully scraped attendance for user: {username}")
        g.log_outcome = "scrape_success"
        # Ensure the jsonify includes status/data keys if that's the expected contract
        # If scrape_attendance returns {"status": "success", "data": [...]}, just return it:
        return jsonify(data), 200
        # If scrape_attendance just returns the list/dict of data:
        # return jsonify({"status": "success", "data": data}), 200


    except Exception as e:
        # Catch unexpected errors *during* the scrape_attendance call
        logging.exception(f"Error during attendance scraping execution for user: {username}")
        g.log_outcome = "scrape_exception"
        g.log_error_message = str(e)
        # Consider specific exception types if scrape_attendance raises them
        return jsonify({"status": "error", "message": f"Failed to fetch attendance data: {e}", "data": None}), 500


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the executor
    def shutdown_executor():
        print("Shutting down log executor...")
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_executor)

    logging.info(f"Starting Flask app for attendance API in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5002, threads=8) # Use a different port
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG) # Changed port