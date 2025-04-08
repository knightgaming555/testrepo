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
        cms_scraper,
        scrape_notifications, # Renamed? Assuming cms_scraper fetches data, scrape_notifications fetches notifications
    )
except ImportError:
    logging.critical("Failed to import scraping functions. Check path and file names.", exc_info=True)
    # Define dummy functions if needed for testing without imports
    def authenticate_user(u, p): return True
    def cms_scraper(u, p): return {"status": "success", "data": [{"course": "Dummy CMS Course"}]} # Example dummy data
    def scrape_notifications(u, p): return {"status": "success", "data": [{"title": "Dummy CMS Notification"}]} # Example dummy data


load_dotenv()

# --- Configuration and Setup ---
class Config:
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

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

# --- Logging Constants ---
API_LOG_KEY = "api_logs" # Common key for CMS related logs
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
    # Skip logging for OPTIONS requests if desired
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
        logging.error(f"CMS API UA: Error accessing request.user_agent.string: {e}", exc_info=True) # Keep error log

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
        "response_size_bytes": response.content_length, # May be None
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
        # Log locally if submitting the task fails critically
        logging.exception(f"CRITICAL: Failed to submit log task to executor: {e}")

    # Return the original response object.
    # The add_cors_headers function will run after this.
    return response
    
@app.after_request
def add_cors_headers(response):
    """Add CORS headers."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response

# --- Helper Functions for Credentials (Refactored) ---
# (Consider moving these to a shared auth module if used by multiple APIs)

class AuthError(Exception):
    """Custom exception for authentication failures."""
    def __init__(self, message, status_code, log_outcome, log_message):
        super().__init__(message)
        self.status_code = status_code
        self.log_outcome = log_outcome
        self.log_message = log_message

def get_stored_password(username):
    """Retrieves and decrypts a stored password. Raises AuthError on failure."""
    try:
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                decrypted_bytes = fernet.decrypt(encrypted.encode())
                return decrypted_bytes.decode("utf-8")
            except Exception as e:
                logging.error(f"Failed to decrypt password for {username}: {e}")
                raise AuthError("Error processing credentials", 500,
                                "internal_error_decrypt", "Failed to decrypt stored credentials") from e
        else:
            return None # User not found
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored password for {username}: {e}")
        raise AuthError("Internal server error retrieving credentials", 500,
                        "internal_error_credentials", "Redis connection error getting password") from e
    except Exception as e:
         logging.error(f"Error retrieving stored password for {username}: {e}", exc_info=True)
         raise AuthError("Internal server error retrieving credentials", 500,
                         "internal_error_credentials", "Unexpected error getting password") from e

def store_user_credentials(username, password):
    """Stores encrypted user credentials (best effort)."""
    try:
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)
        logging.info(f"Stored/Updated credentials for user: {username}")
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error storing credentials for {username}: {e}")
        # Don't fail the request, just log
    except Exception as e:
        logging.error(f"Error storing credentials for user '{username}': {e}", exc_info=True)
        # Don't fail the request, just log

def validate_and_get_password(username, password):
    """
    Validates credentials and returns the correct password to use.
    Raises AuthError on validation/auth failures.
    Sets g.log_outcome for auth steps.
    """
    if not username or not password:
        raise AuthError("Missing username or password", 400,
                        "validation_error", "Missing username or password")

    stored_pw = get_stored_password(username) # Can raise AuthError

    if stored_pw is not None:
        # User exists in store, check provided password against stored
        g.log_outcome = "stored_auth_attempt"
        if stored_pw.strip() == password.strip():
            g.log_outcome = "stored_auth_success"
            return stored_pw # Use stored password
        else:
            # Password mismatch
            # Optional: Add re-auth check against GUC here if desired
            raise AuthError("Invalid credentials", 401,
                            "auth_error_stored", "Invalid credentials (checked against stored)")
    else:
        # User not in store, authenticate against external source (GUC)
        g.log_outcome = "first_time_auth_attempt"
        logging.info(f"Credentials for {username} not stored. Authenticating externally.")
        try:
            auth_success = authenticate_user(username, password)
            if not auth_success:
                raise AuthError("Invalid credentials", 401,
                                "auth_error_first_time", "Invalid credentials (first time external check)")
            else:
                # Auth successful, store credentials (best effort) and use provided password
                g.log_outcome = "first_time_auth_success"
                store_user_credentials(username, password)
                return password # Use the provided, now verified, password
        except Exception as e:
            # Catch errors during the external authentication call itself
            logging.exception(f"Error during external authentication call for {username}: {e}")
            raise AuthError("Authentication service unavailable", 503, # Or 500
                            "external_auth_error", f"Error calling authentication service: {e}") from e


# --- API Endpoint: /api/cms_data ---
@app.route("/api/cms_data", methods=["GET"])
def api_cms_data():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Cms Data API route is up!", "data": None}), 200
    username = request.args.get("username")
    password = request.args.get("password")
    g.username = username # Set for logging context

    password_to_use = None
    try:
        # --- Authentication ---
        password_to_use = validate_and_get_password(username, password)
        # If it returns, auth was successful

        # --- Scraping ---
        logging.info(f"Starting CMS data scraping for user: {username}")
        g.log_outcome = "scrape_attempt" # Overwrite auth success outcome
        data = None
        try:
            # Call cms_scraper synchronously
            data = cms_scraper(username, password_to_use)

            # --- Handle Scrape Result ---
            # Adapt based on cms_scraper's return format for errors/success
            if isinstance(data, dict) and data.get("status") == "error":
                error_msg = data.get("message", "Unknown CMS scraping error")
                logging.warning(f"CMS scraper function returned error for {username}: {error_msg}")
                g.log_error_message = f"Scrape function error: {error_msg}"
                if "authentication failed" in error_msg.lower():
                     g.log_outcome = "scrape_auth_error"
                     return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
                elif "timeout" in error_msg.lower():
                     g.log_outcome = "scrape_timeout"
                     return jsonify({"status": "error", "message": "Scraping timed out", "data": None}), 504
                else:
                     g.log_outcome = "scrape_returned_error"
                     return jsonify({"status": "error", "message": f"Failed to fetch CMS data: {error_msg}", "data": None}), 502 # Or 500

            elif data is None: # Or check if data == [] if that indicates no data found
                logging.info(f"CMS data scraping returned no data for user: {username}")
                g.log_outcome = "scrape_success_nodata"
                # Return empty list/dict as success, matching original logic?
                return jsonify({"status": "success", "data": []}), 200 # Adjust structure as needed
            else:
                # Success with data
                logging.info(f"Successfully scraped CMS data for user: {username}")
                g.log_outcome = "scrape_success"
                return jsonify(data), 200 # Assuming data is the desired structure

        except Exception as e:
            # Catch unexpected errors during cms_scraper call
            logging.exception(f"Error during CMS data scraping execution for user: {username}")
            g.log_outcome = "scrape_exception"
            g.log_error_message = str(e)
            return jsonify({"status": "error", "message": f"Failed to fetch CMS data: {e}", "data": None}), 500

    except AuthError as e:
        # Handle errors raised by validate_and_get_password
        g.log_outcome = e.log_outcome
        g.log_error_message = e.log_message
        return jsonify({"status": "error", "message": str(e), "data": None}), e.status_code
    except Exception as e:
        # Catch truly unexpected errors before or after scraping
        logging.exception(f"Unhandled exception in /api/cms_data for {username}: {e}")
        g.log_outcome = "internal_error_unhandled"
        g.log_error_message = f"Unhandled exception: {e}"
        return jsonify({"status": "error", "message": "An internal server error occurred", "data": None}), 500


# --- API Endpoint: /api/cms_notifications ---
@app.route("/api/cms_notifications", methods=["GET"])
def api_cms_notifications():
    username = request.args.get("username")
    password = request.args.get("password")
    g.username = username # Set for logging context

    password_to_use = None
    try:
        # --- Authentication (Uses the same logic) ---
        password_to_use = validate_and_get_password(username, password)

        # --- Scraping ---
        logging.info(f"Starting CMS notifications scraping for user: {username}")
        g.log_outcome = "scrape_attempt" # Overwrite auth success outcome
        data = None
        try:
            # Call scrape_notifications synchronously
            data = scrape_notifications(username, password_to_use)

            # --- Handle Scrape Result ---
            # Adapt based on scrape_notifications's return format
            if isinstance(data, dict) and data.get("status") == "error":
                 error_msg = data.get("message", "Unknown CMS notification scraping error")
                 logging.warning(f"CMS notifications scraper returned error for {username}: {error_msg}")
                 g.log_error_message = f"Scrape function error: {error_msg}"
                 if "authentication failed" in error_msg.lower():
                     g.log_outcome = "scrape_auth_error"
                     return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
                 elif "timeout" in error_msg.lower():
                     g.log_outcome = "scrape_timeout"
                     return jsonify({"status": "error", "message": "Scraping timed out", "data": None}), 504
                 else:
                     g.log_outcome = "scrape_returned_error"
                     return jsonify({"status": "error", "message": f"Failed to fetch CMS notifications: {error_msg}", "data": None}), 502

            elif data is None: # Or check for empty list if applicable
                 logging.info(f"CMS notifications scraping returned no data for user: {username}")
                 g.log_outcome = "scrape_success_nodata"
                 return jsonify({"status": "success", "data": []}), 200 # Adjust structure as needed
            else:
                 # Success with data
                 logging.info(f"Successfully scraped CMS notifications for user: {username}")
                 g.log_outcome = "scrape_success"
                 return jsonify(data), 200 # Assuming data is the desired structure

        except Exception as e:
            # Catch unexpected errors during scrape_notifications call
            logging.exception(f"Error during CMS notifications scraping execution for user: {username}")
            g.log_outcome = "scrape_exception"
            g.log_error_message = str(e)
            return jsonify({"status": "error", "message": f"Failed to fetch CMS notifications: {e}", "data": None}), 500

    except AuthError as e:
        # Handle errors raised by validate_and_get_password
        g.log_outcome = e.log_outcome
        g.log_error_message = e.log_message
        return jsonify({"status": "error", "message": str(e), "data": None}), e.status_code
    except Exception as e:
        # Catch truly unexpected errors
        logging.exception(f"Unhandled exception in /api/cms_notifications for {username}: {e}")
        g.log_outcome = "internal_error_unhandled"
        g.log_error_message = f"Unhandled exception: {e}"
        return jsonify({"status": "error", "message": "An internal server error occurred", "data": None}), 500


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the executor
    def shutdown_executor():
        print("Shutting down log executor...")
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_executor)

    logging.info(f"Starting Flask app for CMS API in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5003, threads=8) # Use a different port
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG) # Changed port