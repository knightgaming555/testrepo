import os
import time
import json
import logging # Added
import sys
from datetime import datetime, timezone # Added timezone
from time import perf_counter # Added
from flask import Flask, request, jsonify, g # Added g
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, TimeoutError # Keep for scraping timeout
import concurrent.futures # Added specifically for logging executor
import traceback # Added for UA logging
import threading # Added for logging task context
import atexit # Added for shutdown hook

# --- Setup logging for critical/startup messages ---
# Configure once at the start
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s"
)

# --- Append parent directory if needed ---
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from api.scraping import (
        authenticate_user,
        scrape_exam_seats,
    )
except ImportError:
    logging.critical("Failed to import scraping functions. Using dummy functions.", exc_info=True)
    def authenticate_user(u, p): return True
    def scrape_exam_seats(u, p): return [{"exam": "Dummy Exam", "seat": "A1"}]

load_dotenv()

# --- Configuration and Setup ---
class Config:
    # DEBUG set via environment variable is better practice
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379") # Default Redis URL

config = Config()

if not config.ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
if not config.REDIS_URL:
    raise ValueError("REDIS_URL environment variable not set")

# --- Initialize Redis, Fernet ---
try:
    # decode_responses=True for easier string handling, adjust if needed
    redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
    redis_client.ping() # Test connection
    logging.info("Successfully connected to Redis.")
except redis.exceptions.ConnectionError as e:
    logging.critical(f"Failed to connect to Redis at {config.REDIS_URL}: {e}")
    raise ConnectionError(f"Cannot connect to Redis: {e}") from e
except Exception as e:
    logging.critical(f"Error initializing Redis client: {e}", exc_info=True)
    raise

try:
    fernet = Fernet(config.ENCRYPTION_KEY.encode()) # Key needs to be bytes
except Exception as e:
    logging.critical(f"Failed to initialize Fernet encryption: {e}", exc_info=True)
    raise ValueError("Invalid ENCRYPTION_KEY") from e

# --- Logging Constants ---
API_LOG_KEY = "api_logs" # Specific Redis key for exam_seats logs
MAX_LOG_ENTRIES = 5000 # Max number of log entries to keep

# --- Thread Pool for Background Logging ---
# Use a separate executor for logging to avoid interfering with scraping timeout executor
log_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix='LogThread')

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
app.config.from_object(config) # Load config from class

# --- Request Hooks for Logging ---
@app.before_request
def before_request_func():
    """Initialize request context for timing and logging."""
    g.start_time = perf_counter()
    g.request_time = datetime.now(timezone.utc)
    g.username = None # Will be set in the view function
    g.log_outcome = "unknown" # Default outcome
    g.log_error_message = None # Default error message

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
        if request.user_agent:
            ua_string_from_parsed = request.user_agent.string
    except Exception as e:
        ua_parse_error = True
        logging.error(f"Exam Seats API UA: Error accessing request.user_agent.string: {e}", exc_info=True) # Keep error log

    final_user_agent = ua_string_from_parsed if ua_string_from_parsed else raw_ua_header if raw_ua_header else "Unknown"
    if ua_parse_error and not raw_ua_header:
        final_user_agent = "Unknown (Parsing Error)"
    # --- End User-Agent Handling ---

    # Prepare Log Entry
    username = getattr(g, 'username', None)
    outcome = getattr(g, 'log_outcome', 'unknown')
    error_message = getattr(g, 'log_error_message', None)

    request_args = request.args.to_dict()
    if 'password' in request_args:
        request_args['password'] = '********' # Mask password

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
        "user_agent": final_user_agent,
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
    # This runs *after* after_request_logger
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS" # Keep original methods
    return response

# --- Helper Functions (Keep as they are, assuming they work) ---
def get_all_stored_users():
    """Retrieves all stored user credentials."""
    try:
        stored = redis_client.hgetall("user_credentials")
        # decode_responses=True handles decoding
        return stored # Returns dict[str, str]
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored users: {e}")
        raise ConnectionError("Failed to retrieve credentials due to Redis connection error") from e
    except Exception as e:
        logging.error(f"Error getting stored users from Redis: {e}", exc_info=True)
        raise RuntimeError("Failed to retrieve credentials due to an unexpected error") from e

def store_user_credentials(username, password):
    """Stores encrypted user credentials."""
    try:
        encrypted = fernet.encrypt(password.encode()).decode() # Encrypt bytes, store as string
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


# --- API Endpoint: /api/exam_seats ---
@app.route("/api/exam_seats", methods=["GET"])
def api_exam_seats():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Exam seats API route is up!", "data": None}), 200
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

    logging.info(f"Starting exam seats scraping for user: {username}")
    g.log_outcome = "scrape_attempt"
    data = None
    # Use a temporary executor *only* for the scraping timeout logic
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix='ScrapeThread') as executor:
        future = executor.submit(scrape_exam_seats, username, password_to_use)
        try:
            # Wait for the scraping function with a timeout
            data = future.result(timeout=20) # Increased timeout slightly
        except TimeoutError:
            logging.warning(f"Timeout during exam seats scraping for user: {username}")
            g.log_outcome = "scrape_timeout"
            g.log_error_message = "Scraping function timed out after 20 seconds"
            return jsonify({"status": "error", "message": "Scraping timed out", "data": None}), 504
        except Exception as e:
            # Catch errors raised *by* the scrape_exam_seats function itself
            logging.exception(f"Error during exam seats scraping execution for user: {username}")
            g.log_outcome = "scrape_exception"
            g.log_error_message = str(e)
            # Check if it was an auth error reported by the scraper
            if "authentication failed" in str(e).lower():
                 g.log_outcome = "scrape_auth_error"
                 return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
            else:
                 return jsonify({"status": "error", "message": f"Failed to fetch exam seats data: {e}", "data": None}), 500

    # --- Process Scrape Result ---
    # Check if scrape_exam_seats returned an error structure (if it does that)
    if isinstance(data, dict) and "error" in data:
         error_msg = data["error"]
         logging.warning(f"Scraping function returned error structure for {username}: {error_msg}")
         g.log_error_message = f"Scrape function error: {error_msg}"
         if "authentication failed" in error_msg.lower():
             g.log_outcome = "scrape_auth_error"
             return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
         else:
             g.log_outcome = "scrape_returned_error"
             return jsonify({"status": "error", "message": f"Failed to fetch exam seats: {error_msg}", "data": None}), 502

    # Handle cases where scraping might return None or empty list
    if data is None:
        logging.warning(f"Exam seats scraping returned None for user: {username}")
        g.log_outcome = "scrape_success_nodata"
        return jsonify([]), 200 # Return empty list, 200 OK
    elif isinstance(data, list) and not data:
         logging.info(f"Successfully scraped exam seats for user: {username} (no seats found)")
         g.log_outcome = "scrape_success_empty"
         return jsonify([]), 200 # Return empty list, 200 OK
    else:
        # Actual success with data
        logging.info(f"Successfully scraped exam seats for user: {username}")
        g.log_outcome = "scrape_success"
        # Assuming scrape_exam_seats returns the list directly
        return jsonify(data), 200


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the *logging* executor
    def shutdown_log_executor():
        print("Shutting down log executor...")
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_log_executor)

    logging.info(f"Starting Flask app for exam_seats API in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Use Waitress or Gunicorn for production
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5004, threads=8) # Use a different port
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG) # Changed port