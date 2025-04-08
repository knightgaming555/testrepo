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
from concurrent.futures import ThreadPoolExecutor # Keep this one
import threading # Added
import atexit # Added

# --- Setup logging for critical/startup messages ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s')

# --- Append parent directory (Adjust if necessary) ---
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from api.scraping import (
        authenticate_user,
        scrape_grades,
    )
except ImportError:
    logging.critical("Failed to import scraping functions. Check path and file names.", exc_info=True)
    # Define dummy functions if needed for testing without imports
    def authenticate_user(u, p): return True
    def scrape_grades(u, p): return [{"course": "Dummy Course", "grade": "A"}] # Example dummy data

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
    redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
    redis_client.ping() # Test connection
    logging.info("Successfully connected to Redis.")
except redis.exceptions.ConnectionError as e:
    logging.critical(f"Failed to connect to Redis at {config.REDIS_URL}: {e}")
    # Depending on requirements, you might exit or run with limited functionality
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
API_LOG_KEY = "api_logs" # Specific Redis key for grades logs
MAX_LOG_ENTRIES = 5000 # Max number of log entries to keep in Redis list

# --- Thread Pool for Background Logging ---
log_executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix='LogThread')

# --- Background Logging Task ---
def _log_to_redis_task(log_entry_dict):
    """Internal task to write logs to Redis asynchronously."""
    try:
        # Ensure all data types are JSON serializable
        log_entry_json = json.dumps(log_entry_dict)
        # Use pipeline for atomic push+trim
        # No need to get a separate client if decode_responses=True, just pass string
        pipe = redis_client.pipeline()
        pipe.lpush(API_LOG_KEY, log_entry_json)
        pipe.ltrim(API_LOG_KEY, 0, MAX_LOG_ENTRIES - 1)
        pipe.execute()
    except redis.exceptions.ConnectionError as e:
        # Log to standard error if Redis connection fails during logging
        print(f"[{threading.current_thread().name}] Log Error: Redis connection error: {e}", file=sys.stderr)
    except TypeError as e:
         # Catch serialization errors
         print(f"[{threading.current_thread().name}] Log Error: Failed to serialize log entry to JSON: {e}", file=sys.stderr)
         problematic_items = {k: repr(v) for k, v in log_entry_dict.items() if not isinstance(v, (str, int, float, bool, list, dict, type(None)))}
         print(f"[{threading.current_thread().name}] Log Error: Problematic items: {problematic_items}", file=sys.stderr)
    except Exception as e:
        # Catch any other errors during the logging task
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
    # Avoid logging OPTIONS requests, customize as needed
    if request.method == 'OPTIONS': # Standard practice
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
        logging.error(f"Grades API UA: Error accessing request.user_agent.string: {e}", exc_info=True) # Keep error log

    # Determine the final user_agent string for the log using fallback logic:
    # 1. Try the string from the parsed object.
    # 2. If that failed or was empty, try the raw header string.
    # 3. If both are unavailable, default to "Unknown".
    final_user_agent = ua_string_from_parsed if ua_string_from_parsed else raw_ua_header if raw_ua_header else "Unknown"

    # Handle the edge case where parsing failed AND the raw header was also missing
    if ua_parse_error and not raw_ua_header:
        final_user_agent = "Unknown (Parsing Error)"
    # --- End User-Agent Handling ---


    # --- Prepare Log Entry (Matches the structure from previous examples) ---
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
        "error_message": error_message,
        "ip_address": ip_address,
        "method": request.method,
        "outcome": outcome,
        "request_args": request_args,
        "request_timestamp_utc": g.request_time.isoformat(),
        "response_size_bytes": response.content_length, # Get size from response object, may be None
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status_code": response.status_code,
        "time_elapsed_ms": round(elapsed_ms, 2),
        "user_agent": final_user_agent, # Use the robustly determined value
        "username": username,
    }
    # --- End Log Entry Preparation ---

    # Submit the logging task to the background executor
    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        # Use standard logging if submitting the log task fails (critical)
        logging.exception(f"CRITICAL: Failed to submit log task to executor: {e}")

    # Return the original response immediately
    # The add_cors_headers function will run after this.
    return response
@app.after_request
def add_cors_headers(response):
    """Add CORS headers to allow cross-origin requests."""
    # This runs *after* after_request_logger
    response.headers["Access-Control-Allow-Origin"] = "*" # Be more specific in production if possible
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization" # Add others if needed
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS" # Adjust as needed
    return response


# --- Helper Functions for Credentials (Consider moving to a shared module) ---
def get_all_stored_users():
    """Retrieves all stored user credentials."""
    try:
        stored = redis_client.hgetall("user_credentials")
        # decode_responses=True handles decoding
        return stored # Returns dict[str, str]
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored users: {e}")
        # Decide how to handle this - fail request or proceed without? Failing is safer.
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
        # Log the error but might not need to fail the request if scraping succeeded
    except Exception as e:
        logging.error(f"Error storing credentials for user '{username}': {e}", exc_info=True)

def get_stored_password(username):
    """Retrieves and decrypts a stored password."""
    try:
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                # Re-encode to bytes for decryption
                decrypted_bytes = fernet.decrypt(encrypted.encode())
                return decrypted_bytes.decode("utf-8")
            except Exception as e: # Catches InvalidToken, etc.
                logging.error(f"Failed to decrypt password for {username}: {e}")
                # Consider this an auth failure or internal error? Treat as internal error for now.
                raise ValueError("Failed to decrypt stored credentials") from e
        else:
            return None # User not found in storage
    except redis.exceptions.ConnectionError as e:
        logging.error(f"[Redis] Connection error getting stored password for {username}: {e}")
        raise ConnectionError("Failed to retrieve stored password due to Redis connection error") from e
    except Exception as e:
         logging.error(f"Error retrieving stored password for {username}: {e}", exc_info=True)
         raise RuntimeError("Failed to retrieve stored password due to an unexpected error") from e

# --- API Endpoint: /api/grades ---
@app.route("/api/grades", methods=["GET"])
def api_grades():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Grades API route is up!", "data": None}), 200
    username = request.args.get("username")
    password = request.args.get("password")
    g.username = username # Set username in request context for logging

    # --- Validation ---
    if not username or not password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"status": "error", "message": "Missing username or password", "data": None}), 400

    password_to_use = None
    try:
        # --- Authentication Logic ---
        stored_users = get_all_stored_users() # Fetch all users (can be slow with many users)
        # Alternative: Directly try fetching the specific user `hget("user_credentials", username)`

        if username in stored_users:
            g.log_outcome = "stored_auth_attempt"
            stored_pw = get_stored_password(username) # Handles decryption errors internally by raising
            if stored_pw is None:
                # This case shouldn't happen if username is in stored_users keys, but handle defensively
                 logging.error(f"Inconsistency: User {username} found in keys but hget failed.")
                 g.log_outcome = "internal_error_credential_state"
                 g.log_error_message = "Credential state inconsistency"
                 return jsonify({"status": "error", "message": "Internal server error", "data": None}), 500

            if stored_pw.strip() != password.strip():
                g.log_outcome = "auth_error_stored"
                g.log_error_message = "Invalid credentials (checked against stored)"
                # Optional: try re-authenticating against GUC here?
                return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401
            else:
                g.log_outcome = "stored_auth_success"
                password_to_use = stored_pw # Use the verified stored password
        else:
            # --- First time user (or not found in store) ---
            g.log_outcome = "first_time_auth_attempt"
            logging.info(f"Credentials for {username} not stored. Authenticating against GUC.")
            auth_success = authenticate_user(username, password) # Check against GUC
            if not auth_success:
                g.log_outcome = "auth_error_first_time"
                g.log_error_message = "Invalid credentials (first time GUC check)"
                return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401

            # Auth successful, store credentials and use provided password
            g.log_outcome = "first_time_auth_success"
            store_user_credentials(username, password)
            password_to_use = password

    # --- Handle Specific Expected Errors from Auth ---
    except ValueError as e: # Catch decryption errors from get_stored_password
        g.log_outcome = "internal_error_decrypt"
        g.log_error_message = str(e)
        return jsonify({"status": "error", "message": "Error processing credentials", "data": None}), 500
    except (ConnectionError, RuntimeError) as e: # Catch Redis/Runtime errors from credential helpers
        g.log_outcome = "internal_error_credentials"
        g.log_error_message = str(e)
        return jsonify({"status": "error", "message": "Internal server error retrieving credentials", "data": None}), 500
    except Exception as e: # Catch unexpected errors during auth
         logging.exception(f"Unexpected error during authentication phase for {username}: {e}")
         g.log_outcome = "internal_error_auth_unhandled"
         g.log_error_message = f"Unexpected auth error: {e}"
         return jsonify({"status": "error", "message": "Internal server error during authentication", "data": None}), 500


    # --- Scraping (if authentication passed) ---
    if not password_to_use:
         # Should not happen if logic above is correct, but safety check
         logging.error(f"Internal logic error: password_to_use not set for user {username} after auth checks.")
         g.log_outcome = "internal_error_auth_logic"
         g.log_error_message = "Password for scraping not determined"
         return jsonify({"status": "error", "message": "Internal server error", "data": None}), 500

    logging.info(f"Starting grades scraping for user: {username}")
    g.log_outcome = "scrape_attempt"
    data = None # Initialize data
    try:
        # Call scrape_grades directly and synchronously
        # Assumes scrape_grades handles its own internal timeouts/errors gracefully
        # or raises specific exceptions we can catch.
        data = scrape_grades(username, password_to_use)

        # Check if scrape_grades returned an error structure (if it does that)
        if isinstance(data, dict) and "error" in data:
             error_msg = data["error"]
             logging.warning(f"Scraping function returned error for {username}: {error_msg}")
             g.log_error_message = f"Scrape function error: {error_msg}"
             # Map internal error messages to outcomes and status codes
             if "authentication failed" in error_msg.lower():
                 g.log_outcome = "scrape_auth_error"
                 return jsonify({"status": "error", "message": "Authentication failed during scrape", "data": None}), 401
             elif "timeout" in error_msg.lower():
                  g.log_outcome = "scrape_timeout"
                  return jsonify({"status": "error", "message": "Scraping timed out", "data": None}), 504
             else:
                  g.log_outcome = "scrape_returned_error"
                  return jsonify({"status": "error", "message": f"Failed to fetch grades: {error_msg}", "data": None}), 502 # Bad Gateway?

        # Handle cases where scraping might return None or empty list on failure/no data
        if data is None:
            logging.warning(f"Grades scraping returned None for user: {username}")
            # Treat as success with empty data as per original logic?
            g.log_outcome = "scrape_success_nodata" # More specific outcome
            return jsonify([]), 200 # Return empty list, 200 OK
        elif isinstance(data, list) and not data:
             logging.info(f"Successfully scraped grades for user: {username} (no grades found)")
             g.log_outcome = "scrape_success_empty" # Specific outcome for empty list
             return jsonify([]), 200 # Return empty list, 200 OK
        else:
            # Actual success with data
            logging.info(f"Successfully scraped grades for user: {username}")
            g.log_outcome = "scrape_success"
            # NOTE: Original code returned 'data', assuming scrape_grades returns
            # the exact structure needed (e.g., a list of grades). If it returns
            # a dict like {"status": "success", "data": [...]}, adjust here.
            return jsonify(data), 200

    except Exception as e:
        # Catch unexpected errors *during* the scrape_grades call
        logging.exception(f"Error during grades scraping execution for user: {username}")
        g.log_outcome = "scrape_exception"
        g.log_error_message = str(e)
        # Consider specific exception types if scrape_grades raises them (e.g., TimeoutError, AuthError)
        return jsonify({"status": "error", "message": f"Failed to fetch grades data: {e}", "data": None}), 500


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the executor
    def shutdown_executor():
        print("Shutting down log executor...")
        # wait=True ensures pending log tasks attempt completion
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_executor)

    # Use Waitress or Gunicorn for production instead of app.run(debug=True)
    logging.info(f"Starting Flask app for grades API in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5001, threads=8) # Use a different port if needed
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG) # Changed port for clarity if running multiple APIs