import os
import requests
from flask import Flask, request, jsonify, g # Added g
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime, timezone # Added timezone
import sys
import logging # Added
import json # Added
from time import perf_counter # Added
import concurrent.futures # Added
import threading # Added
import atexit # Added
import traceback # Added

# --- Append parent directory if needed ---
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
    from api.scraping import authenticate_user # Your actual auth function
except ImportError:
    logging.critical("Failed to import authenticate_user. Using dummy function.", exc_info=True)
    def authenticate_user(username, password):
        logging.warning("Using dummy authenticate_user function.")
        # Simulate success for testing if real function is unavailable
        return True

# Load env vars
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s"
)
logger = logging.getLogger("login_api") # Use specific logger name

# --- Test credentials for simulation (Keep for test endpoint) ---
TEST_CREDENTIALS = {
    "test_user": "test_password",
    "admin": "admin123",
    "student": "student123",
    "mohamed.elsaadi": "Messo_1245",
}
STORED_CREDENTIALS = {
    "mohamed.elsaadi": "Messo_1245",
}

def simulate_authenticate_user(username, password, check_stored=False):
    """Simulated authentication function for testing purposes."""
    logger.info(f"Simulating authentication for user: {username}")
    university_auth_success = (
        username in TEST_CREDENTIALS and TEST_CREDENTIALS[username] == password
    )
    if check_stored:
        stored_password_match = (
            username in STORED_CREDENTIALS and STORED_CREDENTIALS[username] == password
        )
        if university_auth_success and not stored_password_match:
            logger.warning(f"Password mismatch detected for {username}! University accepts new password.")
            STORED_CREDENTIALS[username] = password
            logger.info(f"Updated stored password for {username}")
            return {"success": True, "stored_password_updated": True, "message": "Password updated and authentication successful"}
        elif university_auth_success:
            logger.info(f"Authentication successful for {username} (password matches stored)")
            return {"success": True, "stored_password_updated": False, "message": "Authentication successful"}
        else:
            logger.info(f"Authentication failed for {username}")
            return {"success": False, "stored_password_updated": False, "message": "Invalid credentials"}
    return university_auth_success

# --- Configuration ---
class Config:
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379") # Default Redis URL
    # BASE_SCHEDULE_URL_CONFIG = os.environ.get("BASE_SCHEDULE_URL", "...") # Not used here
    # BASE_ATTENDANCE_URL_CONFIG = os.environ.get("BASE_ATTENDANCE_URL", "...") # Not used here

config = Config()

if not config.ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
if not config.REDIS_URL:
    raise ValueError("REDIS_URL environment variable not set")

# --- Redis and Encryption ---
try:
    redis_client = redis.from_url(config.REDIS_URL, decode_responses=True)
    redis_client.ping()
    logger.info("Successfully connected to Redis.")
except redis.exceptions.ConnectionError as e:
    logger.critical(f"Failed to connect to Redis at {config.REDIS_URL}: {e}")
    raise ConnectionError(f"Cannot connect to Redis: {e}") from e
except Exception as e:
    logger.critical(f"Error initializing Redis client: {e}", exc_info=True)
    raise

try:
    fernet = Fernet(config.ENCRYPTION_KEY.encode())
except Exception as e:
    logger.critical(f"Failed to initialize Fernet encryption: {e}", exc_info=True)
    raise ValueError("Invalid ENCRYPTION_KEY") from e

# --- Logging Constants ---
API_LOG_KEY = "api_logs" # Specific Redis key for login logs
MAX_LOG_ENTRIES = 5000

# --- Thread Pool for Background Logging ---
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

# --- Helper function to get country from IP ---
def get_country_from_ip(ip_address):
    if not ip_address or ip_address in ("127.0.0.1", "::1"):
        logger.debug("Localhost or missing IP; using fallback country 'Localhost'.")
        return "Localhost"
    try:
        # Increased timeout slightly
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=7)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        if data.get("error"):
             logger.warning(f"IP API error for {ip_address}: {data.get('reason')}")
             return "API Error"
        country = data.get("country_name", "Unknown")
        logger.info(f"Determined country '{country}' for IP {ip_address}")
        return country
    except requests.exceptions.Timeout:
        logger.error(f"Timeout determining country for IP {ip_address}")
        return "Lookup Timeout"
    except requests.exceptions.RequestException as e:
         logger.error(f"Network error determining country for IP {ip_address}: {e}")
         return "Lookup Failed (Network)"
    except json.JSONDecodeError as e:
         logger.error(f"JSON decode error determining country for IP {ip_address}: {e}")
         return "Lookup Failed (JSON)"
    except Exception as e:
        logger.error(f"Unexpected error determining country for IP {ip_address}: {e}")
        return "Lookup Failed (Unknown)"

# --- Flask App ---
app = Flask(__name__)
app.config.from_object(config) # Load config

# --- Request Hooks for Logging ---
@app.before_request
def before_request_func():
    """Initialize request context for timing and logging."""
    g.start_time = perf_counter()
    g.request_time = datetime.now(timezone.utc)
    g.username = None # Will be set in the view function if possible
    g.log_outcome = "unknown" # Default outcome
    g.log_error_message = None # Default error message

@app.after_request
def after_request_logger(response):
    """Gathers log info, handles User-Agent robustly, and submits the logging task asynchronously."""
    # Skip logging for specific paths or methods if needed
    if request.method == 'OPTIONS' or request.path == '/test-login-form': # Example: skip form page
        return response

    elapsed_ms = (perf_counter() - g.start_time) * 1000

    # --- Robust User-Agent Handling ---
    ua_string_from_parsed = None
    ua_parse_error = False
    raw_ua_header = request.headers.get('User-Agent')

    try:
        if request.user_agent:
            ua_string_from_parsed = request.user_agent.string
    except Exception as e:
        ua_parse_error = True
        logger.error(f"Login API UA: Error accessing request.user_agent.string: {e}", exc_info=True)

    final_user_agent = ua_string_from_parsed if ua_string_from_parsed else raw_ua_header if raw_ua_header else "Unknown"
    if ua_parse_error and not raw_ua_header:
        final_user_agent = "Unknown (Parsing Error)"
    # --- End User-Agent Handling ---

    # Prepare Log Entry
    username = getattr(g, 'username', None) # Get username if set in route
    outcome = getattr(g, 'log_outcome', 'unknown')
    error_message = getattr(g, 'log_error_message', None)

    # Mask password in request arguments (POST body for /api/login)
    request_data = {}
    if request.is_json:
        try:
            request_data = request.get_json() if request.content_length else {}
            if 'password' in request_data:
                request_data['password'] = '********'
        except Exception as e:
            logger.warning(f"Could not parse request JSON for logging: {e}")
            request_data = {"error": "Could not parse JSON body"}
    else:
        # Handle form data if needed for other endpoints
        request_data = request.form.to_dict()
        if 'password' in request_data:
            request_data['password'] = '********'


    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or "Unknown"

    log_entry = {
        "endpoint": request.path,
        "error_message": error_message,
        "ip_address": ip_address,
        "method": request.method,
        "outcome": outcome,
        # Log masked JSON body or form data instead of query args for POST
        "request_data": request_data,
        "request_timestamp_utc": g.request_time.isoformat(),
        "response_size_bytes": response.content_length,
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status_code": response.status_code,
        "time_elapsed_ms": round(elapsed_ms, 2),
        "user_agent": final_user_agent,
        "username": username,
    }

    # Submit logging task
    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        logger.exception(f"CRITICAL: Failed to submit log task to executor: {e}")

    return response

@app.after_request
def add_cors_headers(response):
    """Add CORS headers."""
    # This runs *after* after_request_logger
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS" # Keep original methods
    return response

# --- Credential Helpers ---
def store_user_credentials(username, password):
    """Stores encrypted user credentials."""
    try:
        # Ensure password is str before encoding
        if isinstance(password, bytes):
            password = password.decode('utf-8', errors='ignore')
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)
        logger.info(f"Stored/Updated credentials for user: {username}")
    except redis.exceptions.ConnectionError as e:
        logger.error(f"[Redis] Connection error storing credentials for {username}: {e}")
        # Decide if this should raise an error or just be logged
        # raise ConnectionError("Failed to store credentials due to Redis connection error") from e
    except Exception as e:
        logger.error(f"Error storing credentials for user '{username}': {e}", exc_info=True)
        # raise RuntimeError("Failed to store credentials due to an unexpected error") from e

def get_stored_password(username):
    """Retrieves and decrypts a stored password. Returns None if not found or on error."""
    try:
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                # Ensure encrypted is bytes for fernet
                if isinstance(encrypted, str):
                    encrypted = encrypted.encode('utf-8')
                decrypted_bytes = fernet.decrypt(encrypted)
                return decrypted_bytes.decode("utf-8")
            except Exception as e: # Catches InvalidToken, etc.
                logger.error(f"Failed to decrypt password for {username}: {e}")
                return None # Treat decryption failure as password not available
        else:
            return None # User not found in storage
    except redis.exceptions.ConnectionError as e:
        logger.error(f"[Redis] Connection error getting stored password for {username}: {e}")
        return None # Treat connection error as password not available
    except Exception as e:
         logger.error(f"Error retrieving stored password for {username}: {e}", exc_info=True)
         return None # Treat other errors as password not available

# --- API Endpoint: /api/login ---
@app.route("/api/login", methods=["POST"])
def api_login():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        logging.info("Received bot health check request for attendance API.")
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Login API route is up!", "data": None}), 200
    data = request.get_json()
    if not data:
        # Set g values even for bad requests if possible
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing JSON request body"
        return jsonify({"status": "error", "message": "Missing JSON request body"}), 400

    username = data.get("username")
    password = data.get("password")
    g.username = username # Set username in context for logging

    # --- Validation ---
    if not username or not password:
        logger.warning("Login attempt missing username or password in JSON body")
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    # --- Version Check (from query param) ---
    # Note: Sending version in query param for POST is less common, but kept from original
    version_number_raw = None
    current_version = "1.0" # Default
    try:
        version_number_raw = redis_client.get("VERSION_NUMBER")
        if version_number_raw:
             current_version = version_number_raw # Already a string if decode_responses=True
    except redis.exceptions.ConnectionError as e:
         logger.error(f"[Redis] Connection error getting VERSION_NUMBER: {e}")
         # Decide if this is fatal or just a warning
         # g.log_outcome = "internal_error_redis"
         # g.log_error_message = "Failed to get version from Redis"
         # return jsonify({"status": "error", "message": "Internal server error (version check)"}), 500
    except Exception as e:
         logger.error(f"Error getting VERSION_NUMBER: {e}", exc_info=True)

    req_version = request.args.get("version_number") # Get from query parameters
    if req_version != current_version:
        logger.warning(f"Incorrect version number for {username}. Required: {current_version}, Got: {req_version}")
        g.log_outcome = "version_error"
        g.log_error_message = f"Incorrect version. Required: {current_version}, Got: {req_version}"
        return jsonify({"status": "error", "message": f"Incorrect version number. Please update the app to version {current_version}.", "data": None}), 403

    # --- Authentication ---
    logger.info(f"Login attempt for {username}")
    try:
        auth_success = authenticate_user(username, password) # Use the real function

        if auth_success:
            # Check if stored password exists and differs
            stored_password = get_stored_password(username)
            password_changed = stored_password is not None and stored_password != password

            if password_changed:
                logger.info(f"Password change detected for {username}. Updating stored credentials.")
            elif stored_password is None:
                logger.info(f"First successful login or credentials not stored for {username}. Storing.")
            # Store/Update credentials on successful login
            store_user_credentials(username, password) # Best effort storage

            # Store country (best effort)
            try:
                ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
                country = get_country_from_ip(ip_addr)
                if country not in ("Lookup Failed (Network)", "Lookup Failed (JSON)", "Lookup Failed (Unknown)", "Lookup Timeout", "API Error", "Localhost", "Unknown"):
                     redis_client.hset("user_countries", username, country)
                     logger.info(f"Stored country '{country}' for {username} from IP {ip_addr}")
                else:
                     logger.warning(f"Could not determine/store valid country for {username} from IP {ip_addr}, result was: {country}")
            except redis.exceptions.ConnectionError as e:
                 logger.error(f"[Redis] Connection error storing country for {username}: {e}")
            except Exception as country_err:
                logger.error(f"Error storing country for {username}: {country_err}", exc_info=True)

            logger.info(f"Login successful for {username}")
            g.log_outcome = "login_success"
            response_data = {"status": "success", "username": username}
            if password_changed:
                response_data["message"] = "Login successful. Password updated."
            return jsonify(response_data), 200
        else:
            logger.warning(f"Invalid credentials provided for {username}")
            g.log_outcome = "login_fail_invalid_credentials"
            g.log_error_message = "Invalid credentials"
            return jsonify({"status": "error", "message": "Invalid credentials", "data": None}), 401

    except Exception as e:
        # Catch errors during the authentication process itself
        logger.exception(f"Error during authentication process for {username}: {e}")
        g.log_outcome = "internal_error_auth"
        g.log_error_message = f"Authentication process failed: {e}"
        return jsonify({"status": "error", "message": "Authentication failed due to an internal error"}), 500


# --- Test Endpoints (Keep as they are, logging will happen via after_request) ---

@app.route("/api/test-login", methods=["POST"])
def test_login():
    # This endpoint only tests, doesn't store. Logging happens via after_request.
    # Set g.username for logging context
    data = request.get_json()
    username = data.get("username") if data else None
    password = data.get("password") if data else None
    g.username = username

    if not username or not password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    try:
        auth_success = authenticate_user(username, password) # Use real auth
        if auth_success:
            g.log_outcome = "test_login_success"
            return jsonify({"status": "success", "message": "Credentials are valid", "test_only": True}), 200
        else:
            g.log_outcome = "test_login_fail"
            g.log_error_message = "Invalid credentials (test)"
            return jsonify({"status": "error", "message": "Invalid credentials", "test_only": True}), 401
    except Exception as e:
        logger.exception(f"Error during test authentication for {username}: {e}")
        g.log_outcome = "internal_error_test_auth"
        g.log_error_message = f"Test authentication failed: {e}"
        return jsonify({"status": "error", "message": "Test authentication failed due to an internal error"}), 500


@app.route("/api/store_wrong_password", methods=["POST"])
def store_wrong_password():
    # This endpoint is for testing, logging happens via after_request.
    data = request.get_json()
    username = data.get("username") if data else None
    wrong_password = data.get("wrong_password") if data else None
    g.username = username # Set for logging

    if not username or not wrong_password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or wrong_password"
        return jsonify({"status": "error", "message": "Missing username or wrong_password"}), 400

    try:
        store_user_credentials(username, wrong_password) # Use the helper
        logger.info(f"Stored wrong password for {username} via test endpoint")
        g.log_outcome = "test_store_wrong_pw_success"
        return jsonify({"status": "success", "message": f"Wrong password stored for {username}"}), 200
    except Exception as e:
        logger.error(f"Error storing wrong password for {username} via test endpoint: {e}", exc_info=True)
        g.log_outcome = "test_store_wrong_pw_fail"
        g.log_error_message = f"Failed to store wrong password: {e}"
        return jsonify({"status": "error", "message": "Failed to store wrong password"}), 500


@app.route("/test-login-form", methods=["GET", "POST"])
def test_login_form():
    # This endpoint serves an HTML form and processes its submission.
    # Logging for the POST request will happen via after_request.
    # We don't log the GET request for the form itself.
    result = None
    if request.method == "POST":
        # Set g.username for logging context if possible
        username = request.form.get("username")
        password = request.form.get("password")
        g.username = username

        logger.info(f"Test form submission for username: {username}")

        if not username or not password:
            result = {"status": "error", "message": "Missing username or password"}
            g.log_outcome = "test_form_validation_error"
            g.log_error_message = "Missing username or password"
            logger.warning("Test form submission missing username or password")
        else:
            use_simulation = request.form.get("use_simulation") == "on"
            check_stored = request.form.get("check_stored") == "on"
            auth_mode = "Unknown"
            auth_success = False
            password_updated_flag = False

            try:
                if use_simulation:
                    logger.info("Using simulated authentication for test form")
                    if check_stored:
                        auth_result = simulate_authenticate_user(username, password, check_stored=True)
                        auth_success = auth_result["success"]
                        auth_mode = "Simulated (Stored Check)"
                        password_updated_flag = auth_result.get("stored_password_updated", False)
                    else:
                        auth_success = simulate_authenticate_user(username, password)
                        auth_mode = "Simulated (Simple)"
                else:
                    logger.info("Using real authentication for test form")
                    auth_success = authenticate_user(username, password) # Use real auth
                    auth_mode = "Real"

                if auth_success:
                    result = {"status": "success", "message": f"Credentials are valid ({auth_mode})", "auth_mode": auth_mode, "password_updated": password_updated_flag}
                    g.log_outcome = "test_form_success"
                    logger.info(f"Test form authentication successful for {username} using {auth_mode}")
                else:
                    result = {"status": "error", "message": f"Invalid credentials ({auth_mode})", "auth_mode": auth_mode, "password_updated": password_updated_flag}
                    g.log_outcome = "test_form_fail"
                    g.log_error_message = f"Invalid credentials ({auth_mode})"
                    logger.warning(f"Test form authentication failed for {username} using {auth_mode}")

            except Exception as e:
                 logger.exception(f"Error during test form authentication for {username}: {e}")
                 result = {"status": "error", "message": f"Test authentication failed due to an internal error: {e}", "auth_mode": auth_mode, "password_updated": password_updated_flag}
                 g.log_outcome = "internal_error_test_form_auth"
                 g.log_error_message = f"Test form authentication failed: {e}"

    # Render the HTML form, potentially with results from POST
    return html_response(result)


def html_response(result=None):
    # (HTML content remains the same as provided previously)
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
            button { padding: 10px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
            .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
            .success { background-color: #dff0d8; border: 1px solid #d6e9c6; color: #3c763d; }
            .error { background-color: #f2dede; border: 1px solid #ebccd1; color: #a94442; }
            .info-box { background-color: #d9edf7; border: 1px solid #bce8f1; color: #31708f; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
            .checkbox-group { margin-top: 10px; }
            .checkbox-group label { display: inline; margin-left: 5px; }
            .highlight { font-weight: bold; color: #d9534f; }
        </style>
    </head>
    <body>
        <h1>Test Login Form</h1>
        <p>This form tests credentials without actually storing them in the system.</p>

        <div class="info-box">
            <h3>Test Credentials (Simulation Mode):</h3>
            <ul>
                <li><strong>Username:</strong> test_user | <strong>Password:</strong> test_password</li>
                <li><strong>Username:</strong> admin | <strong>Password:</strong> admin123</li>
                <li><strong>Username:</strong> student | <strong>Password:</strong> student123</li>
                <li><strong class="highlight">Username:</strong> mohamed.elsaadi | <strong>Password:</strong> Messo_1245</li>
            </ul>
            <p><strong>Password Update Test:</strong> For mohamed.elsaadi, try using a different password with "Check Stored Password" enabled.</p>
        </div>

        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>

            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>

            <div class="checkbox-group">
                <input type="checkbox" id="use_simulation" name="use_simulation" checked>
                <label for="use_simulation">Use simulated authentication (doesn't connect to university website)</label>
            </div>

            <div class="checkbox-group">
                <input type="checkbox" id="check_stored" name="check_stored" checked>
                <label for="check_stored">Check against stored password (simulates password change detection)</label>
            </div>

            <button type="submit" style="margin-top: 15px;">Test Login</button>
        </form>
    """

    if result:
        status_class = "success" if result["status"] == "success" else "error"
        details_html = (
            f"<p>{result.get('details', '')}</p>" if result.get("details") else ""
        )
        # Use the password_updated flag from the result dict
        password_updated_text = "✓ Yes" if result.get("password_updated") else "✗ No"

        html += f"""
        <div class="result {status_class}">
            <h3>Result: {result["status"].upper()}</h3>
            <p>{result["message"]}</p>
            {details_html}
            <p>Authentication mode: {result.get("auth_mode", "Unknown")}</p>
            <p>Password updated (simulation): {password_updated_text}</p>
        </div>
        """
    html += """
    </body>
    </html>
    """
    return html


# --- Main Execution ---
if __name__ == "__main__":
    # Add shutdown hook for the *logging* executor
    def shutdown_log_executor():
        print("Shutting down log executor...")
        log_executor.shutdown(wait=True)
        print("Log executor shut down.")
    atexit.register(shutdown_log_executor)

    logging.info(f"Starting Flask app for login API in {'DEBUG' if config.DEBUG else 'PRODUCTION'} mode.")
    # Use Waitress or Gunicorn for production
    # Example: from waitress import serve
    #          serve(app, host='0.0.0.0', port=5005, threads=8) # Use a different port
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG) # Changed port