# app.py (Version 2 - Enhanced Admin Control)
import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet

import redis
import json
import logging  # Import logging module
from datetime import datetime

from scraping import (
    authenticate_user,
    scrape_guc_data,
    scrape_schedule,
    cms_scraper,
    scrape_grades,
    scrape_attendance,
    scrape_exam_seats,
)


# Load environment variables from .env file
load_dotenv()


class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )  # Configurable schedule URL
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )  # Configurable attendance URL


config = Config()
app = Flask(__name__, template_folder="../templates")
CORS(app)

redis_client = redis.from_url(os.environ.get("REDIS_URL"))

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
scraper_logs = []  # In-memory scraper log list (for /admin/view_logs)
api_logs = []  # In-memory API request log list (for /admin/view_api_logs)
LOG_HISTORY_LENGTH = 100  # Number of log messages to keep in memory


def get_config(key, default_value):
    """Retrieve a persistent configuration value from Redis, or initialize it with a default"""
    value = redis_client.get(key)
    if value is not None:
        return value.decode()
    else:
        redis_client.set(key, default_value)
        return default_value


def set_config(key, value):
    """Update a persistent configuration value in Redis."""
    redis_client.set(key, value)


# Global variables for whitelist, version and now configurable URLs
whitelist = get_config(
    "WHITELIST",
    os.environ.get("WHITELIST"),
).split(",")
version_number2 = get_config("VERSION_NUMBER", os.environ.get("VERSION_NUMBER"))
BASE_SCHEDULE_URL = get_config(
    "BASE_SCHEDULE_URL_CONFIG", config.BASE_SCHEDULE_URL_CONFIG
)  # Load from Redis or Config class
BASE_ATTENDANCE_URL = get_config(
    "BASE_ATTENDANCE_URL_CONFIG", config.BASE_ATTENDANCE_URL_CONFIG
)  # Load from Redis or Config class


# In-memory dictionary for storing user credentials for testing.


# Initialize Fernet using the provided encryption key.
fernet = Fernet(config.ENCRYPTION_KEY)


def is_user_authorized(username):
    return username in whitelist


def store_user_credentials(username, password):
    """
    Encrypt and store the user's credentials in Redis.
    The credentials are stored in a Redis hash named "user_credentials".
    """
    encrypted_password = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted_password)


def get_all_stored_users():
    """
    Retrieve all stored user credentials from Redis.
    Returns a dictionary mapping usernames to encrypted passwords (as strings).
    """
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def log_scraper_event(message):
    """Add a message to the scraper log, keeping history limited."""
    log_message = f"{datetime.now().isoformat()} - {message}"
    scraper_logs.insert(0, log_message)  # Prepend to keep most recent first
    if len(scraper_logs) > LOG_HISTORY_LENGTH:
        scraper_logs.pop()  # Remove oldest if limit exceeded


def log_api_request(endpoint, status_code):
    """Log API request details."""
    log_message = (
        f"{datetime.now().isoformat()} - Endpoint: {endpoint}, Status: {status_code}"
    )
    api_logs.insert(0, log_message)
    if len(api_logs) > LOG_HISTORY_LENGTH:
        api_logs.pop()


@app.before_request
def before_api_request():
    """Log API requests before they are processed."""
    if request.path.startswith("/api/"):  # Only log /api/ endpoints
        pass  # Log inside each route for more detail now


@app.after_request
def after_api_request(response):
    if request.path.startswith("/api/"):
        log_api_request(request.path, response.status_code)  # Log AFTER response
    return response


@app.route("/")
def index():
    return jsonify({"message": "Welcome to the API!"}), 200


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Authenticate the user and store their encrypted credentials.
    Checks the provided version number and ensures the user is authorized.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    # Check version number (from query parameters)
    version_number = request.args.get("version_number")
    if version_number != version_number2:
        return (
            jsonify(
                {"status": "error", "message": "Incorrect version number", "data": None}
            ),
            403,
        )
    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    store_user_credentials(username, password)
    return jsonify({"status": "success", "username": username}), 200


@app.route("/api/guc_data", methods=["GET"])
def api_guc_data():
    """
    Return the user's scraped GUC data (student info and notifications).
    Checks version number, whitelist, validates credentials, and stores credentials if not already present.
    """
    username = request.args.get("username")
    password = request.args.get("password")
    version_number = request.args.get("version_number")
    if version_number != version_number2:  # Version number check remains
        return (
            jsonify(
                {"status": "error", "message": "Incorrect version number", "data": None}
            ),
            403,
        )
    if not username or not password:  # Missing username/password check remains
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):  # Whitelist check remains
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )

    # Check if credentials are already stored
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )

    log_scraper_event(f"Starting guc_data scraping for user: {username}")
    data = scrape_guc_data(username, password)  # Proceed with scraping
    if data:
        log_scraper_event(f"Successfully scraped guc_data for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape guc_data for user: {username}")
        return jsonify({"error": "Failed to fetch GUC data"}), 500


@app.route("/api/schedule", methods=["GET"])
def api_schedule():
    """
    Return the user's schedule data.
    Checks version number, whitelist, validates credentials, and stores credentials if not already present.
    """
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:  # Missing username/password check remains
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):  # Whitelist check remains
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )

    # Check if credentials are already stored
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(f"Starting schedule scraping for user: {username}")
    data = scrape_schedule(
        username, password, BASE_SCHEDULE_URL, 3, 2
    )  # Proceed with scraping
    if data:
        log_scraper_event(f"Successfully scraped schedule for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape schedule for user: {username}")
        return jsonify({"error": "Failed to fetch schedule data"}), 500


@app.route("/api/cms_data", methods=["GET"])
def api_cms_data():
    """
    Return CMS courses data.
    Checks version number, whitelist, and validates the credentials.
    """
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(f"Starting CMS data scraping for user: {username}")
    data = cms_scraper(username, password)
    if data:
        log_scraper_event(f"Successfully scraped CMS data for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape CMS data for user: {username}")
        return jsonify([]), 200


@app.route("/api/cms_content", methods=["GET", "POST"])
def api_cms_content():
    """
    Return CMS course content data from a specific course URL.
    Expects a 'course_url' parameter.
    Checks version number, whitelist, and validates the credentials.
    """
    username = request.args.get("username")
    password = request.args.get("password")
    course_url = request.args.get("course_url")

    if not username or not password or not course_url:
        return jsonify({"status": "error", "message": "Missing parameters"}), 400
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(
        f"Starting CMS content scraping for user: {username}, URL: {course_url}"
    )
    data = cms_scraper(username, password, course_url)
    if data:
        log_scraper_event(
            f"Successfully scraped CMS content for user: {username}, URL: {course_url}"
        )
        return jsonify(data), 200
    else:
        log_scraper_event(
            f"Failed to scrape CMS content for user: {username}, URL: {course_url}"
        )
        return jsonify([]), 200


@app.route("/api/grades", methods=["GET"])
def api_grades():
    """
    Return the user's grades data.
    Checks version number, whitelist, and validates the credentials.
    """
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(f"Starting grades scraping for user: {username}")
    data = scrape_grades(username, password)
    if data:
        log_scraper_event(f"Successfully scraped grades for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape grades for user: {username}")
        return jsonify([]), 200


@app.route("/api/attendance", methods=["GET"])
def api_attendance():
    """
    Return the user's attendance data.
    Checks version number, whitelist, and validates the credentials.
    """
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(f"Starting attendance scraping for user: {username}")
    data = scrape_attendance(username, password, BASE_ATTENDANCE_URL, 3, 2)
    if data:
        log_scraper_event(f"Successfully scraped attendance for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape attendance for user: {username}")
        return jsonify({"error": "Failed to fetch attendance data"}), 500


@app.route("/api/exam_seats", methods=["GET"])
def api_exam_seats():
    """
    Return the user's exam seats data.
    Checks version number, whitelist, and validates the credentials.
    """
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )
    if not authenticate_user(username, password):
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )
    stored_users = get_all_stored_users()
    if username not in stored_users:  # Check if username exists in stored users
        if not authenticate_user(username, password):  # Authenticate only if not stored
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(
            username, password
        )  # Store credentials if not already stored
    else:  # If username is already stored, still authenticate (as per original code)
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    log_scraper_event(f"Starting exam seats scraping for user: {username}")
    data = scrape_exam_seats(username, password)
    if data:
        log_scraper_event(f"Successfully scraped exam seats for user: {username}")
        return jsonify(data), 200
    else:
        log_scraper_event(f"Failed to scrape exam seats for user: {username}")
        return jsonify([]), 200


@app.route("/api/refresh_cache", methods=["POST"])
def refresh_cache():
    """
    Refresh cache in three sections.
    When called (with the correct secret) and with a query parameter 'section':
      - Section "1": refreshes GUC data and Schedule data.
      - Section "2": refreshes CMS data and Grades.
      - Section "3": refreshes Attendance and Exam Seats.
    Optionally, if a 'username' parameter is provided, only that user’s data is refreshed.
    """
    secret = request.args.get("secret")
    section = request.args.get("section")
    if secret != config.CACHE_REFRESH_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    if section not in ["1", "2", "3"]:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Missing or invalid 'section' parameter. Use '1', '2', or '3'.",
                }
            ),
            400,
        )

    # Optional: refresh only a specific user's data if 'username' is provided.
    target_username = request.args.get("username")
    stored_users = get_all_stored_users()
    if target_username:
        if target_username in stored_users:
            stored_users = {target_username: stored_users[target_username]}
        else:
            return jsonify({"status": "error", "message": "Username not found"}), 404

    results = {}
    for username, cred in stored_users.items():
        try:
            # Decrypt the stored credential (cred is a string)
            password = fernet.decrypt(cred.encode()).decode()
            user_results = {}
            if section == "1":
                user_results["guc_data"] = (
                    "updated" if scrape_guc_data(username, password) else "failed"
                )
                user_results["schedule"] = (
                    "updated"
                    if scrape_schedule(username, password, BASE_SCHEDULE_URL, 3, 2)
                    else "failed"
                )
            elif section == "2":
                user_results["cms_data"] = (
                    "updated" if cms_scraper(username, password) else "failed"
                )
                user_results["grades"] = (
                    "updated" if scrape_grades(username, password) else "failed"
                )
            elif section == "3":
                user_results["attendance"] = (
                    "updated"
                    if scrape_attendance(username, password, BASE_ATTENDANCE_URL, 3, 2)
                    else "failed"
                )
                user_results["exam_seats"] = (
                    "updated" if scrape_exam_seats(username, password) else "failed"
                )
            results[username] = user_results
        except Exception as e:
            results[username] = f"error: {str(e)}"
    return jsonify({"status": "done", "results": results}), 200


@app.route("/admin/config", methods=["GET"])
def admin_config():
    """
    Return the current persistent configuration.
    This endpoint returns a JSON object with:
      - version_number: The API version.
      - whitelist: A list of whitelisted users.
      - stored_users: A list of usernames for which credentials are stored.
    """
    config_data = {
        "version_number": version_number2,
        "whitelist": whitelist,
        "stored_users": list(get_all_stored_users().keys()),
        "stored_user_count": len(get_all_stored_users()),  # Added user count
    }
    return jsonify(config_data), 200


@app.route("/admin/view_full_config", methods=["GET"])
def admin_view_full_config():
    """
    Return all configuration settings, including those from .env and defaults.
    """
    full_config_data = {
        "version_number": version_number2,
        "whitelist": whitelist,
        "stored_users": list(get_all_stored_users().keys()),
        "stored_user_count": len(get_all_stored_users()),  # Added user count here too
        "base_schedule_url": BASE_SCHEDULE_URL,
        "base_attendance_url": BASE_ATTENDANCE_URL,
        # Include sensitive config? Be careful, maybe exclude ENCRYPTION_KEY and CACHE_REFRESH_SECRET
        # "encryption_key_present": config.ENCRYPTION_KEY is not None,
        # "cache_refresh_secret_present": config.CACHE_REFRESH_SECRET is not None,
        "redis_connected": redis_client.ping(),  # Basic Redis connection check
    }
    return jsonify(full_config_data), 200


@app.route("/admin/update_config", methods=["POST"])
def admin_update_config():
    """
    Update a configuration value persistently in Redis.
    Expects form fields 'config_key' and 'config_value'.
    """
    config_key = request.form.get("config_key")
    config_value = request.form.get("config_value")
    if not config_key or config_value is None:
        return "Both config_key and config_value are required.", 400
    config_key = config_key.upper()
    set_config(config_key, config_value)
    global whitelist, version_number2, BASE_SCHEDULE_URL, BASE_ATTENDANCE_URL
    if config_key == "WHITELIST":
        whitelist = config_value.split(",")
    elif config_key == "VERSION_NUMBER":
        version_number2 = config_value
    elif config_key == "BASE_SCHEDULE_URL_CONFIG":
        BASE_SCHEDULE_URL = config_value  # Update global variable immediately
        set_config(
            "BASE_SCHEDULE_URL_CONFIG", config_value
        )  # Double set config just in case
    elif config_key == "BASE_ATTENDANCE_URL_CONFIG":
        BASE_ATTENDANCE_URL = config_value  # Update global variable immediately
        set_config(
            "BASE_ATTENDANCE_URL_CONFIG", config_value
        )  # Double set config just in case
    return f"Configuration {config_key} updated to {config_value}.", 200


@app.route("/admin/add_whitelist", methods=["POST"])
def admin_add_whitelist():
    username = request.form.get("username")
    if not username:
        return "Username is required", 400
    if username in whitelist:
        return f"User {username} is already whitelisted.", 400
    whitelist.append(username)
    # Update persistent config
    set_config("WHITELIST", ",".join(whitelist))
    return f"User {username} added to whitelist.", 200


@app.route("/admin/remove_whitelist", methods=["POST"])
def admin_remove_whitelist():
    username = request.form.get("username")
    if not username:
        return "Username is required", 400
    if username not in whitelist:
        return f"User {username} is not in the whitelist.", 400
    whitelist.remove(username)
    # Update persistent config
    set_config("WHITELIST", ",".join(whitelist))
    return f"User {username} removed from whitelist.", 200


@app.route("/admin/refresh_user", methods=["POST"])
def admin_refresh_user():
    """
    Refresh cache for a specific user.
    Expects 'username' and 'section' in the form data.
    Sections:
      "1": Refresh GUC data and Schedule data.
      "2": Refresh CMS data and Grades.
      "3": Refresh Attendance and Exam Seats.
    """
    username = request.form.get("username")
    section = request.form.get("section")
    action = request.form.get(
        "action", "refresh"
    )  # Default action is refresh, can be 'clear'
    if not username or section not in ["1", "2", "3"]:
        return "Username and valid section are required.", 400
    if action not in ["refresh", "clear"]:
        return "Invalid action. Use 'refresh' or 'clear'.", 400

    stored_users = get_all_stored_users()
    if username not in stored_users:
        return f"User {username} not found in stored credentials.", 404
    try:
        password = fernet.decrypt(stored_users[username].encode()).decode()
        user_results = {}
        if section == "1":
            if action == "refresh":
                user_results["guc_data"] = (
                    "updated" if scrape_guc_data(username, password) else "failed"
                )
                user_results["schedule"] = (
                    "updated"
                    if scrape_schedule(username, password, BASE_SCHEDULE_URL, 3, 2)
                    else "failed"
                )
            elif action == "clear":
                # Implement cache clearing if you are using a caching mechanism.
                # For now, just indicate it's a 'clear' action. In a real cache system, you would remove keys.
                user_results["guc_data"] = "cache cleared"
                user_results["schedule"] = "cache cleared"
        elif section == "2":
            if action == "refresh":
                user_results["cms_data"] = (
                    "updated" if cms_scraper(username, password) else "failed"
                )
                user_results["grades"] = (
                    "updated" if scrape_grades(username, password) else "failed"
                )
            elif action == "clear":
                user_results["cms_data"] = "cache cleared"
                user_results["grades"] = "cache cleared"
        elif section == "3":
            if action == "refresh":
                user_results["attendance"] = (
                    "updated"
                    if scrape_attendance(username, password, BASE_ATTENDANCE_URL, 3, 2)
                    else "failed"
                )
                user_results["exam_seats"] = (
                    "updated" if scrape_exam_seats(username, password) else "failed"
                )
            elif action == "clear":
                user_results["attendance"] = "cache cleared"
                user_results["exam_seats"] = "cache cleared"
        return jsonify({"status": "done", "results": {username: user_results}}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/admin/refresh_all", methods=["POST"])
def admin_refresh_all():
    """
    Refresh cache for all users.
    Expects 'section' in the form data.
    Sections:
      "1": Refresh GUC data and Schedule data.
      "2": Refresh CMS data and Grades.
      "3": Refresh Attendance and Exam Seats.
    """
    section = request.form.get("section")
    action = request.form.get(
        "action", "refresh"
    )  # Default action is refresh, can be 'clear'
    if section not in ["1", "2", "3"]:
        return "Valid section is required.", 400
    if action not in ["refresh", "clear"]:
        return "Invalid action. Use 'refresh' or 'clear'.", 400

    stored_users = get_all_stored_users()
    results = {}
    for username, cred in stored_users.items():
        try:
            password = fernet.decrypt(cred.encode()).decode()
            user_results = {}
            if section == "1":
                if action == "refresh":
                    user_results["guc_data"] = (
                        "updated" if scrape_guc_data(username, password) else "failed"
                    )
                    user_results["schedule"] = (
                        "updated"
                        if scrape_schedule(username, password, BASE_SCHEDULE_URL, 3, 2)
                        else "failed"
                    )
                elif action == "clear":
                    user_results["guc_data"] = "cache cleared"
                    user_results["schedule"] = "cache cleared"
            elif section == "2":
                if action == "refresh":
                    user_results["cms_data"] = (
                        "updated" if cms_scraper(username, password) else "failed"
                    )
                    user_results["grades"] = (
                        "updated" if scrape_grades(username, password) else "failed"
                    )
                elif action == "clear":
                    user_results["cms_data"] = "cache cleared"
                    user_results["grades"] = "cache cleared"
            elif section == "3":
                if action == "refresh":
                    user_results["attendance"] = (
                        "updated"
                        if scrape_attendance(
                            username, password, BASE_ATTENDANCE_URL, 3, 2
                        )
                        else "failed"
                    )
                    user_results["exam_seats"] = (
                        "updated" if scrape_exam_seats(username, password) else "failed"
                    )
                elif action == "clear":
                    user_results["attendance"] = "cache cleared"
                    user_results["exam_seats"] = "cache cleared"
            results[username] = user_results
        except Exception as e:
            results[username] = f"error: {str(e)}"
    return jsonify({"status": "done", "results": results}), 200


@app.route("/admin/redis_info", methods=["GET"])
def admin_redis_info():
    """Return Redis INFO command output."""
    try:
        redis_info = redis_client.info()
        return jsonify(redis_info), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve Redis info: {str(e)}"}), 500


@app.route("/admin/view_logs", methods=["GET"])
def admin_view_logs():
    """Return recent scraper logs."""
    return jsonify({"logs": scraper_logs}), 200


@app.route("/admin/view_api_logs", methods=["GET"])
def admin_view_api_logs():
    """Return recent API request logs."""
    return jsonify({"api_logs": api_logs}), 200


@app.route("/admin/list_credentials", methods=["GET"])
def admin_list_credentials():
    """List usernames with stored credentials (encrypted)."""
    stored_users = get_all_stored_users()
    return jsonify({"usernames_with_credentials": list(stored_users.keys())}), 200


@app.route("/admin/delete_credential", methods=["POST"])
def admin_delete_credential():
    """Delete stored credential for a given username."""
    username = request.form.get("username")
    if not username:
        return "Username is required.", 400
    stored_users = get_all_stored_users()
    if username not in stored_users:
        return f"No credentials stored for user: {username}", 404
    redis_client.hdel("user_credentials", username)
    return (
        jsonify(
            {"status": "done", "message": f"Credentials deleted for user: {username}"}
        ),
        200,
    )


@app.route("/admin/view_cache_keys", methods=["GET"])
def admin_view_cache_keys():
    """
    List cache keys (if you are using a predictable caching key scheme).
    Example:  /admin/view_cache_keys?username=testuser§ion=schedule
    (This assumes you've implemented caching and key structure.)
    """
    # This is a placeholder - you'd need to customize this based on *your* caching implementation and key structure.
    username = request.args.get("username")
    section = request.args.get("section")
    key_pattern = (
        "*"  # Default - list all keys (be VERY careful in production with this!)
    )
    if username:
        key_pattern = f"*{username}*"  # Example pattern - adjust to your keys
        if section:
            key_pattern = f"*{username}:{section}*"  # More specific

    try:
        keys = redis_client.keys(
            key_pattern
        )  # BE CAREFUL WITH 'keys *' in production.  It can be slow on large datasets.  For debugging only.
        decoded_keys = [key.decode() for key in keys]  # Decode byte keys to strings
        return jsonify({"cache_keys": decoded_keys}), 200
    except Exception as e:
        return jsonify({"error": f"Error listing cache keys: {str(e)}"}), 500


@app.route("/admin/delete_cache_key", methods=["POST"])
def admin_delete_cache_key():
    """Delete a specific cache key manually."""
    key_to_delete = request.form.get("key")
    if not key_to_delete:
        return "Cache key to delete is required.", 400
    try:
        deleted_count = redis_client.delete(key_to_delete)
        if deleted_count > 0:
            return (
                jsonify(
                    {"status": "done", "message": f"Deleted cache key: {key_to_delete}"}
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "status": "warning",
                        "message": f"Cache key not found or already deleted: {key_to_delete}",
                    }
                ),
                404,
            )
    except Exception as e:
        return jsonify({"error": f"Error deleting cache key: {str(e)}"}), 500


@app.route("/admin/shutdown", methods=["POST"])
def admin_shutdown():
    import os

    os._exit(0)
    return "Server is shutting down", 200


@app.route("/admin/restart", methods=["POST"])
def admin_restart():
    import os
    import sys

    print("Restarting Flask application...")
    os.execv(
        sys.executable, ["python"] + sys.argv
    )  # Restart the script with the same args
    return "Restarting...", 200


# For local testing only. Vercel will import the app as a WSGI application.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
