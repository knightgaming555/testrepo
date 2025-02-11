# app.py
import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet

import redis
import json

from api.scraping import (
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


config = Config()
app = Flask(__name__, template_folder="../templates")
CORS(app)

redis_client = redis.from_url(os.environ.get("REDIS_URL"))


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


# Global variables for whitelist and version
# Instead of hardcoding, load from Redis with environment variables as defaults.
whitelist = get_config(
    "WHITELIST",
    os.environ.get("WHITELIST", "mohamed.elsaadi,seif.elkady,malak.mohamedelkady"),
).split(",")
version_number2 = get_config("VERSION_NUMBER", os.environ.get("VERSION_NUMBER", "1.2"))


# In-memory dictionary for storing user credentials for testing.


# Initialize Fernet using the provided encryption key.
fernet = Fernet(config.ENCRYPTION_KEY)

# Base URLs for schedule and attendance scrapers
BASE_SCHEDULE_URL = "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx"
BASE_ATTENDANCE_URL = "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx"


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

    data = scrape_guc_data(username, password)  # Proceed with scraping
    if data:
        return jsonify(data), 200
    else:
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

    data = scrape_schedule(
        username, password, BASE_SCHEDULE_URL, 3, 2
    )  # Proceed with scraping
    if data:
        return jsonify(data), 200
    else:
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

    data = cms_scraper(username, password)
    if data:
        return jsonify(data), 200
    else:
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

    data = cms_scraper(username, password, course_url)
    if data:
        return jsonify(data), 200
    else:
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

    data = scrape_grades(username, password)
    if data:
        return jsonify(data), 200
    else:
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

    data = scrape_attendance(username, password, BASE_ATTENDANCE_URL, 3, 2)
    if data:
        return jsonify(data), 200
    else:
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

    data = scrape_exam_seats(username, password)
    if data:
        return jsonify(data), 200
    else:
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
    }
    return jsonify(config_data), 200


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
    global whitelist, version_number2
    if config_key == "WHITELIST":
        whitelist = config_value.split(",")
    elif config_key == "VERSION_NUMBER":
        version_number2 = config_value
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
    if not username or section not in ["1", "2", "3"]:
        return "Username and valid section are required.", 400
    stored_users = get_all_stored_users()
    if username not in stored_users:
        return f"User {username} not found in stored credentials.", 404
    try:
        password = fernet.decrypt(stored_users[username].encode()).decode()
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
    if section not in ["1", "2", "3"]:
        return "Valid section is required.", 400
    stored_users = get_all_stored_users()
    results = {}
    for username, cred in stored_users.items():
        try:
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


@app.route("/admin/shutdown", methods=["POST"])
def admin_shutdown():
    import os

    os._exit(0)
    return "Server is shutting down", 200


# For local testing only. Vercel will import the app as a WSGI application.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
