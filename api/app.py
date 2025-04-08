# app.py (Version 2 - Enhanced Admin Control)
import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import sys
import redis
import json
import logging  # Import logging module
from datetime import datetime
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from api.scraping import (
    authenticate_user,
    scrape_guc_data,
    scrape_schedule,
    cms_scraper,
    scrape_grades,
    scrape_attendance,
    scrape_exam_seats,
)

from api.guc_data import (
    get_dev_announcement, 
    set_dev_announcement, 

    config
)


# Load environment variables from .env file
load_dotenv()


class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    BASE_SCHEDULE_URL = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )  # Configurable schedule URL
    BASE_ATTENDANCE_URL = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )  # Configurable attendance URL


config = Config()
app = Flask(__name__, template_folder="../templates")
CORS(app)
API_LOG_KEY = "api_logs"
MAX_LOG_ENTRIES = 1000
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


def get_whitelist():
    whitelist_raw = redis_client.get("WHITELIST")
    if whitelist_raw:
        return [user.strip() for user in whitelist_raw.decode().split(",")]
    else:
        return []


def get_version_number():
    version_raw = redis_client.get("VERSION_NUMBER")
    return version_raw.decode() if version_raw else None


def get_base_schedule_url():
    return get_config("BASE_SCHEDULE_URL_CONFIG", config.BASE_SCHEDULE_URL)


def get_base_attendance_url():
    return get_config("BASE_ATTENDANCE_URL_CONFIG", config.BASE_ATTENDANCE_URL)


# Initialize Fernet using the provided encryption key.
fernet = Fernet(config.ENCRYPTION_KEY)


def is_user_authorized(username):
    return username in get_whitelist()


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

def get_all_user_activity():
    """Retrieve activity data for all users."""
    all_activity = {}
    user_keys = redis_client.keys("user_activity:*")
    
    for key in user_keys:
        username = key.decode().split(":", 1)[1]
        activity_data = redis_client.hgetall(key)
        if activity_data:
            all_activity[username] = {k.decode(): v.decode() for k, v in activity_data.items()}
    
    return all_activity


@app.route("/")
def index():
    return jsonify({"message": "Welcome to the API!"}), 200

@app.route("/api/user-activity", methods=["GET"])
def api_user_activity():
    """API endpoint to retrieve user activity data.
    
    Query parameters:
    - username: Optional. If provided, returns activity for specific user.
                If not provided, returns activity for all users.
    - secret: Required for security. Must match ADMIN_SECRET env variable.
    """
    # Check admin secret for authorization
    
    # Get username from query parameters (optional)
    username = request.args.get("username")
    
    if username:
        # Get activity for specific user
        activity_data = get_user_activity(username)
        if not activity_data:
            return jsonify({"error": f"No activity data found for user: {username}"}), 404
        return jsonify({username: activity_data}), 200
    else:
        # Get activity for all users
        all_activity = get_all_user_activity()
        return jsonify(all_activity), 200


# Add this import at the top of the file if not already present

# Add this endpoint to your app.py file
@app.route("/admin/announcement", methods=["GET", "POST"])
def admin_announcement():
    # Check for admin secret key
    secret = request.headers.get("Admin-Secret")
    if not secret or secret != config.CACHE_REFRESH_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    if request.method == "GET":
        try:
            return jsonify({
                "status": "success",
                "announcement": get_dev_announcement(),
                # Removed "users" field
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    
    elif request.method == "POST":
        try:
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "Missing data"}), 400
            
            # Update announcement if provided
            if "announcement" in data:
                set_dev_announcement(data["announcement"])
            
            # Update users if provided
        
            return jsonify({
                "status": "success", 
                "message": "Announcement updated",
                "current_announcement": get_dev_announcement(),
                # Removed "current_users" field
            }), 200
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

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
        "version_number": get_version_number(),
        "whitelist": get_whitelist(),
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
        "version_number": get_version_number(),
        "whitelist": get_whitelist(),
        "stored_users": list(get_all_stored_users().keys()),
        "stored_user_count": len(get_all_stored_users()),
        "base_schedule_url": get_base_schedule_url(),
        "base_attendance_url": get_base_attendance_url(),
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
    return f"Configuration {config_key} updated to {config_value}.", 200


@app.route("/admin/add_whitelist", methods=["POST"])
def admin_add_whitelist():
    username = request.form.get("username")
    if not username:
        return "Username is required", 400
    current_whitelist = get_whitelist()
    if username in current_whitelist:
        return f"User {username} is already whitelisted.", 400
    new_whitelist = current_whitelist + [username]
    set_config("WHITELIST", ",".join(new_whitelist))
    return f"User {username} added to whitelist.", 200


@app.route("/admin/remove_whitelist", methods=["POST"])
def admin_remove_whitelist():
    username = request.form.get("username")
    if not username:
        return "Username is required", 400
    current_whitelist = get_whitelist()
    if username not in current_whitelist:
        return f"User {username} is not in the whitelist.", 400
    new_whitelist = [user for user in current_whitelist if user != username]
    set_config("WHITELIST", ",".join(new_whitelist))
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
                    if scrape_schedule(
                        username, password, get_base_schedule_url(), 3, 2
                    )
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
                        username, password, get_base_attendance_url(), 3, 2
                    )
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
                        if scrape_schedule(
                            username, password, get_base_schedule_url(), 3, 2
                        )
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
                            username, password, get_base_attendance_url(), 3, 2
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


@app.route("/debug/whitelist", methods=["GET"])
def debug_whitelist():
    whitelist = get_whitelist()
    return jsonify({"whitelist": whitelist})


@app.route("/debug/redis_whitelist", methods=["GET"])
def debug_redis_whitelist():
    whitelist_raw = redis_client.get("WHITELIST")
    return jsonify(
        {"redis_whitelist": whitelist_raw.decode() if whitelist_raw else None}
    )


@app.route("/admin/country_stats", methods=["GET"])
def admin_country_stats():
    """
    Return the number of users per country.
    Uses the Redis hash "user_countries" where each key is a username and
    the value is the user's country.
    """
    user_countries = redis_client.hgetall("user_countries")
    stats = {}
    for username, country in user_countries.items():
        # Decode the value if needed
        country = country.decode() if isinstance(country, bytes) else country
        stats[country] = stats.get(country, 0) + 1
    return jsonify(stats), 200


@app.route("/debug/version", methods=["GET"])
def debug_version():
    version_number_raw = redis_client.get("VERSION_NUMBER")
    version_number = version_number_raw.decode() if version_number_raw else None
    return jsonify({"version_number": version_number})


@app.route("/api/logs", methods=["GET"])
def api_logs_new():
    """Retrieves the last N API logs from Redis."""
    try:
        log_entries_json = redis_client.lrange(API_LOG_KEY, 0, MAX_LOG_ENTRIES - 1)
        logs = []
        for entry_json in log_entries_json:
            try:
                logs.append(json.loads(entry_json))
            except json.JSONDecodeError as e:
                print(f"Error decoding log entry from Redis: {e}. Entry: {entry_json}")
                logs.append({"error": "Failed to parse log entry", "raw_entry": entry_json[:100]}) 

        return jsonify(logs), 200
    except redis.exceptions.ConnectionError as e:
        print(f"Error retrieving logs from Redis (connection): {e}")
        return jsonify({"error": "Failed to connect to log storage"}), 503
    except Exception as e:
        print(f"Error retrieving logs from Redis: {e}")
        return jsonify({"error": "Failed to retrieve logs from storage"}), 500


# For local testing only. Vercel will import the app as a WSGI application.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
