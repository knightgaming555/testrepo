import os
from datetime import datetime
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


# --- Begin common configuration and helper code ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )


config = Config()

# Set up Redis client
redis_client = redis.from_url(os.environ.get("REDIS_URL"))

# Set up Fernet encryption/decryption
fernet = Fernet(config.ENCRYPTION_KEY)


def get_config_value(key, default_value):
    value = redis_client.get(key)
    if value is not None:
        return value.decode()
    else:
        redis_client.set(key, default_value)
        return default_value


def get_all_stored_users():
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def store_user_credentials(username, password):
    encrypted_password = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted_password)


# In-memory logs (not used in this endpoint but available if needed)
scraper_logs = []
api_logs = []
LOG_HISTORY_LENGTH = 100


def log_scraper_event(message):
    log_message = f"{datetime.now().isoformat()} - {message}"
    scraper_logs.insert(0, log_message)
    if len(scraper_logs) > LOG_HISTORY_LENGTH:
        scraper_logs.pop()


# --- End common configuration and helper code ---

# Get configuration values for URLs
BASE_SCHEDULE_URL = get_config_value(
    "BASE_SCHEDULE_URL_CONFIG", config.BASE_SCHEDULE_URL_CONFIG
)
BASE_ATTENDANCE_URL = get_config_value(
    "BASE_ATTENDANCE_URL_CONFIG", config.BASE_ATTENDANCE_URL_CONFIG
)

# Import scraping functions from your existing module (adjust the import path as needed)
from api.scraping import (
    scrape_guc_data,
    scrape_schedule,
    cms_scraper,
    scrape_grades,
    scrape_attendance,
    scrape_exam_seats,
)

# Create the Flask app
app = Flask(__name__)


@app.route("/api/refresh_cache", methods=["POST"])
def refresh_cache():
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

    # Optionally refresh only a specific user's data if 'username' is provided.
    target_username = request.args.get("username")
    stored_users = get_all_stored_users()
    if target_username:
        if target_username in stored_users:
            stored_users = {target_username: stored_users[target_username]}
        else:
            return jsonify({"status": "error", "message": "Username not found"}), 404

    results = {}
    tasks = []
    with ThreadPoolExecutor() as executor:
        for username, cred in stored_users.items():
            try:
                password = fernet.decrypt(cred.encode()).decode()
            except Exception as e:
                results[username] = f"error: {str(e)}"
                continue

            if section == "1":
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "guc_data",
                            u,
                            "updated" if scrape_guc_data(u, p) else "failed",
                        )
                    )
                )
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "schedule",
                            u,
                            (
                                "updated"
                                if scrape_schedule(u, p, BASE_SCHEDULE_URL, 3, 2)
                                else "failed"
                            ),
                        )
                    )
                )
            elif section == "2":
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "cms_data",
                            u,
                            "updated" if cms_scraper(u, p) else "failed",
                        )
                    )
                )
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "grades",
                            u,
                            "updated" if scrape_grades(u, p) else "failed",
                        )
                    )
                )
            elif section == "3":
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "attendance",
                            u,
                            (
                                "updated"
                                if scrape_attendance(u, p, BASE_ATTENDANCE_URL, 3, 2)
                                else "failed"
                            ),
                        )
                    )
                )
                tasks.append(
                    executor.submit(
                        lambda u=username, p=password: (
                            "exam_seats",
                            u,
                            "updated" if scrape_exam_seats(u, p) else "failed",
                        )
                    )
                )

        for future in as_completed(tasks):
            key, user, res = future.result()
            if user not in results:
                results[user] = {}
            results[user][key] = res

    return jsonify({"status": "done", "results": results}), 200


if __name__ == "__main__":
    app.run(debug=True)
