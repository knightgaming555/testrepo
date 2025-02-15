import os
import time
from datetime import datetime
from flask import Flask, request, jsonify
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from api.scraping import (
    authenticate_user,
    scrape_attendance,
)  # Replace with your actual function

load_dotenv()


# --- Configuration and Setup ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )


config = Config()
redis_client = redis.from_url(os.environ.get("REDIS_URL"))
fernet = Fernet(config.ENCRYPTION_KEY)


def log_event(message):
    print(f"{datetime.now().isoformat()} - {message}")


BASE_ATTENDANCE_URL = os.environ.get(
    "BASE_ATTENDANCE_URL", config.BASE_ATTENDANCE_URL_CONFIG
)

app = Flask(__name__)


@app.route("/api/attendance", methods=["GET"])
def api_attendance():

    def is_user_authorized(username):
        whitelist_raw = redis_client.get("WHITELIST")
        if whitelist_raw:
            whitelist = [u.strip() for u in whitelist_raw.decode().split(",")]
            return username in whitelist
        return False

    def get_all_stored_users():
        stored = redis_client.hgetall("user_credentials")
        return {k.decode(): v.decode() for k, v in stored.items()}

    def store_user_credentials(username, password):
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)

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

    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
        except Exception:
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": "Error decrypting credentials",
                        "data": None,
                    }
                ),
                500,
            )
        if stored_pw != password.strip():
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    else:
        if not authenticate_user(username, password):
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
        store_user_credentials(username, password)

    log_event(f"Starting attendance scraping for user: {username}")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            scrape_attendance, username, password, BASE_ATTENDANCE_URL, 3, 2
        )
        try:
            data = future.result(timeout=10)
        except TimeoutError:
            log_event(f"Timeout during attendance scraping for user: {username}")
            return jsonify({"error": "Scraping timed out"}), 504
        except Exception as e:
            log_event(
                f"Error during attendance scraping for user: {username} - {str(e)}"
            )
            return jsonify({"error": "Failed to fetch attendance data"}), 500

    if data:
        log_event(f"Successfully scraped attendance for user: {username}")
        return jsonify(data), 200
    else:
        log_event(f"Failed to scrape attendance for user: {username}")
        return jsonify({"error": "Failed to fetch attendance data"}), 500


if __name__ == "__main__":
    app.run(debug=True)
