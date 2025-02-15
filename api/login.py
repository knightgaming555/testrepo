import os
from flask import Flask, request, jsonify
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime
from api.scraping import authenticate_user  # Your actual auth function

# Load env vars
load_dotenv()


# --- Configuration ---
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

# --- Redis and Encryption ---
redis_client = redis.from_url(os.environ.get("REDIS_URL"))
fernet = Fernet(config.ENCRYPTION_KEY)


def log_event(message):
    print(f"{datetime.now().isoformat()} - {message}")


# --- Flask App ---
app = Flask(__name__)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    def store_user_credentials(username, password):
        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)

    def is_user_authorized(username):
        whitelist_raw = redis_client.get("WHITELIST")
        if whitelist_raw:
            whitelist = [u.strip() for u in whitelist_raw.decode().split(",")]
            return username in whitelist
        return False

    version_number_raw = redis_client.get("VERSION_NUMBER")
    version_number2 = version_number_raw.decode() if version_number_raw else "1.0"
    req_version = request.args.get("version_number")
    if req_version != version_number2:
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
    log_event(f"User {username} logged in successfully.")
    return jsonify({"status": "success", "username": username}), 200


if __name__ == "__main__":
    app.run(debug=True)
