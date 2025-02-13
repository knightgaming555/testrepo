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
    cms_scraper,
)  # Replace with your actual function

load_dotenv()


# --- Configuration and Setup ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


config = Config()
redis_client = redis.from_url(os.environ.get("REDIS_URL"))
fernet = Fernet(config.ENCRYPTION_KEY)


def get_all_stored_users():
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def store_user_credentials(username, password):
    encrypted = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted)


def log_event(message):
    print(f"{datetime.now().isoformat()} - {message}")


def authenticate_user(username, password):
    return True


def is_user_authorized(username):
    whitelist_raw = redis_client.get("WHITELIST")
    if whitelist_raw:
        whitelist = [u.strip() for u in whitelist_raw.decode().split(",")]
        return username in whitelist
    return False


version_number_raw = redis_client.get("VERSION_NUMBER")
version_number2 = version_number_raw.decode() if version_number_raw else "1.0"

app = Flask(__name__)


@app.route("/api/cms_content", methods=["GET", "POST"])
def api_cms_content():
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
    if username in get_all_stored_users():
        try:
            stored_pw = (
                fernet.decrypt(get_all_stored_users()[username].encode())
                .decode()
                .strip()
            )
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

    log_event(f"Starting CMS content scraping for user: {username}, URL: {course_url}")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cms_scraper, username, password, course_url)
        try:
            data = future.result(timeout=10)
        except TimeoutError:
            log_event(f"Timeout during CMS content scraping for user: {username}")
            return jsonify({"error": "Scraping timed out"}), 504
        except Exception as e:
            log_event(
                f"Error during CMS content scraping for user: {username} - {str(e)}"
            )
            return jsonify({"error": "Failed to fetch CMS content"}), 500

    if data:
        log_event(
            f"Successfully scraped CMS content for user: {username}, URL: {course_url}"
        )
        return jsonify(data), 200
    else:
        log_event(
            f"Failed to scrape CMS content for user: {username}, URL: {course_url}"
        )
        return jsonify([]), 200


if __name__ == "__main__":
    app.run(debug=True)
