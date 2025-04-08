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
    scrape_notifications,
)

load_dotenv()


# --- Configuration and Setup ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")


config = Config()
redis_client = redis.from_url(os.environ.get("REDIS_URL"))
fernet = Fernet(config.ENCRYPTION_KEY)


def log_event(message):
    print(f"{datetime.now().isoformat()} - {message}")


app = Flask(__name__)


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


def validate_credentials(username, password):
    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        return (
            jsonify({"status": "error", "message": "User not authorized"}),
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

    return None


@app.route("/api/cms_data", methods=["GET"])
def api_cms_data():
    username = request.args.get("username")
    password = request.args.get("password")

    validation_result = validate_credentials(username, password)
    if validation_result:
        return validation_result

    log_event(f"Starting CMS data scraping for user: {username}")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(cms_scraper, username, password)
        try:
            data = future.result(timeout=10)
        except TimeoutError:
            log_event(f"Timeout during CMS data scraping for user: {username}")
            return jsonify({"error": "Scraping timed out"}), 504
        except Exception as e:
            log_event(f"Error during CMS data scraping for user: {username} - {str(e)}")
            return jsonify({"error": "Failed to fetch CMS data"}), 500

    if data:
        log_event(f"Successfully scraped CMS data for user: {username}")
        return jsonify(data), 200
    else:
        log_event(f"Failed to scrape CMS data for user: {username}")
        return jsonify([]), 200


@app.route("/api/cms_notifications", methods=["GET"])
def api_cms_notifications():
    username = request.args.get("username")
    password = request.args.get("password")

    validation_result = validate_credentials(username, password)
    if validation_result:
        return validation_result

    log_event(f"Starting CMS notifications scraping for user: {username}")
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(scrape_notifications, username, password)
        try:
            data = future.result(timeout=10)
        except TimeoutError:
            log_event(f"Timeout during CMS notifications scraping for user: {username}")
            return jsonify({"error": "Scraping timed out"}), 504
        except Exception as e:
            log_event(
                f"Error during CMS notifications scraping for user: {username} - {str(e)}"
            )
            return jsonify({"error": "Failed to fetch CMS notifications"}), 500

    if data:
        log_event(f"Successfully scraped CMS notifications for user: {username}")
        return jsonify(data), 200
    else:
        log_event(f"Failed to scrape CMS notifications for user: {username}")
        return jsonify([]), 200


if __name__ == "__main__":
    app.run(debug=True)
