import re
import json
import asyncio
import httpx
from httpx_ntlm import HttpNtlmAuth  # NTLM auth for httpx
from time import perf_counter
from bs4 import BeautifulSoup
import warnings
from urllib3.exceptions import InsecureRequestWarning
from flask import Flask, request, jsonify
from datetime import datetime
import redis
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import traceback
from concurrent.futures import ThreadPoolExecutor

# Load environment variables
load_dotenv()

# Initialize Redis and encryption key
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
fernet = Fernet(ENCRYPTION_KEY)


# --- Configuration ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )
    GUC_DATA_URLS = [
        "https://apps.guc.edu.eg/student_ext/index.aspx",
        "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx",
    ]


config = Config()

# Suppress InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

# --- Cache Utilities ---
DATA_CACHE_EXPIRY = 600  # seconds (10 minutes)


def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached.decode())
    except Exception as e:
        print(f"[Cache] Get error for key '{key}': {e}")
    return None


def set_to_app_cache(key, value, timeout=DATA_CACHE_EXPIRY):
    try:
        redis_client.setex(
            key, timeout, json.dumps(value, ensure_ascii=False).encode("utf-8")
        )
    except Exception as e:
        print(f"[Cache] Set error for key '{key}': {e}")


# --- HTML Parsing Functions ---
def parse_student_info(html):
    soup = BeautifulSoup(html, "lxml")
    info = {}
    prefix = "ContentPlaceHolderright_ContentPlaceHoldercontent_Label"
    mapping = {
        "FullName": "fullname",
        "UniqAppNo": "uniqappno",
        "UserCode": "usercode",
        "Mail": "mail",
        "sg": "sg",
    }
    for label, key in mapping.items():
        element = soup.find(id=f"{prefix}{label}")
        info[key] = (
            element.get_text(" ", strip=True).replace("\r", "") if element else ""
        )
    return info


def parse_notifications(html):
    soup = BeautifulSoup(html, "lxml")
    notifications = []
    table = soup.find(
        id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
    )
    if table:
        rows = table.find_all("tr")[1:]  # Skip header row
        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 6:
                continue
            notif = {
                "id": cells[0].get_text(" ", strip=True).replace("\r", ""),
                "title": cells[2].get_text(" ", strip=True).replace("\r", ""),
                "date": cells[3].get_text(" ", strip=True).replace("\r", ""),
                "staff": cells[4].get_text(" ", strip=True).replace("\r", ""),
                "importance": cells[5].get_text(" ", strip=True).replace("\r", ""),
            }
            button = cells[1].find("button")
            if button:
                email_time_str = button.get("data-email_time", "")
                try:
                    email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                    notif["email_time"] = email_time.isoformat()
                except Exception as e:
                    print(
                        f"Error parsing email_time '{email_time_str}': {e}. Using current time."
                    )
                    notif["email_time"] = datetime.now().isoformat()
                notif["subject"] = (
                    button.get("data-subject_text", "")
                    .replace("Notification System:", "")
                    .strip()
                    .replace("\r", "")
                )
                notif["body"] = (
                    button.get("data-body_text", "")
                    .replace("------------------------------", "")
                    .strip()
                    .replace("\r", "")
                )
            else:
                notif["email_time"] = datetime.now().isoformat()
                notif["subject"] = ""
                notif["body"] = ""
            notifications.append(notif)
    else:
        print("Notifications table not found in the HTML.")
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


# --- Asynchronous Scraping with httpx and NTLM ---
async def async_scrape_guc_data_fast(username, password, urls):
    domain = "GUC"
    # Setup NTLM auth using httpx_ntlm.
    auth = HttpNtlmAuth(f"{domain}\\{username}", password)
    async with httpx.AsyncClient(auth=auth, timeout=10.0) as client:
        tasks = [client.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
        htmls = {url: response.text for url, response in zip(urls, responses)}
    student_html = htmls[urls[0]]
    notif_html = htmls[urls[1]]
    student_info = parse_student_info(student_html)
    notifications = parse_notifications(notif_html)
    return {"notifications": notifications, "student_info": student_info}


# --- Whitelist and Credential Storage ---
def get_all_stored_users():
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def store_user_credentials(username, password):
    encrypted = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted)


def is_user_authorized(username):
    whitelist_raw = redis_client.get("WHITELIST")
    if whitelist_raw:
        whitelist = [u.strip() for u in whitelist_raw.decode().split(",")]
        return username in whitelist
    return False


# --- Custom Exception for Auth Errors ---
class AuthError(Exception):
    def __init__(self, message, status_code=403):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# --- Individual Auth Check Functions ---
def check_version(req_version, version_number):
    if req_version is None or req_version.strip() == "":
        raise AuthError("Missing version number", 400)
    if req_version != version_number:
        raise AuthError("Incorrect version number", 403)
    return True


def check_credentials_presence(username, password):
    if not username or not password:
        raise AuthError("Missing username or password", 400)
    return True


def check_whitelist(username):
    if not is_user_authorized(username):
        raise AuthError("User is not authorized", 403)
    return True


def check_stored_credentials(username, password):
    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
        except Exception as e:
            raise AuthError("Error decrypting credentials", 500)
        if stored_pw != password.strip():
            raise AuthError("Invalid credentials", 401)
    else:
        store_user_credentials(username, password)
    return True


# --- Flask API Setup ---
app = Flask(__name__)


@app.route("/api/guc_data", methods=["GET"])
def api_guc_data():
    username = request.args.get("username")
    password = request.args.get("password")
    req_version = request.args.get("version_number")
    version_number_raw = redis_client.get("VERSION_NUMBER")
    version_number = version_number_raw.decode() if version_number_raw else "1.0"
    cache_key = f"guc_data:{username}"

    def log_event(message):
        print(f"{datetime.now().isoformat()} - {message}")

    # Run authentication checks and cache lookup concurrently.
    with ThreadPoolExecutor(max_workers=5) as executor:
        auth_futures = {
            "version": executor.submit(check_version, req_version, version_number),
            "presence": executor.submit(check_credentials_presence, username, password),
            "whitelist": executor.submit(check_whitelist, username),
            "stored_credentials": executor.submit(
                check_stored_credentials, username, password
            ),
        }
        cache_future = executor.submit(get_from_app_cache, cache_key)

        # Wait for auth tasks.
        for key, future in auth_futures.items():
            try:
                future.result()
            except Exception as e:
                return (
                    jsonify({"status": "error", "message": str(e), "data": None}),
                    getattr(e, "status_code", 403),
                )
        # Check the cache.
        cached_data = cache_future.result()

    # If cache exists, return it immediately without scraping.
    if cached_data:
        log_event(f"Serving guc_data from cache for user: {username}")
        return jsonify(cached_data), 200

    # No cache: perform asynchronous scraping using httpx.
    try:
        start = perf_counter()
        scrape_result = asyncio.run(
            async_scrape_guc_data_fast(username, password, config.GUC_DATA_URLS)
        )
        elapsed = perf_counter() - start
        log_event(
            f"Successfully scraped guc_data for user: {username} in {elapsed:.3f}s"
        )
    except Exception as e:
        log_event(f"Error in async scraping: {e}")
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch GUC data"}), 500

    if scrape_result:
        set_to_app_cache(cache_key, scrape_result)
        return jsonify(scrape_result), 200
    else:
        log_event(f"Failed to scrape guc_data for user: {username}")
        return jsonify({"error": "Failed to fetch GUC data"}), 500


if __name__ == "__main__":
    app.run(debug=True)
