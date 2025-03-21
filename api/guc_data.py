import re
import json
import requests
from requests_ntlm import HttpNtlmAuth  # You might not need this now
from time import perf_counter
from bs4 import BeautifulSoup
import warnings
from urllib3.exceptions import InsecureRequestWarning  # You might not need this now
from flask import Flask, request, jsonify
from datetime import datetime
import redis
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import pycurl
from io import BytesIO
import traceback

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
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
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

# Suppress InsecureRequestWarning (if you were still using requests and needed this)
warnings.simplefilter("ignore", InsecureRequestWarning)

# --- Cache Utilities ---
DATA_CACHE_EXPIRY = 600  # seconds (10 minutes cache for data)


def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached.decode())  # Decode bytes to string
    except Exception as e:
        print(f"[Cache] Get error for key '{key}': {e}")
    return None


def set_to_app_cache(key, value, timeout=DATA_CACHE_EXPIRY):
    try:
        redis_client.setex(
            key, timeout, json.dumps(value, ensure_ascii=False).encode("utf-8")
        )  # Encode to bytes
    except Exception as e:
        print(f"[Cache] Set error for key '{key}': {e}")


# --- Fast Scraping Functions for GUC Data (adapted from your initial fast code) ---
def multi_fetch(urls, userpwd):
    """Fetches multiple URLs concurrently using pycurl."""
    multi = pycurl.CurlMulti()
    handles = []
    buffers = {}

    for url in urls:
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
        c.setopt(c.USERPWD, userpwd)
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.FOLLOWLOCATION, True)
        c.setopt(c.TIMEOUT, 10)  # Timeout for each handle
        multi.add_handle(c)
        handles.append(c)
        buffers[url] = buffer

    num_handles = len(handles)
    while num_handles:
        ret, num_handles = multi.perform()
        multi.select(1.0)

    results = {}
    for url, c in zip(urls, handles):
        results[url] = buffers[url].getvalue().decode("utf-8", errors="replace")
        multi.remove_handle(c)
        c.close()
    multi.close()
    return results


def parse_student_info(html):
    """Parses student info HTML using BeautifulSoup with lxml."""
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
        if element:
            text = element.get_text(" ", strip=True).replace("\r", "")
            info[key] = text
        else:
            info[key] = ""
    return info


def parse_notifications(html):
    """Parses notifications HTML using BeautifulSoup with lxml."""
    soup = BeautifulSoup(html, "lxml")
    notifications = []
    table = soup.find(
        id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
    )
    if table:
        rows = table.find_all("tr")[1:]
        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 6:
                continue
            notif = {}
            notif["id"] = cells[0].get_text(" ", strip=True).replace("\r", "")
            notif["title"] = cells[2].get_text(" ", strip=True).replace("\r", "")
            notif["date"] = cells[3].get_text(" ", strip=True).replace("\r", "")
            notif["staff"] = cells[4].get_text(" ", strip=True).replace("\r", "")
            notif["importance"] = cells[5].get_text(" ", strip=True).replace("\r", "")
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
                subject = (
                    button.get("data-subject_text", "")
                    .replace("Notification System:", "")
                    .strip()
                    .replace("\r", "")
                )
                body = (
                    button.get("data-body_text", "")
                    .replace("------------------------------", "")
                    .strip()
                    .replace("\r", "")
                )
                notif["subject"] = subject
                notif["body"] = body
            else:
                notif["email_time"] = datetime.now().isoformat()
                notif["subject"] = ""
                notif["body"] = ""
            notifications.append(notif)
    else:
        print("Notifications table not found in the HTML.")
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


def scrape_guc_data_fast(username, password, urls):
    """Scrapes student info and notifications using fast methods."""
    userpwd = f"GUC\\{username}:{password}"
    try:
        results = multi_fetch(urls, userpwd)
        student_html = results[urls[0]]
        notif_html = results[urls[1]]

        student_info = parse_student_info(student_html)
        notifications = parse_notifications(notif_html)

        return {"notifications": notifications, "student_info": student_info}

    except Exception as e:
        print(f"Error in scrape_guc_data_fast: {e}")
        traceback.print_exc()
        return None


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


# --- Flask API Setup ---
app = Flask(__name__)


@app.route("/api/guc_data", methods=["GET"])
def api_guc_data():
    username = request.args.get("username")
    password = request.args.get("password")
    req_version = request.args.get("version_number")
    version_number_raw = redis_client.get("VERSION_NUMBER")
    version_number2 = version_number_raw.decode() if version_number_raw else "1.0"

    def log_event(message):
        print(f"{datetime.now().isoformat()} - {message}")

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

    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
            provided_pw = password.strip()
        except Exception as e:
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
        if stored_pw != provided_pw:
            return (
                jsonify(
                    {"status": "error", "message": "Invalid credentials", "data": None}
                ),
                401,
            )
    else:
        store_user_credentials(
            username, password
        )  # Still store even if not previously cached.

    cache_key = f"guc_data:{username}"
    cached_data = get_from_app_cache(cache_key)

    if cached_data:
        log_event(f"Serving guc_data from cache for user: {username}")
        return jsonify(cached_data), 200

    log_event(f"Starting guc_data scraping for user: {username}")

    start = perf_counter()
    try:
        data = scrape_guc_data_fast(
            username, password, config.GUC_DATA_URLS
        )  # Using the fast scrape function
    except Exception as e:
        log_event(f"Error during scraping for user: {username} - {str(e)}")
        return jsonify({"error": "Failed to fetch GUC data"}), 500
    elapsed = perf_counter() - start

    if data:
        log_event(
            f"Successfully scraped guc_data for user: {username} in {elapsed:.3f}s"
        )
        set_to_app_cache(cache_key, data)  # Cache the fast result
        return jsonify(data), 200
    else:
        log_event(f"Failed to scrape guc_data for user: {username}")
        return jsonify({"error": "Failed to fetch GUC data"}), 500


if __name__ == "__main__":
    app.run(debug=True)
