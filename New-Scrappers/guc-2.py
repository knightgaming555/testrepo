import re
import json
import requests
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup
from datetime import datetime
from flask import Flask, request, jsonify
import logging
import os
from time import perf_counter
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import warnings
from urllib3.exceptions import InsecureRequestWarning
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

# Suppress InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)


# --- Configuration ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )
    # Two URLs: one for student info and one for notifications
    GUC_DATA_URLS = [
        "https://apps.guc.edu.eg/student_ext/index.aspx",
        "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx",
    ]


config = Config()

# Cache expiry (10 minutes)
DATA_CACHE_EXPIRY = 600


# --- Cache Utilities ---
def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            # Fast cache retrieval like in your CMS code.
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


# --- Scraping Functions ---
def parse_student_info(html):
    """Parses student info HTML using BeautifulSoup (lxml) and normalizes text."""
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
    """Parses notifications HTML using BeautifulSoup (lxml) and normalizes newline characters."""
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
                subject = subject.replace("\r\n", "\n")
                body = body.replace("\r\n", "\n")
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


def scrape_guc_data_improved(username, password, urls):
    """
    Scrapes student info and notifications concurrently using NTLM authentication.
    Uses a persistent requests.Session with ThreadPoolExecutor.
    """
    session = requests.Session()
    session.auth = HttpNtlmAuth(f"GUC\\{username}", password)
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    logging.info(f"Initiating concurrent requests for user {username}")
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_index = executor.submit(session.get, urls[0], timeout=10, verify=False)
        future_notif = executor.submit(session.get, urls[1], timeout=10, verify=False)
        index_resp = future_index.result()
        notif_resp = future_notif.result()

    if index_resp.status_code != 200:
        raise Exception(
            f"Index request failed with status code {index_resp.status_code}"
        )
    if notif_resp.status_code != 200:
        raise Exception(
            f"Notifications request failed with status code {notif_resp.status_code}"
        )

    student_info = parse_student_info(index_resp.text)
    notifications = parse_notifications(notif_resp.text)
    return {"student_info": student_info, "notifications": notifications}


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
    version_number = version_number_raw.decode() if version_number_raw else "1.0"

    def log_event(message):
        print(f"{datetime.now().isoformat()} - {message}")

    if req_version != version_number:
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
            if stored_pw != password.strip():
                return (
                    jsonify(
                        {
                            "status": "error",
                            "message": "Invalid credentials",
                            "data": None,
                        }
                    ),
                    401,
                )
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
    else:
        store_user_credentials(username, password)

    # Retrieve cache quickly
    cache_key = f"guc_data:{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        log_event(f"Serving guc_data from cache for user: {username}")
        return jsonify(cached_data), 200

    log_event(f"Starting guc_data scraping for user: {username}")
    start = perf_counter()
    try:
        data = scrape_guc_data_improved(username, password, config.GUC_DATA_URLS)
    except Exception as e:
        log_event(f"Error during scraping for user: {username} - {str(e)}")
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch GUC data"}), 500
    elapsed = perf_counter() - start

    if data:
        log_event(
            f"Successfully scraped guc_data for user: {username} in {elapsed:.3f}s"
        )
        set_to_app_cache(cache_key, data)
        # Return only the scraped data as requested.
        return jsonify(data), 200
    else:
        log_event(f"Failed to scrape guc_data for user: {username}")
        return jsonify({"error": "Failed to fetch GUC data"}), 500


if __name__ == "__main__":
    app.run(debug=True)
