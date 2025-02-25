import re
import json
import aiohttp
import asyncio
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
import lxml
from functools import wraps

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
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", 10))
    CONNECTIONS_LIMIT = int(os.environ.get("CONNECTIONS_LIMIT", 100))


config = Config()

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


# --- Fast Asynchronous Scraping Functions ---
async def fetch_url(session, url, username, password):
    """Fetch a URL using aiohttp with NTLM authentication."""
    auth = aiohttp.BasicAuth(f"GUC\\{username}", password)

    try:
        async with session.get(
            url,
            auth=auth,
            timeout=config.REQUEST_TIMEOUT,
            allow_redirects=True,
            ssl=False,  # Disable SSL verification for speed
        ) as response:
            if response.status != 200:
                print(f"Error fetching {url}: Status {response.status}")
                return None

            html = await response.text()
            return html
    except Exception as e:
        print(f"Exception fetching {url}: {str(e)}")
        return None


async def fetch_all_urls(urls, username, password):
    """Fetch multiple URLs concurrently."""
    connector = aiohttp.TCPConnector(
        limit=config.CONNECTIONS_LIMIT, ssl=False, keepalive_timeout=30
    )

    timeout = aiohttp.ClientTimeout(total=config.REQUEST_TIMEOUT)

    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
    ) as session:
        tasks = [fetch_url(session, url, username, password) for url in urls]
        results = await asyncio.gather(*tasks)
        return dict(zip(urls, results))


def parse_student_info(html):
    """Parse student info HTML using BeautifulSoup with lxml."""
    if not html:
        return {}

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
    """Parse notifications HTML using BeautifulSoup with lxml."""
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    notifications = []

    table = soup.find(
        id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
    )
    if not table:
        print("Notifications table not found in the HTML")
        return []

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
            "email_time": datetime.now().isoformat(),
            "subject": "",
            "body": "",
        }

        button = cells[1].find("button")
        if button:
            email_time_str = button.get("data-email_time", "")
            try:
                email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                notif["email_time"] = email_time.isoformat()
            except Exception as e:
                print(f"Error parsing email_time '{email_time_str}': {e}")

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

        notifications.append(notif)

    # Sort notifications by email_time
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


async def scrape_guc_data_async(username, password, urls):
    """Scrape GUC data using asynchronous requests."""
    try:
        results = await fetch_all_urls(urls, username, password)

        if not all(results.values()):
            missing_urls = [url for url, result in results.items() if not result]
            print(f"Failed to fetch some URLs: {missing_urls}")
            return None

        student_html = results[urls[0]]
        notif_html = results[urls[1]]

        # Process HTML parsing in separate threads to benefit from multiple cores
        loop = asyncio.get_running_loop()

        # Create tasks for parsing to run concurrently
        student_info_future = loop.run_in_executor(
            None, parse_student_info, student_html
        )
        notifications_future = loop.run_in_executor(
            None, parse_notifications, notif_html
        )

        student_info = await student_info_future
        notifications = await notifications_future

        return {"notifications": notifications, "student_info": student_info}

    except Exception as e:
        print(f"Error in scrape_guc_data_async: {str(e)}")
        traceback.print_exc()
        return None


# Helper to run async code from sync functions
def run_async(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def scrape_guc_data_fast(username, password, urls):
    """Synchronous wrapper for the async scraping function."""
    return run_async(scrape_guc_data_async(username, password, urls))


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


# --- Optional: Command line testing ---
def test_scraping_speed(username, password, num_runs=3):
    """Test function to measure raw scraping speed."""
    print("Testing raw scraping speed...")

    total_time = 0

    for i in range(num_runs):
        start_time = perf_counter()
        data = scrape_guc_data_fast(username, password, config.GUC_DATA_URLS)
        elapsed = perf_counter() - start_time
        total_time += elapsed
        print(f"Run {i+1}/{num_runs}: {elapsed:.3f}s")

    avg_time = total_time / num_runs
    print(f"Average scraping time over {num_runs} runs: {avg_time:.3f}s")

    return avg_time


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 2:
        # Run as a test script
        username = sys.argv[1]
        password = sys.argv[2]
        avg_time = test_scraping_speed(username, password)
        print(f"Average scraping time: {avg_time:.3f}s")
    else:
        # Use Flask's built-in server with threading for better concurrency
        from werkzeug.serving import run_simple

        run_simple("localhost", 5000, app, use_reloader=True, threaded=True)
