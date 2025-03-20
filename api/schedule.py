import re
import json
import requests
from requests_ntlm import HttpNtlmAuth
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

# Load environment variables
load_dotenv()

# Initialize Redis and encryption key (for storing credentials and whitelist)
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
fernet = Fernet(ENCRYPTION_KEY)

# Base URL for schedule scraping
BASE_URL = "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx"

timings = {
    "1": "8:30A.M-9:45A.M",
    "2": "9:45AM-10:55AM",
    "3": "11:00AM-12:10PM",
    "4": "12:20PM-1:30PM",
    "5": "1:35PM-2:45PM",
}

# Suppress only the InsecureRequestWarning from urllib3
warnings.simplefilter("ignore", InsecureRequestWarning)

# --- Cache Utilities ---
# LONG_CACHE_TIMEOUT is set for around 2 months in seconds.
LONG_CACHE_TIMEOUT = 5184000  # 2 months in seconds


def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached)
    except Exception as e:
        print(f"[Cache] Get error for key '{key}': {e}")
    return None


def set_to_app_cache(key, value, timeout=LONG_CACHE_TIMEOUT):
    try:
        redis_client.setex(key, timeout, json.dumps(value))
    except Exception as e:
        print(f"[Cache] Set error for key '{key}': {e}")


# --- Fast Scraping Functions ---
def extract_schedule_data(cell_html):
    """Extracts schedule data from a single table cell HTML using BeautifulSoup."""
    soup = BeautifulSoup(cell_html, "lxml")
    course_info = {"Type": "Unknown", "Location": "Unknown", "Course_Name": "Unknown"}
    try:
        if "Free" in cell_html:
            return {"Type": "Free", "Location": "Free", "Course_Name": "Free"}
        if "Lecture" in cell_html:
            span = soup.select_one(
                "span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']"
            )
            if span:
                span_text = span.get_text(separator=" ", strip=True)
                location = span_text[-3:]
                course_info["Location"] = location
                course_info["Course_Name"] = (
                    span_text.replace("Lecture", "").replace(location, "").strip()
                )
                course_info["Type"] = "Lecture"
        elif "Tut" in cell_html or "Lab" in cell_html:
            small_tag = soup.select_one("small")
            if small_tag:
                text_nodes = [text for text in small_tag.parent.stripped_strings]
                course_info["Course_Name"] = (
                    text_nodes[0].strip() if text_nodes else "Unknown"
                )
                if len(text_nodes) > 2:
                    course_info["Location"] = text_nodes[2].strip()
                course_info["Type"] = small_tag.get_text(separator=" ", strip=True)
            else:
                table = soup.select_one("table")
                if table and not soup.select_one(
                    "table[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_XaltTbl']"
                ):
                    rows = table.select("tr")
                    if rows:
                        tds = rows[0].select("td")
                        if len(tds) >= 3:
                            course_info["Course_Name"] = (
                                tds[0].get_text(separator=" ", strip=True)
                                + " "
                                + re.sub(
                                    r"(Tut|Lab)",
                                    "",
                                    tds[2].get_text(separator=" ", strip=True),
                                    flags=re.IGNORECASE,
                                ).strip()
                            )
                            course_info["Location"] = tds[1].get_text(
                                separator=" ", strip=True
                            )
                            type_match = re.search(
                                r"(Tut|Lab)",
                                tds[2].get_text(separator=" ", strip=True),
                                re.IGNORECASE,
                            )
                            course_info["Type"] = (
                                type_match.group(0).capitalize()
                                if type_match
                                else "Unknown"
                            )
                elif table and soup.select_one(
                    "table[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_XaltTbl']"
                ):
                    span = soup.select_one(
                        "span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']"
                    )
                    if span:
                        span_text = span.get_text(separator=" ", strip=True)
                        course_info["Type"] = "Lecture"
                        location = span_text[-3:]
                        course_info["Location"] = location
                        course_info["Course_Name"] = (
                            span_text.replace("Lecture", "")
                            .replace(location, "")
                            .strip()
                        )
    except Exception as e:
        print(f"Error extracting schedule data: {e}")
    return course_info


def parse_schedule_bs4(html):
    """Parses the schedule HTML using BeautifulSoup and CSS selectors."""
    soup = BeautifulSoup(html, "lxml")
    schedule = {}
    rows = soup.select(
        "tr[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xrw']"
    )
    period_names = [
        "First Period",
        "Second Period",
        "Third Period",
        "Fourth Period",
        "Fifth Period",
    ]
    for row in rows:
        try:
            day_cell = row.select_one("td[align='center']")
            day = (
                day_cell.get_text(separator=" ", strip=True)
                if day_cell
                else "Unknown Day"
            )
            periods = row.select("td[width='180']")
            day_schedule = {}
            for i, period_cell in enumerate(periods):
                if i < len(period_names):
                    cell_data = extract_schedule_data(str(period_cell))
                    day_schedule[period_names[i]] = (
                        cell_data
                        if cell_data
                        else {"Type": "Free", "Location": "Free", "Course_Name": "Free"}
                    )
            schedule[day] = day_schedule
        except Exception as e:
            print(f"Error getting schedule: {e}")
    day_order = ["Saturday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday"]
    sorted_schedule = {
        day: schedule.get(day, {}) for day in day_order if day in schedule
    }
    return sorted_schedule


def scrape_schedule(username, password, base_url):
    """Scrapes schedule data with NTLM authentication and JavaScript redirection.
    Caching is now applied in the API endpoint so that a fresh fetch is only done
    when no cached version exists.
    """
    try:
        with requests.Session() as session:
            session.auth = HttpNtlmAuth(username, password)
            start = perf_counter()
            res = session.get(base_url, timeout=10, verify=False)
            if res.status_code != 200:
                return {
                    "error": f"Initial request failed ({res.status_code})"
                }, perf_counter() - start
            js_redirect_pattern = re.compile(r"sTo\('([a-f0-9-]+)'\)", re.IGNORECASE)
            js_match = js_redirect_pattern.search(res.text)
            if not js_match:
                return {
                    "error": "Failed to find JavaScript redirect parameter 'v'"
                }, perf_counter() - start
            v_parameter_value = js_match.group(1)
            schedule_url = f"{base_url}?v={v_parameter_value}"
            schedule_res = session.get(schedule_url, timeout=10, verify=False)
            scraped = parse_schedule_bs4(schedule_res.text)
            return scraped, perf_counter() - start
    except Exception as e:
        return {"error": str(e)}, perf_counter() - start


def filter_schedule_details(schedule_data):
    """Filters the parsed schedule to only include course, type, and location."""
    filtered_schedule = {}
    for day, periods in schedule_data.items():
        filtered_periods = {}
        for period_name, period_details in periods.items():
            if isinstance(period_details, dict):
                filtered_periods[period_name] = {
                    "Course_Name": period_details.get("Course_Name", "N/A"),
                    "Type": period_details.get("Type", "N/A"),
                    "Location": period_details.get("Location", "N/A"),
                }
            else:
                filtered_periods[period_name] = period_details
        filtered_schedule[day] = filtered_periods
    return filtered_schedule


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


@app.route("/api/schedule", methods=["GET"])
def api_schedule():
    # Extract username and password from query parameters
    username = request.args.get("username")
    password = request.args.get("password")
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Whitelist check
    if not is_user_authorized(username):
        return jsonify({"error": "User is not authorized"}), 403

    # Check stored credentials; if not present, store them
    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
        except Exception:
            return jsonify({"error": "Error decrypting credentials"}), 500
        if stored_pw != password.strip():
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        store_user_credentials(username, password)

    log_event = lambda msg: print(f"{datetime.now().isoformat()} - {msg}")

    # --- Caching Logic for Schedule Data ---
    cache_key = f"schedule:{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        log_event(f"Serving schedule data from cache for user: {username}")
        return jsonify(cached_data), 200

    log_event(f"Starting schedule scraping for user: {username}")
    result, elapsed = scrape_schedule(username, password, BASE_URL)
    if "error" in result:
        log_event(f"Error: {result['error']}")
        return jsonify({"error": result["error"]}), 500
    else:
        log_event(
            f"Successfully scraped schedule for user: {username} in {elapsed:.3f}s"
        )
        filtered = filter_schedule_details(result)
        # Cache the filtered schedule for about 2 months

        response_data = (filtered, timings)

        set_to_app_cache(cache_key, response_data, LONG_CACHE_TIMEOUT)
        return jsonify(response_data), 200


if __name__ == "__main__":
    app.run(debug=True)
