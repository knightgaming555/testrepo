import os
import hashlib
import pickle
import logging
import json
import threading
import concurrent.futures
from urllib.parse import unquote, urlparse, urlunparse

import redis
import requests
from selectolax.parser import HTMLParser
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from cryptography.fernet import Fernet

from scraping import scrape_course_announcements

# Load environment variables
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cms_content")

# --- Redis Setup ---
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.Redis.from_url(
    redis_url, socket_connect_timeout=15, socket_timeout=15
)

# --- Encryption Setup ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY must be set")
fernet = Fernet(ENCRYPTION_KEY.encode())

# --- Config ---
CACHE_EXPIRY = 14400  # 4 hours for combined content+announcements


# --- URL Normalization Helper ---
def normalize_course_url(course_url):
    # Decode, strip, lower-case, and (if necessary) append ".aspx"
    decoded = unquote(course_url).strip().lower()
    parsed = urlparse(decoded)
    # If the path contains "courseviewstn" and doesn't end with ".aspx", append it.
    if "courseviewstn" in parsed.path and not parsed.path.endswith(".aspx"):
        new_path = parsed.path + ".aspx"
        parsed = parsed._replace(path=new_path)
    return urlunparse(parsed)


# --- Unified Cache Key Generator ---
def generate_cache_key(username, course_url):
    normalized_url = normalize_course_url(course_url)
    hash_value = hashlib.md5(normalized_url.encode("utf-8")).hexdigest()
    return f"cms:{username}:{hash_value}"


# --- Caching Functions ---
def get_from_cache(key):
    data = redis_client.get(key)
    if data:
        try:
            logger.info(f"Cache hit for key {key}")
            return pickle.loads(data)
        except Exception:
            return None
    logger.info(f"Cache miss for key {key}")
    return None


def set_in_cache(key, value, expiry=CACHE_EXPIRY):
    try:
        redis_client.setex(key, expiry, pickle.dumps(value, protocol=4))
        logger.info(f"Set cache for key {key} with expiry {expiry}")
        return True
    except Exception as e:
        logger.error(f"Error setting cache for key {key}: {e}")
        return False


# --- Session Management ---
thread_local = threading.local()


def get_session(username, password):
    if not hasattr(thread_local, "session"):
        thread_local.session = create_optimized_session(username, password)
    return thread_local.session


def create_optimized_session(username, password):
    session = requests.Session()
    if username and password:
        from requests_ntlm import HttpNtlmAuth

        session.auth = HttpNtlmAuth(username, password)
    from urllib3.util import Retry
    from requests.adapters import HTTPAdapter

    retry_strategy = Retry(
        total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy, pool_connections=32, pool_maxsize=32
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0", "Connection": "keep-alive"})
    session.timeout = (15, 15)
    return session


# --- Content Parsing Functions (original logic) ---
def fast_parse_content(html_content):
    parser = HTMLParser(html_content)
    week_divs = parser.css(".weeksdata")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        weeks = list(executor.map(parse_single_week, week_divs))
    weeks = [w for w in weeks if w]
    weeks.sort(key=lambda w: w["week_name"], reverse=True)
    return weeks


def parse_single_week(week_div):
    week_title = week_div.css_first("h2.text-big")
    if not week_title:
        return None
    week_name = week_title.text().strip()
    week_data = {
        "week_name": week_name,
        "announcement": "",
        "description": "",
        "contents": [],
    }
    div_p3 = week_div.css_first("div.p-3")
    if div_p3:
        for child_div in div_p3.css("div"):
            if "display:none" in child_div.attributes.get("style", ""):
                continue
            header = child_div.css_first("div")
            para = child_div.css_first("p.m-2.p2")
            if header and para:
                header_text = header.text().strip()
                if "Announcement" in header_text:
                    week_data["announcement"] = para.text().strip()
                elif "Description" in header_text:
                    week_data["description"] = para.text().strip()
    content_cards = week_div.css(".card.mb-4")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        contents = list(executor.map(parse_content_item, content_cards))
    week_data["contents"] = [c for c in contents if c]
    return week_data


def parse_content_item(card):
    title_div = card.css_first("[id^='content']")
    if not title_div:
        return None
    title = title_div.text().strip()
    download_btn = card.css_first("a#download")
    download_url = download_btn.attributes.get("href") if download_btn else None
    if download_url and not download_url.startswith("http"):
        download_url = "https://cms.guc.edu.eg" + download_url
    return {"title": title, "download_url": download_url}


# --- Combined CMS Scraper Function ---
def cms_scraper(username, password, course_url, force_fetch=False):
    key = generate_cache_key(username, course_url)
    if not force_fetch:
        cached = get_from_cache(key)
        if cached:
            logger.info(
                f"Returning cached CMS data for {username} and course {course_url}"
            )
            return cached
    logger.info(f"Fetching fresh CMS data for {username} and course {course_url}")
    session = get_session(username, password)
    try:
        response = session.get(course_url, timeout=session.timeout)
        if response.status_code != 200:
            logger.error(
                f"Failed to retrieve CMS content; status code {response.status_code}"
            )
            return {"error": f"Failed to retrieve content: {response.status_code}"}
        content = fast_parse_content(response.text)
        announcements = scrape_course_announcements(
            username, password, course_url, max_retries=2, retry_delay=1
        )
        # Combine by inserting the announcement object as the first element (if announcements exist)
        if announcements and announcements.get("announcements_html"):
            combined = [
                {"course_announcement": announcements.get("announcements_html")}
            ] + content
        else:
            combined = content
        set_in_cache(key, combined)
        return combined
    except Exception as e:
        logger.exception(f"Error fetching CMS data for {username} at {course_url}: {e}")
        return {"error": str(e)}


# --- Flask API Endpoint ---
app = Flask(__name__)


@app.route("/api/cms_content", methods=["GET"])
def get_cms_content():
    username = request.args.get("username")
    password = request.args.get("password")
    course_url = request.args.get("course_url")
    force_fetch = request.args.get("force_fetch", "0") == "1"
    if not username or not password or not course_url:
        return jsonify({"error": "Username, password and course URL are required"}), 400
    result = cms_scraper(username, password, course_url, force_fetch=force_fetch)
    if isinstance(result, dict) and "error" in result:
        return jsonify({"error": result["error"]}), 500
    return jsonify(result), 200


@app.route("/api/test_form", methods=["GET"])
def test_form():
    return """
    <html>
      <head><title>CMS Content API Test</title></head>
      <body>
        <h1>Test CMS Content API</h1>
        <form action="/api/cms_content" method="get">
          <div>Username: <input type="text" name="username"></div>
          <div>Password: <input type="password" name="password"></div>
          <div>Course URL: <input type="text" name="course_url" size="100"></div>
          <div>Force Fetch (1 to bypass cache): <input type="text" name="force_fetch"></div>
          <div><input type="submit" value="Get Content"></div>
        </form>
      </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=True)
