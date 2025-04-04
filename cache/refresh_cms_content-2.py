import os
import hashlib
import pickle
import logging
import json
import sys
import requests
from urllib.parse import unquote
import redis
from selectolax.parser import HTMLParser
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import urllib3

# Disable insecure request warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from api.scraping import scrape_course_announcements

# Load environment variables
load_dotenv()


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("refresh_all_caches")

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
VERIFY_SSL = os.environ.get("VERIFY_SSL", "True").lower() == "true"


# --- Unified Cache Key Generator (with URL normalization) ---
def generate_cache_key(username, course_url):
    normalized_url = unquote(course_url).strip().lower()
    hash_value = hashlib.md5(normalized_url.encode("utf-8")).hexdigest()
    return f"cms:{username}:{hash_value}"


# --- Caching Function ---
def set_in_cache(key, value):
    try:
        redis_client.setex(key, CACHE_EXPIRY, pickle.dumps(value))
        logger.info(f"Set cache for key {key} with expiry {CACHE_EXPIRY}")
    except Exception as e:
        logger.error(f"Error setting cache for key {key}: {e}")


# --- Get Existing Cache ---
def get_from_cache(key):
    try:
        data = redis_client.get(key)
        if data:
            return pickle.loads(data)
        return None
    except Exception as e:
        logger.error(f"Error getting cache for key {key}: {e}")
        return None


# --- Session Management ---
def get_session(username, password):
    session = requests.Session()
    if username and password:
        from requests_ntlm import HttpNtlmAuth

        session.auth = HttpNtlmAuth(username, password)
    session.headers.update({"User-Agent": "Mozilla/5.0", "Connection": "keep-alive"})
    session.timeout = (15, 15)
    return session


# --- Content Parsing Functions (original logic) ---
def fast_parse_content(html_content):
    parser = HTMLParser(html_content)
    week_divs = parser.css(".weeksdata")
    weeks = []
    for week_div in week_divs:
        week = parse_single_week(week_div)
        if week:
            weeks.append(week)
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
    contents = []
    for card in content_cards:
        item = parse_content_item(card)
        if item:
            contents.append(item)
    week_data["contents"] = contents
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


# --- Fetch Functions ---
def fetch_cms_content(username, password, course_url):
    logger.info(f"Fetching CMS content for {username} - {course_url}")
    session = get_session(username, password)
    try:
        response = session.get(course_url, timeout=session.timeout, verify=VERIFY_SSL)
        if response.status_code == 401:
            logger.error(f"Authentication failed (401) for {username} - {course_url}")
            return None  # Return None to indicate auth failure - don't update cache
        if response.status_code != 200:
            logger.error(
                f"Failed to retrieve CMS content; status {response.status_code}"
            )
            return None  # Return None for other failures - don't update cache
        content = fast_parse_content(response.text)
        if not content:
            logger.warning(f"Parsed content is empty for {username} - {course_url}")
            return None  # Don't update cache with empty content
        return content
    except Exception as e:
        logger.exception(f"Error fetching CMS content: {e}")
        return None  # Don't update cache on exception


def fetch_announcements(username, password, course_url):
    logger.info(f"Fetching announcements for {username} - {course_url}")
    try:
        announcements = scrape_course_announcements(
            username,
            password,
            course_url,
            max_retries=2,
            retry_delay=1,
            verify_ssl=VERIFY_SSL,
        )
        if not announcements or not announcements.get("announcements_html"):
            logger.warning(f"No announcements found for {username} - {course_url}")
            return None  # Don't update with empty announcements
        return announcements
    except Exception as e:
        logger.exception(f"Error fetching announcements: {e}")
        return None  # Don't update cache on exception


# --- Refresh All Caches ---
def refresh_all_caches():
    logger.info("Starting full cache refresh for all users...")
    stored_users = redis_client.hgetall("user_credentials")
    if not stored_users:
        logger.info("No stored users found in 'user_credentials'.")
        return
    for username_bytes, encrypted_pw in stored_users.items():
        username = username_bytes.decode()
        try:
            password = fernet.decrypt(encrypted_pw).decode().strip()
        except Exception as e:
            logger.error(f"Error decrypting credentials for {username}: {e}")
            continue

        # Assume each user's course list is stored under key "cms:{username}" as a JSON list.
        course_data = redis_client.get(f"cms:{username}")
        if not course_data:
            logger.error(
                f"No course list found for user {username} under key 'cms:{username}'"
            )
            continue
        try:
            courses = json.loads(course_data)
            if not isinstance(courses, list):
                courses = []
        except Exception:
            courses = course_data.decode().split(",")

        for course in courses:
            if isinstance(course, dict):
                course_url = course.get("course_url", "")
                course_name = course.get("course_name", "Unknown")
            else:
                course_url = course
                course_name = course
            if not course_url:
                logger.error(f"No course URL found in entry: {course}")
                continue

            key = generate_cache_key(username, course_url)
            # Get existing cached data before attempting refresh
            existing_cache = get_from_cache(key)

            # Fetch new content and announcements
            content = fetch_cms_content(username, password, course_url)
            announcements = fetch_announcements(username, password, course_url)

            # Only update cache if we successfully got content
            if content is not None:  # We have valid content
                # At this point we're updating the cache because content fetch succeeded
                if announcements and announcements.get("announcements_html"):
                    # We have both content and announcements
                    combined = [
                        {"course_announcement": announcements.get("announcements_html")}
                    ] + content
                else:
                    # If we have content but no new announcements (or announcements fetch failed)
                    # Check if we had announcements before
                    if (
                        existing_cache
                        and isinstance(existing_cache, list)
                        and len(existing_cache) > 0
                    ):
                        if "course_announcement" in existing_cache[0]:
                            # Keep existing announcement but update content
                            combined = [existing_cache[0]] + content
                        else:
                            combined = content
                    else:
                        combined = content

                # Only set cache if combined is not empty
                if combined:
                    set_in_cache(key, combined)
                    logger.info(
                        f"Successfully refreshed cache for {username} - {course_name} ({course_url})"
                    )
                else:
                    logger.warning(
                        f"Skipped cache update for {username} - {course_name} ({course_url}) - empty data"
                    )
            else:
                logger.warning(
                    f"Skipped cache update for {username} - {course_name} ({course_url}) - content fetch failed"
                )


if __name__ == "__main__":
    refresh_all_caches()
