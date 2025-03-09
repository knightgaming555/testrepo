import os
import hashlib
import pickle
import logging
from flask import Flask, request, jsonify
import redis
import requests
from requests_ntlm import HttpNtlmAuth
from selectolax.parser import HTMLParser
from dotenv import load_dotenv
import concurrent.futures
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import threading
from cryptography.fernet import Fernet


# Load environment variables
load_dotenv()

# Minimal logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cms_content")


# --- Streamlined Configuration ---
class Config:
    DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get(
        "ENCRYPTION_KEY", "your-fallback-encryption-key-32bytes-here"
    )

    # Optimized performance settings
    DEFAULT_TIMEOUT = 1.5
    MAX_RETRIES = 1
    RETRY_DELAY = 0.2
    THREAD_POOL_SIZE = 16
    MAX_CONNECTIONS = 32
    CACHE_EXPIRY = {
        "auth": 7200,  # 2 hours for auth
        "content": 14400,  # 4 hours for content
        "credentials": 604800,  # 1 week for credentials
    }
    PARSER_THREAD_POOL = 8
    CONNECTION_TIMEOUT = 1
    READ_TIMEOUT = 2


config = Config()

# Thread-local storage for session reuse
thread_local = threading.local()

# Redis connection with connection pooling - simplified
redis_client = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    socket_connect_timeout=1,
    socket_timeout=1,
    health_check_interval=30,
)

# Initialize Flask
app = Flask(__name__)

# Set up encryption
try:
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    if not ENCRYPTION_KEY:
        raise ValueError("ENCRYPTION_KEY environment variable not set")
    fernet = Fernet(
        ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY
    )
except Exception as e:
    logger.error(f"Error setting up encryption: {e}")
    # Use a fallback key if needed
    fernet = Fernet(Fernet.generate_key())


# --- Credential Management Functions ---
def get_all_stored_users():
    """Get all stored user credentials from Redis hash"""
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def store_user_credentials(username, password):
    """Store encrypted credentials in Redis hash"""
    encrypted = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted)


def verify_credentials(username, password):
    """Verify credentials against stored credentials"""
    stored_users = get_all_stored_users()

    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
            provided_pw = password.strip()

            # Return whether the credentials match
            return stored_pw == provided_pw
        except Exception as e:
            logger.error(f"Error decrypting credentials: {e}")
            return False
    else:
        # If user doesn't exist, store the credentials and authenticate with CMS
        store_user_credentials(username, password)
        return None  # Signal that we need to do actual authentication


# --- Session Management ---
def get_session(username=None, password=None):
    """Get or create a session optimized for the current thread"""
    if not hasattr(thread_local, "session"):
        thread_local.session = create_optimized_session(username, password)
    return thread_local.session


def create_optimized_session(username, password):
    """Minimal optimized session"""
    session = requests.Session()

    if username and password:
        session.auth = HttpNtlmAuth(username, password)

    # Simplified retry strategy
    retry_strategy = Retry(
        total=config.MAX_RETRIES,
        backoff_factor=config.RETRY_DELAY,
        status_forcelist=[500, 502, 503, 504],
    )

    # Connection pooling
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=config.MAX_CONNECTIONS,
        pool_maxsize=config.MAX_CONNECTIONS,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "User-Agent": "Mozilla/5.0",
            "Connection": "keep-alive",
        }
    )

    # Set tight timeouts
    session.timeout = (config.CONNECTION_TIMEOUT, config.READ_TIMEOUT)

    return session


# --- Simplified Caching ---
def cache_key(prefix, *args):
    """Simple cache key"""
    key_string = prefix + ":".join(str(arg) for arg in args)
    return f"cms:{hashlib.md5(key_string.encode()).hexdigest()}"


def get_from_cache(key):
    """Fast cache retrieval - no compression/encryption"""
    data = redis_client.get(key)
    if data:
        try:
            return pickle.loads(data)
        except:
            return None
    return None


def set_in_cache(key, value, expiry=None):
    """Fast cache storage - no compression/encryption"""
    if expiry is None:
        expiry = config.CACHE_EXPIRY["content"]

    try:
        redis_client.setex(key, expiry, pickle.dumps(value, protocol=4))
        return True
    except:
        return False


# --- Minimal Content Parsing ---
def fast_parse_content(html_content):
    """Simplified and fast content parsing"""
    parser = HTMLParser(html_content)
    weeks = []

    # Get all week divs in one go
    week_divs = parser.css(".weeksdata")

    # Process all weeks at once
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=config.PARSER_THREAD_POOL
    ) as executor:
        futures = []

        for week_div in week_divs:
            futures.append(executor.submit(parse_single_week, week_div))

        for future in concurrent.futures.as_completed(futures):
            week_data = future.result()
            if week_data:
                weeks.append(week_data)

    # Sort weeks
    weeks.sort(key=lambda w: w["week_name"], reverse=True)
    return weeks


def parse_single_week(week_div):
    """Fast parse of a single week"""
    week_title = week_div.css_first("h2.text-big")
    if not week_title:
        return None

    week_name = week_title.text().strip()

    # Initialize week data with minimal fields
    week_data = {
        "week_name": week_name,
        "announcement": "",
        "description": "",
        "contents": [],
    }

    # Get announcement and description
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

    # Get content cards
    content_cards = week_div.css(".card.mb-4")
    for card in content_cards:
        content = parse_content_item(card)
        if content:
            week_data["contents"].append(content)

    return week_data


def parse_content_item(card):
    """Fast parse of content item - no threading"""
    title_div = card.css_first("[id^='content']")
    if not title_div:
        return None

    title = title_div.text().strip()

    # Get download link
    download_btn = card.css_first("a#download")
    download_url = download_btn.attributes.get("href") if download_btn else None

    if download_url and not download_url.startswith("http"):
        download_url = "https://cms.guc.edu.eg" + download_url

    return {"title": title, "download_url": download_url}


# --- Core Functions ---
def authenticate_user(username, password):
    """Verify user credentials with credential caching"""
    # Check auth cache first
    auth_key = cache_key("auth", username)
    cached_auth = get_from_cache(auth_key)

    if cached_auth:
        return True

    # Check stored credentials
    credential_match = verify_credentials(username, password)

    # If credentials match stored, set auth cache and return
    if credential_match is True:
        set_in_cache(auth_key, True, config.CACHE_EXPIRY["auth"])
        return True

    # If credentials don't match or user is new, verify with CMS
    try:
        session = get_session(username, password)
        response = session.get(
            "https://cms.guc.edu.eg/apps/student/HomePageStn.aspx",
            timeout=config.DEFAULT_TIMEOUT,
        )
        is_authenticated = response.status_code == 200 and "Hello," in response.text

        if is_authenticated:
            # We already stored credentials for new users above
            # For existing users with incorrect passwords, update stored credentials
            if credential_match is False:
                store_user_credentials(username, password)

            # Set auth cache
            set_in_cache(auth_key, True, config.CACHE_EXPIRY["auth"])

        return is_authenticated
    except Exception as e:
        logger.exception(f"Authentication error: {e}")
        return False


def cms_scraper(username, password, course_url):
    """Streamlined CMS scraper"""
    cache_key_str = cache_key("content", username, course_url)
    cached_content = get_from_cache(cache_key_str)

    if cached_content:
        return cached_content

    session = get_session(username, password)

    try:
        response = session.get(course_url, timeout=session.timeout)
        if response.status_code != 200:
            return {
                "error": f"Failed to retrieve content: Status code {response.status_code}"
            }

        # Parse content using optimized parser
        weeks_data = fast_parse_content(response.text)

        # Cache the results if we have data
        if weeks_data:
            set_in_cache(cache_key_str, weeks_data, config.CACHE_EXPIRY["content"])

        return weeks_data
    except Exception as e:
        return {"error": str(e)}


# --- API Routes ---
@app.route("/api/cms_content", methods=["GET"])
def get_cms_content():
    username = request.args.get("username")
    password = request.args.get("password")
    course_url = request.args.get("course_url")

    if not username or not password or not course_url:
        return jsonify({"error": "Username, password and course URL are required"}), 400

    # Exact same credential verification as in guc_data.py
    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
            provided_pw = password.strip()
        except Exception as e:
            return (
                jsonify({"error": "Error decrypting credentials"}),
                500,
            )
        if stored_pw != provided_pw:
            return (
                jsonify({"error": "Invalid credentials"}),
                401,
            )
    else:
        store_user_credentials(
            username, password
        )  # Store even if not previously cached

    # Now proceed with threaded content fetching
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        # Check auth from cache
        auth_key = cache_key("auth", username)
        auth_cached = get_from_cache(auth_key)

        # Start auth and content fetching in parallel
        if not auth_cached:
            auth_future = executor.submit(authenticate_user, username, password)

        content_future = executor.submit(cms_scraper, username, password, course_url)

        # Check auth result if needed
        if not auth_cached:
            try:
                is_auth = auth_future.result(timeout=2)
                if not is_auth:
                    return jsonify({"error": "Invalid credentials"}), 401
            except Exception as e:
                logger.exception(f"Authentication error: {e}")
                return jsonify({"error": f"Authentication error: {str(e)}"}), 500

        # Get content result
        try:
            data = content_future.result(timeout=3)
            return jsonify(data), 200
        except Exception as e:
            logger.exception(f"Error retrieving content: {e}")
            return jsonify({"error": str(e)}), 500


# Simple test form
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
            <div><input type="submit" value="Get Content"></div>
        </form>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(debug=config.DEBUG, threaded=True)
