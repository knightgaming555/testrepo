import os
import time
import logging
import hashlib
import pickle
import redis
import concurrent.futures
import threading
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from requests_ntlm import HttpNtlmAuth
import requests
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
from cms_content import (
    cache_key,
    get_from_cache,
    set_in_cache,
    fast_parse_content,
    create_optimized_session,
    get_all_stored_users,
)

# Load environment variables
load_dotenv()

# Configure logging with detailed format
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(threadName)s - %(message)s",
)
logger = logging.getLogger("cms_content_refresher")


# --- Configuration ---
class Config:
    DEBUG = os.environ.get("DEBUG", "False").lower() == "true"
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    DEFAULT_TIMEOUT = 15
    MAX_RETRIES = 1
    RETRY_DELAY = 0.2
    MAX_CONNECTIONS = 20
    MAX_WORKERS = 4  # Limit concurrent requests
    CACHE_EXPIRY = {
        "courses_list": 86400,  # 24 hours
        "content": 14400,  # 4 hours
    }


config = Config()

# Redis connection
redis_client = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    socket_connect_timeout=15,
    socket_timeout=15,
    health_check_interval=30,
)

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
    fernet = Fernet(Fernet.generate_key())

# Thread-local storage for session reuse
thread_local = threading.local()


def create_user_session(username, password):
    """Create a dedicated session for the user with NTLM auth."""
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)

    retry_strategy = Retry(
        total=config.MAX_RETRIES,
        backoff_factor=config.RETRY_DELAY,
        status_forcelist=[500, 502, 503, 504],
    )
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
    session.timeout = (config.DEFAULT_TIMEOUT, config.DEFAULT_TIMEOUT)
    return session


def fetch_courses_list(username, password):
    """Fetch the list of courses for a user and cache the result."""
    cache_courses_key = cache_key("courses_list", username)
    cached_courses = get_from_cache(cache_courses_key)
    if cached_courses:
        logger.info(
            f"Using cached courses list for {username} with key: {cache_courses_key}"
        )
        logger.info(f"Cached value: {cached_courses}")
        return cached_courses

    logger.info(f"Fetching courses list for {username}")
    session = create_user_session(username, password)
    try:
        cms_url = "https://cms.guc.edu.eg/apps/student/HomePageStn.aspx"
        response = session.get(cms_url, timeout=config.DEFAULT_TIMEOUT)
        if response.status_code != 200:
            logger.error(
                f"Failed to fetch courses list for {username}: Status {response.status_code}"
            )
            return []

        from selectolax.parser import HTMLParser

        parser = HTMLParser(response.text)
        courses = []
        table = parser.css_first(
            "#ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewcourses"
        )
        if table:
            rows = table.css("tr")[1:]  # Skip header
            for row in rows:
                cells = row.css("td")
                if len(cells) >= 6:
                    course_name = cells[1].text().strip()
                    course_id = cells[4].text().strip()
                    season_id = cells[5].text().strip()
                    season_name = cells[3].text().strip()
                    course_url = f"https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id={course_id}&sid={season_id}"
                    courses.append(
                        {
                            "course_name": course_name,
                            "course_url": course_url,
                            "season_name": season_name,
                        }
                    )

        if courses:
            set_in_cache(
                cache_courses_key, courses, config.CACHE_EXPIRY["courses_list"]
            )
            # Log the full cached value.
            cached_value = get_from_cache(cache_courses_key)
            logger.info(
                f"Cached courses list for {username} under {cache_courses_key}: {cached_value}"
            )
        else:
            logger.warning(f"No courses found for {username}")

        return courses

    except Exception as e:
        logger.exception(f"Error fetching courses list for {username}: {e}")
        return []


def refresh_course_content(username, password, course):
    """Refresh content for a single course and cache the result."""
    course_name = course.get("course_name", "Unknown")
    course_url = course.get("course_url")
    if not course_url:
        logger.warning(f"No URL for course {course_name} for user {username}")
        return False

    logger.info(f"Refreshing content for course: {course_name} ({username})")
    content_cache_key = cache_key("content", username, course_url)
    logger.info(f"Generated cache key for content: {content_cache_key}")

    try:
        session = create_user_session(username, password)
        response = session.get(
            course_url, timeout=(config.DEFAULT_TIMEOUT, config.DEFAULT_TIMEOUT)
        )
        if response.status_code != 200:
            logger.error(
                f"Failed to fetch {course_name} for {username}: Status {response.status_code}"
            )
            return False

        weeks_data = fast_parse_content(response.text)
        if weeks_data:
            set_in_cache(content_cache_key, weeks_data, config.CACHE_EXPIRY["content"])
            # Log the full cached content.
            cached_value = get_from_cache(content_cache_key)
            logger.info(
                f"Cached content for {course_name} ({username}) under {content_cache_key}: {cached_value}"
            )
            logger.info(
                f"Successfully refreshed content for course: {course_name} ({username})"
            )
            return True
        else:
            logger.warning(f"No content found for {course_name} ({username})")
            return False

    except Exception as e:
        logger.exception(
            f"Error refreshing content for {course_name} ({username}): {e}"
        )
        return False


def refresh_user_cms_content(username, password):
    """Refresh all CMS content for a single user."""
    logger.info(f"Starting CMS content refresh for user: {username}")
    courses = fetch_courses_list(username, password)
    if not courses:
        logger.warning(f"No courses found for {username}")
        return {
            "status": "warning",
            "message": "No courses found",
            "refreshed": 0,
            "total": 0,
        }

    results = {"total": len(courses), "refreshed": 0, "failed": 0, "courses": []}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=config.MAX_WORKERS
    ) as executor:
        future_to_course = {
            executor.submit(refresh_course_content, username, password, course): course
            for course in courses
        }
        for future in concurrent.futures.as_completed(future_to_course):
            course = future_to_course[future]
            course_name = course.get("course_name", "Unknown")
            try:
                success = future.result()
                results["courses"].append(
                    {
                        "course_name": course_name,
                        "status": "success" if success else "failed",
                    }
                )
                if success:
                    results["refreshed"] += 1
                else:
                    results["failed"] += 1
            except Exception as e:
                logger.exception(
                    f"Exception processing {course_name} for {username}: {e}"
                )
                results["failed"] += 1
                results["courses"].append(
                    {"course_name": course_name, "status": "error", "message": str(e)}
                )

    logger.info(
        f"Completed CMS content refresh for {username}: {results['refreshed']}/{results['total']} courses refreshed"
    )
    return {
        "status": "success" if results["failed"] == 0 else "partial",
        "refreshed": results["refreshed"],
        "total": results["total"],
        "details": results["courses"],
    }


def refresh_all_cms_content():
    """Refresh CMS content for all users."""
    logger.info("Starting CMS content refresh for all users")
    stored_users = get_all_stored_users()
    if not stored_users:
        logger.warning("No stored users found")
        return {"status": "warning", "message": "No users found"}

    results = {}
    for username, encrypted_password in stored_users.items():
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode().strip()
            user_result = refresh_user_cms_content(username, password)
            results[username] = user_result
            time.sleep(1)
        except Exception as e:
            logger.exception(f"Error processing user {username}: {e}")
            results[username] = {"status": "error", "message": str(e)}

    summary = {
        "status": "success",
        "total_users": len(stored_users),
        "timestamp": time.time(),
        "details": results,
    }
    logger.info("Completed CMS content refresh for all users")
    return summary


def clear_cms_content_cache(username=None):
    """
    Clear CMS content cache.
    If username is given, clear only that user's cache.
    Otherwise, clear all CMS content cache.
    """
    target = "all users" if username is None else username
    logger.info(f"Clearing CMS content cache for {target}")
    try:
        if username:
            content_pattern = f"cms:content:{username}:*"
            courses_key = f"cms:courses_list:{username}"
            logger.info(
                f"Searching for keys with pattern: {content_pattern} and courses key: {courses_key}"
            )
            all_keys = redis_client.keys("*")
            logger.info(f"Total keys in Redis: {len(all_keys)}")
            cms_related_keys = redis_client.keys("*cms*")
            username_related_keys = redis_client.keys(f"*{username}*")
            deleted_count = 0
            content_keys = []
            for key in username_related_keys:
                key_str = key.decode("utf-8")
                if "cms" in key_str or "content" in key_str:
                    content_keys.append(key_str)
            for key in cms_related_keys:
                key_str = key.decode("utf-8")
                if any(
                    course_hash in key_str
                    for course_hash in [
                        k.decode("utf-8").split(":")[-1]
                        for k in username_related_keys
                        if b":" in k and not k.startswith(b"cms:content:")
                    ]
                ):
                    content_keys.append(key_str)
            if content_keys:
                logger.info(f"Deleting keys: {content_keys}")
                redis_client.delete(*[k.encode("utf-8") for k in content_keys])
                deleted_count = len(content_keys)
                logger.info(f"Deleted {deleted_count} CMS-related keys for {username}")
            else:
                logger.info("No CMS-related keys found to delete for this user")
            return {
                "status": "success",
                "user": username,
                "deleted_keys": deleted_count,
                "debug_info": {
                    "cms_keys_count": len(cms_related_keys),
                    "username_keys_count": len(username_related_keys),
                },
            }
        else:
            all_keys = redis_client.keys("*")
            logger.info(f"Total keys in Redis: {len(all_keys)}")
            cms_related_keys = redis_client.keys("*cms*")
            content_related_keys = redis_client.keys("*content*")
            all_cms_keys = list(set(cms_related_keys + content_related_keys))
            deleted_count = 0
            if all_cms_keys:
                keys_str = [k.decode("utf-8") for k in all_cms_keys]
                logger.info(f"Deleting all CMS and content related keys: {keys_str}")
                redis_client.delete(*all_cms_keys)
                deleted_count = len(all_cms_keys)
                logger.info(f"Deleted {deleted_count} CMS and content related keys")
            else:
                logger.info("No CMS or content related keys found to delete")
            return {
                "status": "success",
                "deleted_keys": deleted_count,
                "total_keys_in_redis": len(all_keys),
            }
    except Exception as e:
        logger.exception(f"Error clearing CMS content cache: {e}")
        return {"status": "error", "message": str(e)}


def show_cms_cache_contents():
    """
    Show all CMS-related cache keys and their values.
    This logs each key and its full cached value.
    """
    logger.info("Showing CMS cache contents")
    keys = list(set(redis_client.keys("*cms*") + redis_client.keys("*content*")))
    cache_contents = {}
    for key in keys:
        key_str = key.decode("utf-8")
        try:
            value = redis_client.get(key)
            try:
                value_decoded = value.decode("utf-8")
            except Exception:
                value_decoded = str(value)
            cache_contents[key_str] = value_decoded
            logger.info(f"Key: {key_str} -> Value: {value_decoded}")
        except Exception as e:
            logger.error(f"Error retrieving value for key {key_str}: {e}")
    return cache_contents


# Interactive terminal menu
if __name__ == "__main__":
    import json

    print("\n=== CMS Content Cache Manager ===\n")
    print("Select an option:")
    print("1. Refresh CMS content cache")
    print("2. Delete CMS content cache")
    print("3. Show CMS cache contents")

    choice = input("\nEnter your choice (1, 2 or 3): ")

    if choice not in ["1", "2", "3"]:
        print("Invalid choice. Please enter 1, 2 or 3.")
        exit(1)

    if choice == "1":  # Refresh
        user_specific = input("\nTarget a specific user? (y/n): ").lower()
        if user_specific == "y":
            username = input("Enter username: ")
            stored_users = get_all_stored_users()
            if username not in stored_users:
                print(f"Error: User '{username}' not found in the database")
                exit(1)
            password = fernet.decrypt(stored_users[username].encode()).decode().strip()
            print(f"\nRefreshing CMS content for user: {username}")
            result = refresh_user_cms_content(username, password)
        else:
            print("\nRefreshing CMS content for all users")
            result = refresh_all_cms_content()
    elif choice == "2":  # Delete
        user_specific = input("\nTarget a specific user? (y/n): ").lower()
        if user_specific == "y":
            username = input("Enter username: ")
            stored_users = get_all_stored_users()
            if username not in stored_users:
                print(f"Error: User '{username}' not found in the database")
                exit(1)
        else:
            username = None
        print(
            f"\nDeleting CMS content cache for {'user: ' + username if username else 'all users'}"
        )
        result = clear_cms_content_cache(username)
    else:  # Show cache contents
        print("\nShowing CMS cache contents:")
        result = show_cms_cache_contents()

    print("\nOperation completed:")
    print(json.dumps(result, indent=2))
