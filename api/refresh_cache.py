import os
import sys
import asyncio
import json
import traceback
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import redis
from cryptography.fernet import Fernet
import urllib3

# Disable insecure request warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure project root is on the path so we can import scraping functions
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Load environment variables
load_dotenv()

# Configuration and Redis/Fernet setup
REDIS_URL = os.environ.get("REDIS_URL")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not REDIS_URL or not ENCRYPTION_KEY:
    raise Exception("REDIS_URL and ENCRYPTION_KEY must be set.")

redis_client = redis.from_url(REDIS_URL)
fernet = Fernet(ENCRYPTION_KEY)

# Cache refresh secret and URLs configuration
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

# SSL verification configuration
VERIFY_SSL = os.environ.get("VERIFY_SSL", "True").lower() == "true"

# Import scraping functions (make sure these are defined in your project)
from cache.refresh_cache import (
    async_scrape_guc_data_fast,
    scrape_attendance,
    scrape_grades,
)
from api.schedule import (
    scrape_schedule,
    filter_schedule_details,
)  # Import filter_schedule_details
from api.scraping import (
    cms_scraper,
    scrape_exam_seats,
)

# Update scraping module's SSL verification setting
import api.scraping

api.scraping.VERIFY_SSL = VERIFY_SSL


# Helper function to get existing cache data
def get_from_cache(key):
    try:
        data = redis_client.get(key)
        if data:
            return json.loads(data.decode("utf-8"))
        return None
    except Exception as e:
        print(f"Error getting cache for key {key}: {e}")
        return None


def get_all_stored_users():
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


app = Flask(__name__)


@app.route("/api/refresh_cache", methods=["POST"])
def refresh_cache():
    secret = request.args.get("secret")
    section = request.args.get("section")
    target_username = request.args.get("username")

    if secret != CACHE_REFRESH_SECRET:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    if section not in ["1", "2", "3"]:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Missing or invalid 'section' parameter. Use '1', '2', or '3'.",
                }
            ),
            400,
        )

    stored_users = get_all_stored_users()
    if target_username:
        if target_username in stored_users:
            stored_users = {target_username: stored_users[target_username]}
        else:
            return jsonify({"status": "error", "message": "Username not found"}), 404

    results = {}

    for username, encrypted_password in stored_users.items():
        results[username] = {}
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode().strip()
        except Exception as e:
            results[username]["error"] = f"Error decrypting credentials: {e}"
            continue

        # SECTION 1: Refresh guc_data and schedule
        if section == "1":
            try:
                # Get existing cache data first
                cache_key = f"guc_data:{username}"
                existing_guc_data = get_from_cache(cache_key)

                # Call the asynchronous guc_data scraper
                result = async_scrape_guc_data_fast(username, password, GUC_DATA_URLS)
                if asyncio.iscoroutine(result):
                    scrape_result = asyncio.run(result)
                else:
                    scrape_result = result

                # Only update cache if we got valid data
                if scrape_result is not None:
                    redis_client.setex(
                        cache_key,
                        1500,
                        json.dumps(scrape_result, ensure_ascii=False).encode("utf-8"),
                    )
                    results[username]["guc_data"] = "updated"
                else:
                    results[username]["guc_data"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["guc_data"] = f"failed: {str(e)}"
                traceback.print_exc()

            try:
                # Get existing schedule data
                schedule_cache_key = f"schedule:{username}"
                existing_schedule = get_from_cache(schedule_cache_key)

                # Run schedule scraper in a thread (since it is a synchronous function)
                schedule_result = asyncio.run(
                    asyncio.to_thread(
                        scrape_schedule, username, password, BASE_SCHEDULE_URL_CONFIG
                    )
                )

                # Only update if we got valid data
                if schedule_result is not None:
                    timings = {
                        "0": "8:15AM-9:45AM",
                        "1": "10:00AM-11:30AM",
                        "2": "11:45AM-1:15PM",
                        "3": "1:45PM-3:15PM",
                        "4": "3:45PM-5:15PM",
                    }
                    filtered_schedule = filter_schedule_details(
                        schedule_result
                    )  # Filter the schedule
                    schedule_response_data = (
                        filtered_schedule,
                        timings,
                    )  # Structure the data with timings
                    redis_client.setex(
                        schedule_cache_key,
                        5184000,
                        json.dumps(schedule_response_data, ensure_ascii=False).encode(
                            "utf-8"
                        ),  # Cache the structured data
                    )
                    results[username]["schedule"] = "updated"
                else:
                    results[username]["schedule"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["schedule"] = f"failed: {str(e)}"
                traceback.print_exc()

        # SECTION 2: Refresh CMS data and grades
        elif section == "2":
            try:
                # Get existing CMS data
                cms_cache_key = f"cms:{username}"
                existing_cms = get_from_cache(cms_cache_key)

                cms_result = asyncio.run(
                    asyncio.to_thread(cms_scraper, username, password, None, 3, 2, True)
                )

                # Only update if we got valid data
                if cms_result is not None:
                    redis_client.setex(
                        cms_cache_key,
                        2592000,
                        json.dumps(cms_result, ensure_ascii=False).encode("utf-8"),
                    )
                    results[username]["cms"] = "updated"
                else:
                    results[username]["cms"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["cms"] = f"failed: {str(e)}"
                traceback.print_exc()

            try:
                # Get existing grades data
                grades_cache_key = f"grades:{username}"
                existing_grades = get_from_cache(grades_cache_key)

                grades_result = asyncio.run(
                    asyncio.to_thread(scrape_grades, username, password)
                )

                # Only update if we got valid data
                if grades_result is not None:
                    redis_client.setex(
                        grades_cache_key,
                        1500,
                        json.dumps(grades_result, ensure_ascii=False).encode("utf-8"),
                    )
                    results[username]["grades"] = "updated"
                else:
                    results[username]["grades"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["grades"] = f"failed: {str(e)}"
                traceback.print_exc()

        # SECTION 3: Refresh attendance and exam seats
        elif section == "3":
            try:
                # Get existing attendance data
                attendance_cache_key = f"attendance:{username}"
                existing_attendance = get_from_cache(attendance_cache_key)

                attendance_result = asyncio.run(
                    asyncio.to_thread(
                        scrape_attendance,
                        username,
                        password,
                        BASE_ATTENDANCE_URL_CONFIG,
                        3,
                        2,
                    )
                )

                # Only update if we got valid data
                if attendance_result is not None:
                    redis_client.setex(
                        attendance_cache_key,
                        1500,
                        json.dumps(attendance_result, ensure_ascii=False).encode(
                            "utf-8"
                        ),
                    )
                    results[username]["attendance"] = "updated"
                else:
                    results[username]["attendance"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["attendance"] = f"failed: {str(e)}"
                traceback.print_exc()

            try:
                # Get existing exam seats data
                exam_seats_cache_key = f"exam_seats:{username}"
                existing_exam_seats = get_from_cache(exam_seats_cache_key)

                exam_seats_result = asyncio.run(
                    asyncio.to_thread(scrape_exam_seats, username, password)
                )

                # Only update if we got valid data
                if exam_seats_result is not None:
                    redis_client.setex(
                        exam_seats_cache_key,
                        1500,
                        json.dumps(exam_seats_result, ensure_ascii=False).encode(
                            "utf-8"
                        ),
                    )
                    results[username]["exam_seats"] = "updated"
                else:
                    results[username]["exam_seats"] = "skipped: error fetching data"
            except Exception as e:
                results[username]["exam_seats"] = f"failed: {str(e)}"
                traceback.print_exc()

    return jsonify({"status": "done", "results": results}), 200


if __name__ == "__main__":
    app.run(debug=True)
