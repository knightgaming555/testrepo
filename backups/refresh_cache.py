import os
import json
from cryptography.fernet import Fernet
from scraping.scraping import (
    scrape_guc_data,
    scrape_schedule,
    cms_scraper,
    scrape_grades,
    scrape_attendance,
    scrape_exam_seats,
)
from app import (
    get_all_stored_users,
)  # Ensure get_all_stored_users is exported from app.py
from dotenv import load_dotenv

load_dotenv()

CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
fernet = Fernet(ENCRYPTION_KEY)

# Base URLs used in schedule and attendance scrapers
BASE_SCHEDULE_URL = "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx"
BASE_ATTENDANCE_URL = "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx"


def handler(request):
    """
    Vercel scheduled function entry point.
    Expects query parameters:
      - secret: must equal CACHE_REFRESH_SECRET
      - section: "1" (refresh guc_data, schedule, cms_data)
                 or "2" (refresh grades, attendance, exam_seats)
    """
    secret = request.args.get("secret")
    section = request.args.get("section")
    if secret != CACHE_REFRESH_SECRET:
        return {
            "statusCode": 403,
            "body": json.dumps({"status": "error", "message": "Unauthorized"}),
        }
    if section not in ["1", "2"]:
        return {
            "statusCode": 400,
            "body": json.dumps(
                {
                    "status": "error",
                    "message": "Missing or invalid 'section' parameter. Use '1' or '2'.",
                }
            ),
        }

    stored_users = get_all_stored_users()
    results = {}
    for username, cred in stored_users.items():
        try:
            password = fernet.decrypt(cred["password"].encode()).decode()
            user_results = {}
            if section == "1":
                user_results["guc_data"] = (
                    "updated" if scrape_guc_data(username, password) else "failed"
                )
                user_results["schedule"] = (
                    "updated"
                    if scrape_schedule(username, password, BASE_SCHEDULE_URL, 3, 2)
                    else "failed"
                )
                user_results["cms_data"] = (
                    "updated" if cms_scraper(username, password) else "failed"
                )
            elif section == "2":
                user_results["grades"] = (
                    "updated" if scrape_grades(username, password) else "failed"
                )
                user_results["attendance"] = (
                    "updated"
                    if scrape_attendance(username, password, BASE_ATTENDANCE_URL, 3, 2)
                    else "failed"
                )
                user_results["exam_seats"] = (
                    "updated" if scrape_exam_seats(username, password) else "failed"
                )
            results[username] = user_results
        except Exception as e:
            results[username] = f"error: {str(e)}"
    return {
        "statusCode": 200,
        "body": json.dumps({"status": "done", "results": results}),
    }
