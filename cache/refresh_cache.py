import sys
import os
import asyncio
import json
import traceback
import time
import re
from datetime import datetime
import redis
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import httpx
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure the project root is on the path so we can import from the api folder
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Load environment variables from .env file
load_dotenv()

REDIS_URL = os.environ.get("REDIS_URL")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not REDIS_URL or not ENCRYPTION_KEY:
    raise Exception("REDIS_URL and ENCRYPTION_KEY must be set.")

# Initialize Redis and encryption engine
redis_client = redis.from_url(REDIS_URL)
fernet = Fernet(ENCRYPTION_KEY)

# Configuration for guc_data scraping
GUC_DATA_URLS = [
    "https://apps.guc.edu.eg/student_ext/index.aspx",
    "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx",
]
DOMAIN = "GUC"  # assumed constant

# Configuration for schedule and attendance scraping
BASE_SCHEDULE_URL_CONFIG = os.environ.get(
    "BASE_SCHEDULE_URL",
    "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
)
BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
    "BASE_ATTENDANCE_URL",
    "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
)

# SSL verification configuration
VERIFY_SSL = os.environ.get("VERIFY_SSL", "True").lower() == "true"

# --- NTLM Authentication Imports ---
# For asynchronous httpx calls:
from httpx_ntlm import HttpNtlmAuth as HttpNtlmAuthAsync

# For synchronous requests calls:
from requests_ntlm import HttpNtlmAuth as HttpNtlmAuthSync


# --- HTML Parsing Functions for guc_data ---
def parse_student_info(html):
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
        info[key] = (
            element.get_text(" ", strip=True).replace("\r", "") if element else ""
        )
    return info


def parse_notifications(html):
    soup = BeautifulSoup(html, "lxml")
    notifications = []
    table = soup.find(
        "table", id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
    )
    if table:
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
            }
            button = cells[1].find("button")
            if button:
                email_time_str = button.get("data-email_time", "")
                try:
                    email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                    notif["email_time"] = email_time.isoformat()
                except Exception as e:
                    print(
                        f"{datetime.now().isoformat()} - Error parsing email_time '{email_time_str}': {e}. Using current time."
                    )
                    notif["email_time"] = datetime.now().isoformat()
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
            else:
                notif["email_time"] = datetime.now().isoformat()
                notif["subject"] = ""
                notif["body"] = ""
            notifications.append(notif)
    else:
        print(
            f"{datetime.now().isoformat()} - Notifications table not found in the HTML."
        )
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


# --- Asynchronous Scraping Function for guc_data ---
async def async_scrape_guc_data_fast(username, password, urls):
    try:
        # Use the httpx NTLM auth for async calls:
        auth = HttpNtlmAuthAsync(f"{DOMAIN}\\{username}", password)
        async with httpx.AsyncClient(
            auth=auth, timeout=10.0, verify=VERIFY_SSL
        ) as client:
            tasks = [client.get(url) for url in urls]
            responses = await asyncio.gather(*tasks)

            # Check for auth failures or other errors
            for response in responses:
                if response.status_code == 401:
                    print(
                        f"{datetime.now().isoformat()} - Authentication failed (401) for {username}"
                    )
                    return None
                if response.status_code != 200:
                    print(
                        f"{datetime.now().isoformat()} - Failed request with status code {response.status_code}"
                    )
                    return None

            htmls = {url: response.text for url, response in zip(urls, responses)}

        student_html = htmls[urls[0]]
        notif_html = htmls[urls[1]]
        student_info = parse_student_info(student_html)
        notifications = parse_notifications(notif_html)

        # Make sure we have valid data
        if not student_info or not notifications:
            print(f"{datetime.now().isoformat()} - Failed to parse data for {username}")
            return None

        return {"notifications": notifications, "student_info": student_info}
    except Exception as e:
        print(
            f"{datetime.now().isoformat()} - Error in async_scrape_guc_data_fast for {username}: {e}"
        )
        return None


__all__ = ["async_scrape_guc_data_fast"]

# --- Import additional scraping functions for schedule and CMS ---
from api.scraping import cms_scraper
from api.schedule import (
    scrape_schedule,
    filter_schedule_details,
)  # Import filter_schedule_details


# --- Grade Scraping Functions ---
def scrape_grades_from_html(soup):
    """
    Extracts midterm grades and subject codes from the grades page.
    Returns a dictionary with keys 'midterm_results' and 'subject_codes'.
    """
    grades = {}
    midterm_table = soup.find(
        "table", id="ContentPlaceHolderright_ContentPlaceHoldercontent_midDg"
    )
    if midterm_table:
        midterm_results = {}
        for row in midterm_table.find_all("tr")[1:]:
            cells = row.find_all("td")
            if len(cells) == 2:
                course_name = cells[0].text.strip()
                percentage = cells[1].text.strip()
                midterm_results[course_name] = percentage
        grades["midterm_results"] = midterm_results
    subject_dropdown = soup.find(
        "select", id="ContentPlaceHolderright_ContentPlaceHoldercontent_smCrsLst"
    )
    if subject_dropdown:
        subject_codes = {}
        for option in subject_dropdown.find_all("option"):
            if option.get("value"):
                subject_codes[option.text.strip()] = option["value"]
        grades["subject_codes"] = subject_codes
    return grades


def extract_detailed_grades(soup):
    """
    Extracts detailed grades (quizzes, assignments, etc.) from the grades page.
    Returns a dictionary with unique keys for each grade element.
    """
    try:
        detailed_grades_table = soup.find(
            "div", id="ContentPlaceHolderright_ContentPlaceHoldercontent_nttTr"
        ).find("table")
        if detailed_grades_table:
            detailed_grades = {}
            rows = detailed_grades_table.find_all("tr")
            if not rows:
                return None
            header_row = None
            for row in rows:
                if row.find_all("td"):
                    header_row = row
                    break
            if not header_row:
                return None
            headers = [
                header.text.strip()
                for header in header_row.find_all("td")
                if header.text.strip()
            ]
            row_counter = 0
            for row in rows[1:]:
                cells = row.find_all("td")
                if len(cells) == len(headers):
                    row_data = {}
                    for i, cell in enumerate(cells):
                        row_data[headers[i]] = cell.text.strip()
                    quiz_assignment = row_data.get("Quiz/Assignment", "Unknown").strip()
                    element_name = row_data.get("Element Name", "Unknown").strip()
                    grade_value = row_data.get("Grade", "Undetermined").strip()
                    unique_key = f"{element_name}_{row_counter}"
                    row_counter += 1
                    if grade_value and "/" in grade_value:
                        parts = grade_value.split("/")
                        if len(parts) == 2:
                            try:
                                percentage = float(parts[0].strip())
                                out_of = float(parts[1].strip())
                            except ValueError:
                                percentage = 0.0
                                out_of = 0.0
                        else:
                            percentage = 0.0
                            out_of = 0.0
                    else:
                        percentage = 0.0
                        out_of = 0.0
                    detailed_grades[unique_key] = {
                        "Quiz/Assignment": quiz_assignment,
                        "Element Name": element_name,
                        "grade": grade_value.replace("\r", "")
                        .replace("\n", "")
                        .replace("\t", "")
                        .strip(),
                        "percentage": percentage,
                        "out_of": out_of,
                    }
            return detailed_grades
        else:
            print("Detailed grades table not found.")
            return None
    except Exception as e:
        print(f"Error extracting detailed grades: {e}")
        return None


def get_grades(session, grades_url, max_retries=3, retry_delay=2):
    """
    Fetches and parses grades data from the grades page.
    Also fetches detailed grades for each subject.
    """
    for attempt in range(max_retries):
        try:
            response = session.get(grades_url, timeout=10, verify=VERIFY_SSL)

            # Check for auth failures
            if response.status_code == 401:
                print(f"Authentication failed (401) for {grades_url}")
                return None

            response.raise_for_status()
            soup = BeautifulSoup(response.content, "lxml")
            grades = scrape_grades_from_html(soup)
            if grades:
                subject_codes = grades.get("subject_codes", {})
                detailed_grades_all_subjects = {}
                for subject_name, subject_code in subject_codes.items():
                    print(
                        f"Fetching detailed grades for subject: {subject_name}, code: {subject_code}"
                    )
                    viewstate = soup.find("input", {"name": "__VIEWSTATE"})
                    viewstate_gen = soup.find("input", {"name": "__VIEWSTATEGENERATOR"})
                    event_validation = soup.find("input", {"name": "__EVENTVALIDATION"})
                    if not viewstate or not viewstate_gen or not event_validation:
                        print(f"Missing form elements for {subject_name}. Skipping.")
                        continue
                    form_data = {
                        "__EVENTTARGET": "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$smCrsLst",
                        "__EVENTARGUMENT": "",
                        "__LASTFOCUS": "",
                        "__VIEWSTATE": viewstate["value"],
                        "__VIEWSTATEGENERATOR": viewstate_gen["value"],
                        "__EVENTVALIDATION": event_validation["value"],
                        "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$smCrsLst": subject_code,
                        "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$HiddenFieldstudent": soup.find(
                            "input",
                            id="ContentPlaceHolderright_ContentPlaceHoldercontent_HiddenFieldstudent",
                        )[
                            "value"
                        ],
                        "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$HiddenFieldseason": soup.find(
                            "input",
                            id="ContentPlaceHolderright_ContentPlaceHoldercontent_HiddenFieldseason",
                        )[
                            "value"
                        ],
                        "ctl00$ctl00$div_position": "0",
                    }
                    subject_grades_url = grades_url
                    response = session.post(
                        subject_grades_url,
                        data=form_data,
                        timeout=10,
                        verify=VERIFY_SSL,
                    )

                    # Check for auth failures in subject request
                    if response.status_code == 401:
                        print(f"Authentication failed (401) for subject {subject_name}")
                        continue

                    response.raise_for_status()
                    subject_soup = BeautifulSoup(response.content, "lxml")
                    detailed_grades = extract_detailed_grades(subject_soup)
                    if detailed_grades:
                        detailed_grades_all_subjects[subject_name] = detailed_grades
                        print(f"Got detailed grades for subject: {subject_name}")
                grades["detailed_grades"] = detailed_grades_all_subjects
                return grades
            else:
                print(
                    f"Grades data not extracted on attempt {attempt+1}/{max_retries}."
                )
        except requests.exceptions.RequestException as e:
            print(
                f"Network error on attempt {attempt+1}/{max_retries} for {grades_url}: {e}"
            )
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
        except Exception as e:
            print(f"Error processing grades data from {grades_url}: {e}")
            return None
    return None


def scrape_grades(username, password, max_retries=3, retry_delay=2):
    """
    Main function to scrape grades for a user.
    Always scrapes the grades and returns the result.
    """
    grades_url = "https://apps.guc.edu.eg/student_ext/Grade/CheckGrade_01.aspx"
    session = requests.Session()
    # Use synchronous NTLM auth
    session.auth = HttpNtlmAuthSync(f"{DOMAIN}\\{username}", password)
    print(f"Scraping grades for {username} from {grades_url}")
    grades = get_grades(session, grades_url, max_retries, retry_delay)
    if grades:
        return grades
    else:
        print(f"scrape_grades returned None for {grades_url}.")
    return None


# --- Attendance Scraping Functions ---
def parse_attendance_course(soup):
    """
    Extracts the attendance table directly from a course-specific POST response.
    Returns a list of attendance records for that course.
    """
    print("Parsing attendance table for a course...")
    attendance_table = soup.find("table", id="DG_StudentCourseAttendance")
    if attendance_table:
        course_attendance = []
        for row in attendance_table.find_all("tr")[1:]:
            cells = row.find_all("td")
            if len(cells) >= 3:
                try:
                    status = cells[1].text.strip() if cells[1].text.strip() else None
                    session_desc = (
                        cells[2].text.strip() if cells[2].text.strip() else None
                    )
                    course_attendance.append(
                        {"status": status, "session": session_desc}
                    )
                except Exception as e:
                    print(f"Error extracting attendance row: {e}")
        return course_attendance
    else:
        print("Attendance table not found in course response.")
        return None


def make_request(
    session, url, method="GET", data=None, max_retries=3, retry_delay=2, timeout=10
):
    """
    Helper function to make GET or POST requests with retry logic.
    """
    for attempt in range(max_retries):
        try:
            if method.upper() == "GET":
                response = session.get(url, timeout=timeout, verify=VERIFY_SSL)
            elif method.upper() == "POST":
                response = session.post(
                    url, data=data, timeout=timeout, verify=VERIFY_SSL
                )
            else:
                print(f"Unsupported method: {method}")
                return None

            # Check for auth failures
            if response.status_code == 401:
                print(f"Authentication failed (401) for {url}")
                return None

            response.raise_for_status()
            return response
        except Exception as e:
            print(f"Request error ({attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
    return None


def get_attendance(session, attendance_url, max_retries=3, retry_delay=2):
    """
    Sequentially fetches and parses attendance data for each course.
    This version closely follows the original working logic but always adds an entry for every course.
    """
    try:
        # First, get the full attendance page
        response = make_request(
            session,
            attendance_url,
            max_retries=max_retries,
            retry_delay=retry_delay,
            timeout=10,
        )
        if not response:
            return None
        soup = BeautifulSoup(response.content, "lxml")
        attendance_data_all_courses = {}
        course_dropdown = soup.find(
            "select", id="ContentPlaceHolderright_ContentPlaceHoldercontent_DDL_Courses"
        )
        if course_dropdown:
            # Extract the hidden form fields from the GET response
            viewstate = soup.find("input", {"name": "__VIEWSTATE"})
            viewstate_gen = soup.find("input", {"name": "__VIEWSTATEGENERATOR"})
            event_validation = soup.find("input", {"name": "__EVENTVALIDATION"})
            if not (viewstate and viewstate_gen and event_validation):
                print("Missing form elements for attendance.")
                return None
            form_base = {
                "__EVENTTARGET": "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$DDL_Courses",
                "__EVENTARGUMENT": "",
                "__LASTFOCUS": "",
                "__VIEWSTATE": viewstate["value"],
                "__VIEWSTATEGENERATOR": viewstate_gen["value"],
                "__EVENTVALIDATION": event_validation["value"],
                "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$H_AlertText": "",
                "ctl00$ctl00$div_position": "0",
            }
            for option in course_dropdown.find_all("option"):
                course_value = option.get("value")
                course_name = option.text.strip()
                if course_value == "0":
                    continue
                print(
                    f"Fetching attendance for course: {course_name} (value {course_value})"
                )
                form_data = form_base.copy()
                form_data[
                    "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$DDL_Courses"
                ] = course_value
                course_response = make_request(
                    session,
                    attendance_url,
                    method="POST",
                    data=form_data,
                    max_retries=max_retries,
                    retry_delay=retry_delay,
                    timeout=10,
                )
                if course_response:
                    course_soup = BeautifulSoup(course_response.content, "lxml")
                    course_attendance = parse_attendance_course(course_soup)
                    # Always add an entry—even if course_attendance is None or empty, use an empty list.
                    attendance_data_all_courses[course_name] = course_attendance or []
            return attendance_data_all_courses
        else:
            print("Course dropdown not found for attendance.")
            return None
    except Exception as e:
        print(f"Error parsing attendance data from {attendance_url}: {e}")
        return None


def extract_v_param(text):
    """
    Extract the dynamic 'v' parameter from a page's text.
    This implementation uses a regex to search for the pattern sTo('...').
    """
    match = re.search(r"sTo\('(.+?)'\)", text)
    if match:
        return match.group(1)
    return None


def fetch_attendance(session, base_attendance_url, username, max_retries, retry_delay):
    """
    Fetches attendance data without using a local cache.
    """
    print(f"Fetching attendance for user '{username}' from {base_attendance_url}")
    response = make_request(
        session,
        base_attendance_url,
        max_retries=max_retries,
        retry_delay=retry_delay,
        timeout=10,
    )
    if not response:
        print("Failed to fetch the base attendance page.")
        return None

    v_param = extract_v_param(response.text)
    if v_param:
        print(f"Extracted 'v' parameter: {v_param}")
        attendance_url = urljoin(base_attendance_url, f"?v={v_param}")
        attendance_data = get_attendance(
            session, attendance_url, max_retries, retry_delay
        )
        print(f"Attendance data for user '{username}': {attendance_data}")
        return attendance_data
    else:
        print("The 'v' parameter was not found in the attendance page.")
        return None


def scrape_attendance(
    username, password, base_attendance_url, max_retries, retry_delay
):
    """
    Main function to scrape attendance data for a user.
    """
    print(
        f"Starting attendance scraping for user '{username}' using URL {base_attendance_url}"
    )
    session = requests.Session()
    # Use synchronous NTLM auth for attendance scraping
    session.auth = HttpNtlmAuthSync(f"{DOMAIN}\\{username}", password)
    attendance_data = fetch_attendance(
        session, base_attendance_url, username, max_retries, retry_delay
    )
    print(f"Final attendance data for user '{username}': {attendance_data}")
    return attendance_data


# --- Helper function to get existing cache data ---
def get_from_cache(key):
    try:
        data = redis_client.get(key)
        if data:
            return json.loads(data.decode("utf-8"))
        return None
    except Exception as e:
        print(f"{datetime.now().isoformat()} - Error getting cache for key {key}: {e}")
        return None


# --- Cache Refresh Logic ---
def refresh_cache():
    print(f"{datetime.now().isoformat()} - Starting cache refresh for all users...")
    stored_users = redis_client.hgetall("user_credentials")
    for username_bytes, encrypted_password_bytes in stored_users.items():
        username = username_bytes.decode()
        encrypted_password = encrypted_password_bytes.decode()
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode().strip()
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - Error decrypting credentials for {username}: {e}"
            )
            continue

        # --- guc_data refresh (asynchronous) ---
        try:
            guc_cache_key = f"guc_data:{username}"
            existing_guc_data = get_from_cache(guc_cache_key)

            scrape_result = asyncio.run(
                async_scrape_guc_data_fast(username, password, GUC_DATA_URLS)
            )

            # Only update cache if we got valid data back
            if scrape_result is not None:
                redis_client.setex(
                    guc_cache_key,
                    1500,
                    json.dumps(scrape_result, ensure_ascii=False).encode("utf-8"),
                )
                print(
                    f"{datetime.now().isoformat()} - GUC Data cache refresh for {username}: updated"
                )
            else:
                print(
                    f"{datetime.now().isoformat()} - GUC Data cache refresh for {username}: skipped due to error, kept existing data"
                )
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - GUC Data cache refresh for {username}: failed"
            )
            traceback.print_exc()

        timings = {
            "0": "8:15AM-9:45AM",
            "1": "10:00AM-11:30AM",
            "2": "11:45AM-1:15PM",
            "3": "1:45PM-3:15PM",
            "4": "3:45PM-5:15PM",
        }
        # --- schedule refresh ---
        try:
            schedule_cache_key = f"schedule:{username}"
            existing_schedule = get_from_cache(schedule_cache_key)

            schedule_result = asyncio.run(
                asyncio.to_thread(
                    scrape_schedule, username, password, BASE_SCHEDULE_URL_CONFIG
                )
            )

            # Only update if we got valid data
            if schedule_result is not None:
                filtered_schedule = filter_schedule_details(
                    schedule_result
                )  # Filter the schedule data
                schedule_response_data = (
                    filtered_schedule,
                    timings,
                )  # Create the same tuple structure
                redis_client.setex(
                    schedule_cache_key,
                    5184000,
                    json.dumps(schedule_response_data, ensure_ascii=False).encode(
                        "utf-8"
                    ),  # Cache the tuple
                )
                print(
                    f"{datetime.now().isoformat()} - Schedule cache refresh for {username}: updated"
                )
            else:
                print(
                    f"{datetime.now().isoformat()} - Schedule cache refresh for {username}: skipped due to error, kept existing data"
                )
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - Schedule cache refresh for {username}: failed"
            )
            traceback.print_exc()

        # --- CMS refresh ---
        try:
            cms_cache_key = f"cms:{username}"
            existing_cms = get_from_cache(cms_cache_key)

            cms_result = asyncio.run(asyncio.to_thread(cms_scraper, username, password))

            # Only update if we got valid data
            if cms_result is not None:
                redis_client.setex(
                    cms_cache_key,
                    2592000,
                    json.dumps(cms_result, ensure_ascii=False).encode("utf-8"),
                )
                print(
                    f"{datetime.now().isoformat()} - CMS cache refresh for {username}: updated"
                )
            else:
                print(
                    f"{datetime.now().isoformat()} - CMS cache refresh for {username}: skipped due to error, kept existing data"
                )
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - CMS cache refresh for {username}: failed"
            )
            traceback.print_exc()

        # --- grades refresh ---
        try:
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
                print(
                    f"{datetime.now().isoformat()} - Grades cache refresh for {username}: updated"
                )
            else:
                print(
                    f"{datetime.now().isoformat()} - Grades cache refresh for {username}: skipped due to error, kept existing data"
                )
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - Grades cache refresh for {username}: failed"
            )
            traceback.print_exc()

        # --- attendance refresh ---
        try:
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
                    json.dumps(attendance_result, ensure_ascii=False).encode("utf-8"),
                )
                print(
                    f"{datetime.now().isoformat()} - Attendance cache refresh for {username}: updated"
                )
            else:
                print(
                    f"{datetime.now().isoformat()} - Attendance cache refresh for {username}: skipped due to error, kept existing data"
                )
        except Exception as e:
            print(
                f"{datetime.now().isoformat()} - Attendance cache refresh for {username}: failed"
            )
            traceback.print_exc()


if __name__ == "__main__":
    refresh_cache()
