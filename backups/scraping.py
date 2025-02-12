# scraping.py
import os
import re
import json
import time
import hashlib
import traceback
from datetime import datetime
from functools import wraps
from urllib.parse import urljoin, urlparse

from dotenv import load_dotenv
import requests
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup
from selectolax.parser import HTMLParser
import redis
import json


load_dotenv()
# In-memory cache for testing (all cache operations use this dictionary)
redis_client = redis.from_url(os.environ.get("REDIS_URL"))


def get_from_app_cache(key):
    """Retrieve data from the Redis cache."""
    cached = redis_client.get(key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            return None
    return None


def set_to_app_cache(key, value, timeout=500):
    """Store data in the Redis cache with an expiry time (in seconds)."""
    redis_client.setex(key, timeout, json.dumps(value))


def calculate_dict_hash(data):
    """Return an MD5 hash of the given dictionary (used for change detection)."""
    return hashlib.md5(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()


# -----------------------------
# GUC Data Scraper Functions
# -----------------------------
def authenticate_user(username, password):
    index_url = "https://apps.guc.edu.eg/student_ext/index.aspx"
    try:
        with requests.Session() as session:
            session.auth = HttpNtlmAuth(username, password)
            response = session.get(index_url, timeout=100)
            if "Welcome" in response.text or response.status_code == 200:
                print(f"Auth Success")
                return True
            else:
                print(f"Auth failed: {response.status_code}")
                return False
    except Exception as e:
        print(f"Error during authentication: {e}")
        return False


def get_notifications(soup, max_retries=3, retry_delay=2):
    """
    Extract notifications from the notifications page.
    Returns a sorted list (by email_time descending) of notification dictionaries.
    """
    notifications = []
    try:
        tree = HTMLParser(str(soup))
        table = tree.css_first(
            "#ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
        )
        if table:
            for row in table.css("tr")[1:]:
                cells = row.css("td")
                if len(cells) >= 6:
                    button = cells[1].css_first("button")
                    # Try to parse the email time; if missing or invalid, use the current time.
                    if button:
                        email_time_str = button.attributes.get("data-email_time", "")
                        try:
                            email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                        except Exception:
                            print(
                                f"Error parsing date '{email_time_str}', using current time."
                            )
                            email_time = datetime.now()
                    else:
                        email_time = datetime.now()
                    notification_data = {
                        "id": cells[0].text(deep=True, separator="").strip(),
                        "title": cells[2].text(deep=True, separator="").strip(),
                        "date": cells[3].text(deep=True, separator="").strip(),
                        "staff": cells[4].text(deep=True, separator="").strip(),
                        "importance": cells[5].text(deep=True, separator="").strip(),
                        "email_time": email_time.isoformat(),
                    }
                    if button:
                        notification_data.update(
                            {
                                "subject": button.attributes.get(
                                    "data-subject_text", ""
                                )
                                .replace("Notification System:", "")
                                .strip(),
                                "body": button.attributes.get("data-body_text", "")
                                .replace("------------------------------", "")
                                .strip(),
                            }
                        )
                    notifications.append(notification_data)
        else:
            print("Notifications table not found in the HTML.")
    except Exception:
        print("Error in get_notifications:")
        print(traceback.format_exc())
    return sorted(notifications, key=lambda x: x["email_time"], reverse=True)


def get_student_info_optimized(soup):
    """
    Extracts student info from the index page using a set of known label IDs.
    Returns a dictionary of student info.
    """
    info = {}
    prefix = "ContentPlaceHolderright_ContentPlaceHoldercontent_Label"
    labels = ["FullName", "UniqAppNo", "UserCode", "Mail", "sg"]
    try:
        tree = HTMLParser(str(soup))
        for label in labels:
            element = tree.css_first(f"#{prefix}{label}")
            info[label.lower()] = (
                element.text(deep=True, separator=" ").strip() if element else ""
            )
    except Exception as e:
        print(f"Error in get_student_info_optimized: {e}")
        return None
    return info


def get_data(
    session,
    target_function,
    target_url,
    max_retries=3,
    retry_delay=2,
    use_selectolax=False,
):
    """
    Fetches the page at target_url and applies target_function to its parsed content.
    Retries up to max_retries times if needed.
    """
    for attempt in range(max_retries):
        try:
            response = session.get(target_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "lxml")
            return target_function(soup)
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt+1}/{max_retries} failed for {target_url}: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
        except Exception as e:
            print(f"Error during processing {target_url}: {e}")
            return None
    return None


def fetch_guc_data_with_cache(
    session, index_url, notifications_url, username, max_retries, retry_delay
):
    """
    Scrapes student info and notifications from the GUC pages.
    Uses in-memory cache keyed by 'student_info_{username}'.
    """
    cache_key = f"student_info_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching GUC data from app cache for {username}")
        return cached_data

    student_info = get_data(
        session, get_student_info_optimized, index_url, max_retries, retry_delay
    )
    if student_info is None:
        return None
    response = session.get(notifications_url, timeout=10)
    soup = BeautifulSoup(response.content, "lxml")
    notifications = get_notifications(soup)
    data = {"student_info": student_info, "notifications": notifications}
    set_to_app_cache(cache_key, data)
    return data


def scrape_guc_data(username, password, max_retries=3, retry_delay=2):
    """
    Main function to scrape GUC data (student info and notifications).
    """
    index_url = "https://apps.guc.edu.eg/student_ext/index.aspx"
    notifications_url = "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx"
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    return fetch_guc_data_with_cache(
        session, index_url, notifications_url, username, max_retries, retry_delay
    )


# -----------------------------
# Schedule Scraper Functions
# -----------------------------
def extract_schedule_data(cell_html):
    """
    Extract course information from an HTML cell in the schedule table.
    Returns a dictionary with Type, Location, and Course_Name.
    """
    if "Free" in cell_html:
        return {"Type": "Free", "Location": "Free", "Course_Name": "Free"}
    tree = HTMLParser(cell_html)
    course_info = {"Type": "Unknown", "Location": "Unknown", "Course_Name": "Unknown"}
    try:
        if "Lecture" in cell_html:
            span = tree.css_first(
                "span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']"
            )
            if span:
                span_text = span.text(deep=True, separator=" ").strip()
                location = span_text[-3:]
                course_info["Location"] = location
                course_info["Course_Name"] = (
                    span_text.replace("Lecture", "").replace(location, "").strip()
                )
                course_info["Type"] = "Lecture"
        elif "Tut" in cell_html or "Lab" in cell_html:
            small_tag = tree.css_first("small")
            if small_tag:
                text_nodes = list(small_tag.parent.itertext(deep=False, separator=" "))
                course_info["Course_Name"] = (
                    text_nodes[0].strip() if text_nodes else "Unknown"
                )
                if len(text_nodes) > 2:
                    course_info["Location"] = text_nodes[2].strip()
                course_info["Type"] = small_tag.text(deep=True, separator=" ").strip()
            else:
                table = tree.css_first("table")
                if table and not table.css_first(
                    "table[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_XaltTbl']"
                ):
                    rows = table.css("tr")
                    if rows:
                        tds = rows[0].css("td")
                        if len(tds) >= 3:
                            course_info["Course_Name"] = (
                                tds[0].text(deep=True, separator=" ").strip()
                                + " "
                                + re.sub(
                                    r"(Tut|Lab)",
                                    "",
                                    tds[2].text(deep=True, separator=" "),
                                    flags=re.I,
                                ).strip()
                            )
                            course_info["Location"] = (
                                tds[1].text(deep=True, separator=" ").strip()
                            )
                            type_match = re.search(
                                r"(Tut|Lab)", tds[2].text(deep=True, separator=" ")
                            )
                            course_info["Type"] = (
                                type_match.group(0).capitalize()
                                if type_match
                                else "Unknown"
                            )
                elif table and table.css_first(
                    "table[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_XaltTbl']"
                ):
                    span = tree.css_first(
                        "span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']"
                    )
                    if span:
                        span_text = span.text(deep=True, separator=" ").strip()
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


def scrape_schedule_from_html(soup):
    """
    Extracts the schedule data from the HTML.
    Returns a dictionary keyed by day with sub-dictionaries for each period.
    """
    tree = HTMLParser(str(soup))
    schedule = {}
    rows = tree.css("tr[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xrw']")
    period_names = [
        "First Period",
        "Second Period",
        "Third Period",
        "Fourth Period",
        "Fifth Period",
    ]
    for row in rows:
        try:
            day = (
                row.css_first("td[align='center']")
                .text(deep=True, separator=" ")
                .strip()
            )
            periods = row.css("td[width='180']")
            day_schedule = {}
            for i, period in enumerate(periods):
                if i < len(period_names):
                    cell_data = extract_schedule_data(period.html)
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


def fetch_schedule_with_cache(
    session, base_schedule_url, username, max_retries, retry_delay
):
    """
    Fetches the schedule data using the provided base URL.
    Uses in-memory caching keyed by 'schedule_data_{username}'.
    """
    cache_key = f"schedule_data_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching schedule data from app cache for {username}")
        return cached_data
    try:
        response = session.get(base_schedule_url, timeout=10)
        response.raise_for_status()
        match = re.search(r"sTo\('(.+?)'\)", response.text)
        if match:
            v_param = match.group(1)
            schedule_url = urljoin(base_schedule_url, f"?v={v_param}")
            schedule_data = get_data(
                session,
                scrape_schedule_from_html,
                schedule_url,
                max_retries,
                retry_delay,
            )
            if schedule_data:
                set_to_app_cache(cache_key, schedule_data, timeout=600)
                return schedule_data
            else:
                return None
        else:
            print("Could not extract 'v' parameter for schedule.")
            return None
    except Exception as e:
        print(f"Error during schedule request: {e}")
        return None


def scrape_schedule(username, password, base_schedule_url, max_retries, retry_delay):
    """
    Main function to scrape the schedule.
    """
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    return fetch_schedule_with_cache(
        session, base_schedule_url, username, max_retries, retry_delay
    )


# -----------------------------
# CMS Scraper Functions
# -----------------------------
def fetch_cms_courses(session, username, cms_url, max_retries, retry_delay):
    """
    Fetches CMS courses from the CMS home page.
    """
    cache_key = f"cms_courses_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching CMS courses data from app cache for {username}")
        return cached_data
    try:
        print(f"Initializing CMS authentication to Home page with URL: {cms_url}")
        response = session.get(cms_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        courses = []
        table = soup.find(
            id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewcourses"
        )
        if table:
            for row in table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) >= 6:
                    course_name = cells[1].text.strip()
                    course_id = cells[4].text.strip()
                    season_id = cells[5].text.strip()
                    course_url = f"https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id={course_id}&sid={season_id}"
                    courses.append(
                        {"course_name": course_name, "course_url": course_url}
                    )
        else:
            print(f"CMS courses table not found for URL: {cms_url}")
        if courses:
            set_to_app_cache(cache_key, courses, timeout=604800)
            return courses
        return courses
    except Exception as e:
        print(f"Error fetching CMS courses: {e}")
        return None


def get_course_content_data(session, course_url):
    """
    Fetches detailed course content from a specific CMS course URL.
    """
    try:
        print(f"Fetching course content from: {course_url}")
        response = session.get(course_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        all_weeks_data = []
        weeks = soup.find_all("div", class_="card mb-5 weeksdata")
        if not weeks:
            print(f"No weeks data found on {course_url}")
            return None
        for week in weeks:
            header = week.find("h2", class_="text-big")
            week_name = header.text.strip() if header else "Not Provided"
            contents = []
            content_cards = week.find_all("div", class_="card mb-4")
            for card in content_cards:
                title_div = card.find(id=re.compile(r"content\d+"))
                download_btn = card.find("a", class_="btn btn-primary contentbtn")
                if title_div:
                    title = title_div.text.strip()
                    download_link = (
                        download_btn["href"]
                        if download_btn and "href" in download_btn.attrs
                        else None
                    )
                    contents.append({"title": title, "download_url": download_link})
                else:
                    print(
                        f"Could not find proper elements in course content at {course_url}"
                    )
            all_weeks_data.append({"week_name": week_name, "contents": contents})
        print(f"Successfully fetched course content from {course_url}")
        return all_weeks_data
    except Exception as e:
        print(f"Error fetching course content: {e}")
        return None


def cms_scraper(username, password, course_url=None, max_retries=3, retry_delay=2):
    """
    Main function to scrape CMS data.
    If course_url is provided, fetch content for that course.
    Otherwise, fetch all courses from the CMS home page.
    """
    cms_url = "https://cms.guc.edu.eg/apps/student/HomePageStn"
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    if course_url:
        print(f"Fetching specific CMS content from: {course_url}")
        course_content = get_course_content_data(session, course_url)
        return course_content if course_content else None
    else:
        print("Fetching all CMS courses data")
        return fetch_cms_courses(session, username, cms_url, max_retries, retry_delay)


# -----------------------------
# Grades Scraper Functions
# -----------------------------
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
            response = session.get(grades_url, timeout=10)
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
                        subject_grades_url, data=form_data, timeout=10
                    )
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
    Caches the result in-memory.
    """
    grades_url = "https://apps.guc.edu.eg/student_ext/Grade/CheckGrade_01.aspx"
    cache_key = f"grades_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching grades data from app cache for {username}")
        return cached_data
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    print(f"Scraping grades for {username} from {grades_url}")
    grades = get_grades(session, grades_url, max_retries, retry_delay)
    if grades:
        set_to_app_cache(cache_key, grades)
        return grades
    else:
        print(f"scrape_grades returned None for {grades_url}.")
    return grades


# -----------------------------
# Attendance Scraper Functions
# -----------------------------
def scrape_attendance_from_html(soup):
    """
    Extracts attendance data from the attendance page.
    Returns a dictionary where each key is a course name and the value is a list of attendance records.
    """
    attendance_data = {}
    course_dropdown = soup.find(
        "select", id="ContentPlaceHolderright_ContentPlaceHoldercontent_DDL_Courses"
    )
    if course_dropdown:
        for option in course_dropdown.find_all("option"):
            course_name = option.text.strip()
            if course_name == "[Choose Course]":
                continue
            attendance_table = soup.find("table", id="DG_StudentCourseAttendance")
            if attendance_table:
                course_attendance = []
                for row in attendance_table.find_all("tr")[1:]:
                    cells = row.find_all("td")
                    if len(cells) >= 3:
                        try:
                            status = (
                                cells[1].text.strip() if cells[1].text.strip() else None
                            )
                            session_desc = (
                                cells[2].text.strip() if cells[2].text.strip() else None
                            )
                            course_attendance.append(
                                {"status": status, "session": session_desc}
                            )
                        except Exception as e:
                            print(f"Error extracting attendance: {e}")
                    else:
                        print(
                            f"Skipping attendance row for {course_name} due to insufficient cells."
                        )
                attendance_data[course_name] = course_attendance
            else:
                print(f"Attendance table not found for {course_name}.")
    else:
        print("Course dropdown not found for attendance.")
    return attendance_data


def get_attendance(session, attendance_url, max_retries=3, retry_delay=2):
    """
    Fetches and parses attendance data for all courses.
    """
    try:
        response = session.get(attendance_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "lxml")
        attendance_data_all_courses = {}
        course_dropdown = soup.find(
            "select", id="ContentPlaceHolderright_ContentPlaceHoldercontent_DDL_Courses"
        )
        if course_dropdown:
            for option in course_dropdown.find_all("option"):
                course_value = option["value"]
                course_name = option.text.strip()
                if course_value == "0":
                    continue
                print(
                    f"Fetching attendance for course: {course_name} (value {course_value})"
                )
                form_data = {
                    "__EVENTTARGET": "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$DDL_Courses",
                    "__EVENTARGUMENT": "",
                    "__LASTFOCUS": "",
                    "__VIEWSTATE": soup.find("input", {"name": "__VIEWSTATE"})["value"],
                    "__VIEWSTATEGENERATOR": soup.find(
                        "input", {"name": "__VIEWSTATEGENERATOR"}
                    )["value"],
                    "__EVENTVALIDATION": soup.find(
                        "input", {"name": "__EVENTVALIDATION"}
                    )["value"],
                    "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$DDL_Courses": course_value,
                    "ctl00$ctl00$ContentPlaceHolderright$ContentPlaceHoldercontent$H_AlertText": "",
                    "ctl00$ctl00$div_position": "0",
                }
                response = session.post(attendance_url, data=form_data, timeout=10)
                response.raise_for_status()
                subject_soup = BeautifulSoup(response.content, "lxml")
                attendance_for_course = scrape_attendance_from_html(subject_soup)
                if course_name in attendance_for_course:
                    attendance_data_all_courses[course_name] = attendance_for_course[
                        course_name
                    ]
        return attendance_data_all_courses
    except requests.exceptions.RequestException as e:
        print(f"Network error for attendance URL {attendance_url}: {e}")
        return None
    except Exception as e:
        print(f"Error parsing attendance data from {attendance_url}: {e}")
        return None


def fetch_attendance_with_cache(
    session, base_attendance_url, username, max_retries, retry_delay
):
    """
    Fetches attendance data using the base attendance URL.
    Uses in-memory caching keyed by 'attendance_data_{username}'.
    """
    cache_key = f"attendance_data_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching attendance data from app cache for {username}")
        return cached_data
    try:
        response = session.get(base_attendance_url, timeout=10)
        response.raise_for_status()
        match = re.search(r"sTo\('(.+?)'\)", response.text)
        if match:
            v_param = match.group(1)
            attendance_url = urljoin(base_attendance_url, f"?v={v_param}")
            attendance_data = get_attendance(
                session, attendance_url, max_retries, retry_delay
            )
            if attendance_data:
                set_to_app_cache(cache_key, attendance_data, timeout=600)
                return attendance_data
            else:
                return None
        else:
            print("Could not extract 'v' parameter for attendance.")
            return None
    except Exception as e:
        print(f"Error during attendance request: {e}")
        return None


def scrape_attendance(
    username, password, base_attendance_url, max_retries, retry_delay
):
    """
    Main function to scrape attendance data for a user.
    """
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    return fetch_attendance_with_cache(
        session, base_attendance_url, username, max_retries, retry_delay
    )


# -----------------------------
# Exam Seats Scraper Functions
# -----------------------------
def scrape_exam_seats_from_html(soup):
    """
    Extracts exam seat information from the exam seats page.
    Returns a list of exam seat records sorted by date and start time.
    """
    exam_seats = []
    try:
        table = soup.find("table", {"id": "Table2"})
        if not table:
            print("Exam seats table not found.")
            return exam_seats
        for row in table.find_all("tr")[1:]:
            cells = row.find_all("td")
            if len(cells) >= 8:
                try:
                    exam_seat = {
                        "course": cells[0].text.strip(),
                        "date": cells[2].text.strip(),
                        "end_time": cells[4].text.strip(),
                        "exam_day": cells[1].text.strip(),
                        "hall": cells[5].text.strip(),
                        "season": cells[0].text.strip().split(" - ")[-1],
                        "seat": cells[6].text.strip(),
                        "start_time": cells[3].text.strip(),
                        "type": cells[7].text.strip(),
                    }
                    exam_seats.append(exam_seat)
                except Exception as e:
                    print(f"Error parsing exam seat row: {e}")
                    continue
        exam_seats.sort(
            key=lambda x: (
                datetime.strptime(x["date"], "%d - %B - %Y"),
                datetime.strptime(x["start_time"], "%I:%M:%S %p").time(),
            )
        )
    except Exception as e:
        print(f"Error extracting exam seats: {e}")
    return exam_seats


def scrape_exam_seats(username, password, max_retries=3, retry_delay=2):
    """
    Main function to scrape exam seats information.
    Uses in-memory caching keyed by 'exam_seats_{username}'.
    """
    exam_seats_url = "https://apps.guc.edu.eg/student_ext/Exam/ViewExamSeat_01.aspx"
    cache_key = f"exam_seats_{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Fetching exam seats data from app cache for {username}")
        return cached_data
    session = requests.Session()
    session.auth = HttpNtlmAuth(username, password)
    for attempt in range(max_retries):
        try:
            response = session.get(exam_seats_url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "lxml")
            seats_data = scrape_exam_seats_from_html(soup)
            if seats_data:
                set_to_app_cache(cache_key, seats_data)
                return seats_data
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt+1} for exam seats failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
    return None
