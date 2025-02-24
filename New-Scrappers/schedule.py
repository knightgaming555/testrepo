import re
import requests
from requests_ntlm import HttpNtlmAuth
from time import perf_counter
from bs4 import BeautifulSoup
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3
warnings.simplefilter("ignore", InsecureRequestWarning)


def extract_schedule_data(cell_html):
    """Extracts schedule data from a single table cell HTML using BeautifulSoup (based on user's logic)."""
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
    """Parses the schedule HTML using BeautifulSoup and CSS selectors (based on user's logic)."""
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
    """Schedule scraper adapted for JavaScript redirection and BeautifulSoup parsing."""
    try:
        with requests.Session() as session:
            session.auth = HttpNtlmAuth(username, password)

            start = perf_counter()
            res = session.get(base_url, timeout=10, verify=False)

            if res.status_code != 200:
                return {"error": f"Initial request failed ({res.status_code})"}, 0

            js_redirect_pattern = re.compile(r"sTo\('([a-f0-9-]+)'\)", re.IGNORECASE)
            js_match = js_redirect_pattern.search(res.text)

            if not js_match:
                return {
                    "error": "Failed to find JavaScript redirect parameter 'v'"
                }, perf_counter() - start

            v_parameter_value = js_match.group(1)
            schedule_url = f"{base_url}?v={v_parameter_value}"
            schedule_res = session.get(schedule_url, timeout=10, verify=False)

            with open("schedule_page_content_bs4.html", "w", encoding="utf-8") as f:
                f.write(schedule_res.text)
            print("Schedule page HTML saved to schedule_page_content_bs4.html")

            return (
                parse_schedule_bs4(schedule_res.text),
                perf_counter() - start,
            )  # Use the new BS4 parser!

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


if __name__ == "__main__":
    USERNAME = "mohamed.elsaadi"
    PASSWORD = "Messo@1245"
    BASE_URL = "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx"

    print(
        "Fetching schedule with BeautifulSoup parser (NO CACHE) ..."
    )  # Updated print statement

    result, elapsed = scrape_schedule(
        USERNAME, PASSWORD, BASE_URL
    )  # No cache parameters

    if "error" in result:
        print(f"Error: {result['error']}")
    else:
        print(
            f"\nSchedule fetched in {elapsed:.3f}s using BeautifulSoup (NO CACHE)"
        )  # Updated print statement

        # full_schedule = result # Commenting out full schedule for cleaner output
        filtered_schedule = filter_schedule_details(result)

        # print("\nFull Parsed Schedule Data (BeautifulSoup Parser):") # Commenting out full schedule for cleaner output
        # for day, periods in full_schedule.items(): # Commenting out full schedule for cleaner output
        #     print(f"\n--- {day} ---") # Commenting out full schedule for cleaner output
        #     for period, details in periods.items(): # Commenting out full schedule for cleaner output
        #         print(f"{period}: {details}") # Commenting out full schedule for cleaner output

        print("\nFiltered Schedule (Course, Type, Location, BeautifulSoup Parser):")
        for day, periods in filtered_schedule.items():
            print(f"\n--- {day} ---")
            for period, details in periods.items():
                print(f"{period}: {details}")
