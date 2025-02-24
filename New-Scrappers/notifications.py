import pycurl
from io import BytesIO
from time import perf_counter
from bs4 import BeautifulSoup
from datetime import datetime
import json
import traceback


def multi_fetch(urls, userpwd):
    # Prepare a multi handle and a dictionary to store buffers.
    multi = pycurl.CurlMulti()
    handles = []
    buffers = {}

    # Set up an easy handle for each URL.
    for url in urls:
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.HTTPAUTH, c.HTTPAUTH_NTLM)
        c.setopt(c.USERPWD, userpwd)  # Format: "DOMAIN\\username:password"
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.FOLLOWLOCATION, True)
        multi.add_handle(c)
        handles.append(c)
        buffers[url] = buffer

    # Perform the requests concurrently.
    num_handles = len(handles)
    while num_handles:
        ret, num_handles = multi.perform()
        multi.select(1.0)

    # After completion, extract content and clean up.
    results = {}
    for url, c in zip(urls, handles):
        results[url] = buffers[url].getvalue().decode("utf-8", errors="replace")
        multi.remove_handle(c)
        c.close()
    multi.close()
    return results


def parse_student_info(html):
    """Parses the student info page HTML and returns a dict with keys:
    fullname, uniqappno, usercode, mail, sg.
    """
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
        if element:
            text = element.get_text(" ", strip=True).replace("\r", "")
            info[key] = text
        else:
            info[key] = ""
    return info


def parse_notifications(html):
    """Parses the notifications page HTML and returns a list of notifications.
    Each notification is a dict with keys:
    id, title, date, staff, importance, email_time, subject, body.
    """
    soup = BeautifulSoup(html, "lxml")
    notifications = []
    table = soup.find(
        id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
    )
    if table:
        rows = table.find_all("tr")[1:]  # skip header row
        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 6:
                continue
            notif = {}
            notif["id"] = cells[0].get_text(" ", strip=True).replace("\r", "")
            notif["title"] = cells[2].get_text(" ", strip=True).replace("\r", "")
            notif["date"] = cells[3].get_text(" ", strip=True).replace("\r", "")
            notif["staff"] = cells[4].get_text(" ", strip=True).replace("\r", "")
            notif["importance"] = cells[5].get_text(" ", strip=True).replace("\r", "")
            button = cells[1].find("button")
            if button:
                email_time_str = button.get("data-email_time", "")
                try:
                    email_time = datetime.strptime(email_time_str, "%m/%d/%Y")
                    notif["email_time"] = email_time.isoformat()
                except Exception as e:
                    print(
                        f"Error parsing email_time '{email_time_str}': {e}. Using current time."
                    )
                    notif["email_time"] = datetime.now().isoformat()
                subject = (
                    button.get("data-subject_text", "")
                    .replace("Notification System:", "")
                    .strip()
                    .replace("\r", "")
                )
                body = (
                    button.get("data-body_text", "")
                    .replace("------------------------------", "")
                    .strip()
                    .replace("\r", "")
                )
                notif["subject"] = subject
                notif["body"] = body
            else:
                notif["email_time"] = datetime.now().isoformat()
                notif["subject"] = ""
                notif["body"] = ""
            notifications.append(notif)
    else:
        print("Notifications table not found in the HTML.")
    # Sort notifications by email_time (latest first)
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


def main():
    urls = [
        "https://apps.guc.edu.eg/student_ext/index.aspx",
        "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx",
    ]
    # Replace with your actual credentials (include domain)
    userpwd = "GUC\\mohamed.elsaadi:Messo@1245"

    start = perf_counter()
    try:
        results = multi_fetch(urls, userpwd)
    except Exception as e:
        print("Error fetching pages:")
        traceback.print_exc()
        return
    elapsed = perf_counter() - start

    student_html = results[urls[0]]
    notif_html = results[urls[1]]

    student_info = parse_student_info(student_html)
    notifications = parse_notifications(notif_html)

    # Build final output in exact format
    output = {"notifications": notifications, "student_info": student_info}

    # Output as formatted JSON
    print(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"\nScraping completed in {elapsed:.3f}s")


if __name__ == "__main__":
    main()
