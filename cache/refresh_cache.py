import asyncio
import json
import traceback
from datetime import datetime
import os
import redis
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import httpx
from httpx_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup

# Load environment variables from .env file (or GitHub Action secrets)
load_dotenv()

REDIS_URL = os.environ.get("REDIS_URL")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not REDIS_URL or not ENCRYPTION_KEY:
    raise Exception("REDIS_URL and ENCRYPTION_KEY must be set.")

# Initialize Redis and encryption engine
redis_client = redis.from_url(REDIS_URL)
fernet = Fernet(ENCRYPTION_KEY)

# Configuration for scraping
GUC_DATA_URLS = [
    "https://apps.guc.edu.eg/student_ext/index.aspx",
    "https://apps.guc.edu.eg/student_ext/Main/Notifications.aspx",
]
DOMAIN = "GUC"  # assumed constant


# --- HTML Parsing Functions ---
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
        id="ContentPlaceHolderright_ContentPlaceHoldercontent_GridViewdata"
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
                        f"Error parsing email_time '{email_time_str}': {e}. Using current time."
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
        print("Notifications table not found in the HTML.")
    notifications.sort(key=lambda x: x["email_time"], reverse=True)
    return notifications


# --- Asynchronous Scraping Function ---
async def async_scrape_guc_data_fast(username, password, urls):
    auth = HttpNtlmAuth(f"{DOMAIN}\\{username}", password)
    async with httpx.AsyncClient(auth=auth, timeout=10.0) as client:
        tasks = [client.get(url) for url in urls]
        responses = await asyncio.gather(*tasks)
        htmls = {url: response.text for url, response in zip(urls, responses)}
    student_html = htmls[urls[0]]
    notif_html = htmls[urls[1]]
    student_info = parse_student_info(student_html)
    notifications = parse_notifications(notif_html)
    return {"notifications": notifications, "student_info": student_info}


# --- Cache Refresh Logic ---
def refresh_cache():
    print(f"{datetime.now().isoformat()} - Starting cache refresh for all users...")
    stored_users = redis_client.hgetall(
        "user_credentials"
    )  # {username: encrypted_password, ...}
    for username_bytes, encrypted_password_bytes in stored_users.items():
        username = username_bytes.decode()
        encrypted_password = encrypted_password_bytes.decode()
        try:
            password = fernet.decrypt(encrypted_password.encode()).decode().strip()
        except Exception as e:
            print(f"Error decrypting credentials for {username}: {e}")
            continue

        try:
            scrape_result = asyncio.run(
                async_scrape_guc_data_fast(username, password, GUC_DATA_URLS)
            )
            cache_key = f"guc_data:{username}"
            # Cache for 10 minutes (600 seconds)
            redis_client.setex(
                cache_key,
                900,
                json.dumps(scrape_result, ensure_ascii=False).encode("utf-8"),
            )
            print(
                f"{datetime.now().isoformat()} - Cache refreshed for user: {username}"
            )
        except Exception as e:
            print(f"Error refreshing cache for {username}: {e}")
            traceback.print_exc()


if __name__ == "__main__":
    refresh_cache()
