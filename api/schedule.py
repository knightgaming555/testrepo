import re
import json
import requests
from requests_ntlm import HttpNtlmAuth
from time import perf_counter
from bs4 import BeautifulSoup
import warnings
from urllib3.exceptions import InsecureRequestWarning
from flask import Flask, request, jsonify, g 
from datetime import datetime, timezone
import redis
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
# Use ThreadPoolExecutor for efficient background tasks
import concurrent.futures 
import logging

# Load environment variables
load_dotenv()

# --- Initialize Redis, Fernet, Constants ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True) 
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable not set")
fernet = Fernet(ENCRYPTION_KEY.encode()) 

BASE_URL = "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx"
timings = {
    "0": "8:15AM-9:45AM", "1": "10:00AM-11:30AM", "2": "11:45AM-1:15PM",
    "3": "1:45PM-3:15PM", "4": "3:45PM-5:15PM",
}
warnings.simplefilter("ignore", InsecureRequestWarning)
LONG_CACHE_TIMEOUT = 5184000

API_LOG_KEY = "api_logs"
MAX_LOG_ENTRIES = 1000

# --- Thread Pool for Background Logging ---
# Initialize the executor globally so it persists across requests within the same process/instance
# Use a small number of workers as logging is I/O bound, not CPU bound.
# max_workers=5 should be plenty; adjust if needed based on expected load.
# The default thread name prefix helps identify log threads if debugging.
log_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix='LogThread')

# --- Cache Utilities (Keep as before) ---
def get_from_app_cache(key):
    try:
        cached = redis_client.get(key)
        if cached:
            return json.loads(cached) 
    except redis.exceptions.ConnectionError as e:
         print(f"[Cache] Redis connection error on get '{key}': {e}")
    except Exception as e:
        print(f"[Cache] Get error for key '{key}': {e}")
    return None

def set_to_app_cache(key, value, timeout=LONG_CACHE_TIMEOUT):
    try:
        redis_client.setex(key, timeout, json.dumps(value))
    except redis.exceptions.ConnectionError as e:
         print(f"[Cache] Redis connection error on set '{key}': {e}")
    except Exception as e:
        print(f"[Cache] Set error for key '{key}': {e}")


# --- Scraping Functions (Keep extract_schedule_data, parse_schedule_bs4, scrape_schedule, filter_schedule_details as before) ---
# ... (extract_schedule_data function remains the same) ...
def extract_schedule_data(cell_html):
    """Extracts schedule data from a single table cell HTML using BeautifulSoup."""
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
                # Handle cases like H10.11 (5 chars) or just H10 (3 chars)
                location_match = re.search(r'([A-Z]\d+(\.\d+)?)$', span_text)
                location = location_match.group(1) if location_match else "Unknown"
                course_info["Location"] = location
                course_name_part = span_text.replace("Lecture", "").strip()
                # Remove location from the end if found
                if location != "Unknown" and course_name_part.endswith(location):
                     course_info["Course_Name"] = course_name_part[:-len(location)].strip()
                else:
                     course_info["Course_Name"] = course_name_part

                course_info["Type"] = "Lecture"

        elif "Tut" in cell_html or "Lab" in cell_html:
            small_tag = soup.select_one("small")
            if small_tag:
                text_nodes = [text for text in small_tag.parent.stripped_strings]
                course_info["Course_Name"] = (
                    text_nodes[0].strip() if text_nodes else "Unknown"
                )
                # Location might be the last element if present
                if len(text_nodes) > 1 and re.match(r'^[A-Z]\d+(\.\d+)?$', text_nodes[-1].strip()):
                    course_info["Location"] = text_nodes[-1].strip()
                elif len(text_nodes) > 2: # Fallback for older structure?
                     course_info["Location"] = text_nodes[2].strip()

                course_info["Type"] = small_tag.get_text(separator=" ", strip=True)

            # Handling the alternative table structure within a cell (often for Labs/Tuts)
            elif soup.select_one("table td"): # Check if there's a table with data
                 tds = soup.select("table td")
                 if tds:
                    course_name = tds[0].get_text(strip=True)
                    location = "Unknown"
                    type_str = "Unknown"

                    if len(tds) > 1:
                        # Location is often in the second td
                        loc_text = tds[1].get_text(strip=True)
                        if re.match(r'^[A-Z]\d+(\.\d+)?$', loc_text):
                             location = loc_text

                    if len(tds) > 2:
                        # Type is often in the third td
                        type_text = tds[2].get_text(strip=True)
                        type_match = re.search(r"(Tut|Lab)", type_text, re.IGNORECASE)
                        if type_match:
                            type_str = type_match.group(0).capitalize()
                            # Append the number/group if present (e.g., Tut 1)
                            numeric_part = re.sub(r"(Tut|Lab)", "", type_text, flags=re.IGNORECASE).strip()
                            if numeric_part:
                                course_name += f" {numeric_part}" # Append group to course name

                    course_info["Course_Name"] = course_name
                    course_info["Location"] = location
                    course_info["Type"] = type_str


            # Special case for alternative Lecture format (sometimes seen with conflicts?)
            elif soup.select_one("span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']"):
                 span = soup.select_one("span[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xlbl']")
                 span_text = span.get_text(separator=" ", strip=True)
                 location_match = re.search(r'([A-Z]\d+(\.\d+)?)$', span_text)
                 location = location_match.group(1) if location_match else "Unknown"
                 course_info["Location"] = location
                 course_name_part = span_text.replace("Lecture", "").strip()
                 if location != "Unknown" and course_name_part.endswith(location):
                     course_info["Course_Name"] = course_name_part[:-len(location)].strip()
                 else:
                    course_info["Course_Name"] = course_name_part
                 course_info["Type"] = "Lecture"

    except Exception as e:
        # Log the specific cell HTML causing the error for debugging
        print(f"Error extracting schedule data from cell: {cell_html}. Error: {e}")

    # Final check for consistency
    if course_info["Course_Name"] == "Unknown" and course_info["Type"] != "Free":
         # If we couldn't parse but it's not marked Free, log cell content
         plain_text = soup.get_text(separator=" ", strip=True)
         print(f"Couldn't fully parse cell, setting Course_Name to text content: '{plain_text}'. Cell HTML: {cell_html}")
         # Use plain text as a fallback Course_Name if nothing else worked
         if plain_text:
              course_info["Course_Name"] = plain_text


    return course_info

# ... (parse_schedule_bs4 function remains the same) ...
def parse_schedule_bs4(html):
    """Parses the schedule HTML using BeautifulSoup and CSS selectors."""
    soup = BeautifulSoup(html, "lxml")
    schedule = {}
    # Correct selector targeting rows with specific ID prefix *within the content table*
    # Find the main schedule table first if its ID is consistent
    schedule_table = soup.find('table', id=lambda x: x and x.endswith('_XtblSched'))
    if not schedule_table:
        print("Error: Could not find the main schedule table.")
        # Attempt broader search as fallback, might be less reliable
        rows = soup.select("tr[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xrw']")
        if not rows:
             print("Error: Could not find any schedule rows.")
             return {} # Return empty if no table or rows found
    else:
         rows = schedule_table.select("tr[id^='ContentPlaceHolderright_ContentPlaceHoldercontent_Xrw']")


    period_names = [
        "First Period",
        "Second Period",
        "Third Period",
        "Fourth Period",
        "Fifth Period",
    ]
    for row in rows:
        try:
            # Day cell is typically the first `td` in these rows
            day_cell = row.find("td", align="center", valign="middle", width="80") # More specific selector
            if not day_cell:
                day_cell = row.find("td") # Fallback to first td if specific one not found

            day = (
                day_cell.get_text(separator=" ", strip=True)
                if day_cell
                else "Unknown Day"
            )

            # Period cells are typically marked with width='180'
            periods = row.select("td[width='180']")
            if not periods : # Fallback if width attribute isn't present/correct
                # Select all direct child TDs excluding the first one (assumed day cell)
                period_cells_all = row.find_all('td', recursive=False)
                if day_cell and period_cells_all and period_cells_all[0] == day_cell:
                     periods = period_cells_all[1:] # Exclude the day cell if it was the first
                else:
                     periods = period_cells_all # Use all if day cell wasn't first or found

            day_schedule = {}
            for i, period_cell in enumerate(periods):
                if i < len(period_names): # Ensure we don't go out of bounds for period_names
                    cell_data = extract_schedule_data(str(period_cell))
                    day_schedule[period_names[i]] = (
                        cell_data
                        if cell_data # Should always return a dict now
                        else {"Type": "Error", "Location": "Error", "Course_Name": "Parsing Failed"}
                    )
            # Only add day if it has some schedule data
            if day_schedule and day != "Unknown Day":
                 schedule[day] = day_schedule
            elif day != "Unknown Day":
                 print(f"Warning: No period data found for day '{day}' in row: {row}")


        except Exception as e:
            print(f"Error processing schedule row: {row}. Error: {e}")

    day_order = ["Saturday", "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday"]
    sorted_schedule = {
        day: schedule.get(day, {}) for day in day_order if day in schedule
    }

    # Basic validation: Check if we got any valid days
    if not sorted_schedule:
         print("Warning: Parsing finished, but no valid schedule days were extracted.")
         # Potentially return an error indicator or log the raw HTML for debugging
         # For now, returning the empty dict as before.
         # Consider adding: return {"error": "Failed to parse schedule structure", "html_preview": html[:500]}

    return sorted_schedule
# ... (scrape_schedule function remains the same) ...
def scrape_schedule(username, password, base_url):
    """Scrapes schedule data with NTLM authentication and JavaScript redirection."""
    try:
        with requests.Session() as session:
            session.auth = HttpNtlmAuth(username, password)
            # Explicitly disable SSL verification for GUC site
            res = session.get(base_url, timeout=20, verify=False) 
            res.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Check for login failure indicators before redirect logic
            if "Login Failed!" in res.text or "Object moved" in res.text:
                 # Check if the redirect is back to the login page explicitly
                 soup_login_check = BeautifulSoup(res.text, 'lxml')
                 if soup_login_check.find('a', href='../External/Login.aspx'):
                      return {"error": "Authentication failed (likely wrong credentials)"}
                 # Otherwise, it might be a different issue but still indicates failure
                 return {"error": "Authentication failed or unexpected page state"}


            js_redirect_pattern = re.compile(r"sTo\('([a-f0-9-]+)'\)", re.IGNORECASE)
            js_match = js_redirect_pattern.search(res.text)

            if not js_match:
                # Check if we are already on the schedule page (sometimes happens)
                soup_schedule_check = BeautifulSoup(res.text, 'lxml')
                if soup_schedule_check.find('table', id=lambda x: x and x.endswith('_XtblSched')):
                    print("Already on schedule page, proceeding with parsing.")
                    scraped = parse_schedule_bs4(res.text)
                    if not scraped: # If parsing fails even if table is found
                         return {"error": "Found schedule table but failed to parse content."}
                    return scraped
                else:
                    # Log part of the unexpected HTML for debugging
                    html_preview = res.text[:500].replace('\n', ' ')
                    print(f"Failed to find JavaScript redirect 'v' parameter. HTML preview: {html_preview}")
                    return {"error": "Failed to find JavaScript redirect parameter 'v'"}

            v_parameter_value = js_match.group(1)
            schedule_url = f"{base_url}?v={v_parameter_value}"
            schedule_res = session.get(schedule_url, timeout=20, verify=False)
            schedule_res.raise_for_status() # Check status of the second request

            # Additional check after getting schedule page
            if "Login Failed!" in schedule_res.text or "Object moved" in schedule_res.text:
                 return {"error": "Authentication failed after redirect (session issue?)"}

            scraped = parse_schedule_bs4(schedule_res.text)
             # Check if parsing returned an empty dict, indicating failure inside parse_schedule_bs4
            if not scraped:
                 return {"error": "Successfully fetched schedule page, but failed to parse its content."}

            return scraped

    except requests.exceptions.Timeout:
        return {"error": "Request timed out connecting to GUC server."}
    except requests.exceptions.ConnectionError as e:
         return {"error": f"Connection error: {e}"}
    except requests.exceptions.HTTPError as e:
         # Include status code in the error if possible
        status_code = e.response.status_code if e.response is not None else "N/A"
        # Check for specific GUC error patterns if needed
        if status_code == 500 and "RuntimeException" in e.response.text:
             return {"error": f"GUC Server Error ({status_code}): RuntimeException. Please try again later."}
        return {"error": f"HTTP error: {status_code} - {e}"}
    except Exception as e:
        # Catch-all for other unexpected errors during scraping
        return {"error": f"An unexpected error occurred during scraping: {e}"}
# ... (filter_schedule_details function remains the same) ...
def filter_schedule_details(schedule_data):
    """Filters the parsed schedule to only include course, type, and location."""
    filtered_schedule = {}
    for day, periods in schedule_data.items():
        filtered_periods = {}
        for period_name, period_details in periods.items():
            # Ensure period_details is a dictionary before accessing keys
            if isinstance(period_details, dict):
                filtered_periods[period_name] = {
                    "Course_Name": period_details.get("Course_Name", "N/A"),
                    "Type": period_details.get("Type", "N/A"),
                    "Location": period_details.get("Location", "N/A"),
                }
            else:
                 # Log unexpected data format
                 print(f"Warning: Unexpected data format for period '{period_name}' on '{day}': {period_details}")
                 filtered_periods[period_name] = { # Provide a default error structure
                      "Course_Name": "Error",
                      "Type": "Error",
                      "Location": "Invalid Data"
                 }
        filtered_schedule[day] = filtered_periods
    return filtered_schedule
# --- Credential/Activity Functions (Keep as before) ---
# ... (get_all_stored_users function remains the same) ...
def get_all_stored_users():
    try:
        stored = redis_client.hgetall("user_credentials")
        return stored 
    except redis.exceptions.ConnectionError as e:
        print(f"Error getting stored users from Redis (connection): {e}")
        return {}
    except Exception as e:
        print(f"Error getting stored users from Redis: {e}")
        return {}
# ... (store_user_credentials function remains the same) ...
def store_user_credentials(username, password):
    try:
        encrypted = fernet.encrypt(password.encode()).decode() 
        redis_client.hset("user_credentials", username, encrypted)
    except redis.exceptions.ConnectionError as e:
        print(f"Error storing credentials for user '{username}' (connection): {e}")
    except Exception as e:
        print(f"Error storing credentials for user '{username}': {e}")
# ... (track_user_activity function remains the same) ...
def track_user_activity(username):
    """Track user activity by recording access timestamp in Redis."""
    if not username: return
    now = datetime.now(timezone.utc).isoformat()
    user_key = f"user_activity:{username}"
    
    try:
        access_count = redis_client.hincrby(user_key, "access_count", 1)
        redis_client.hsetnx(user_key, "first_seen", now)
        redis_client.hset(user_key, "last_seen", now)
    except redis.exceptions.ConnectionError as e:
        print(f"Error tracking activity for user '{username}' (connection): {e}")
    except Exception as e:
        print(f"Error tracking activity for user '{username}': {e}")
# ... (get_user_activity function remains the same) ...
def get_user_activity(username):
    """Retrieve user activity data from Redis."""
    if not username: return None
    user_key = f"user_activity:{username}"
    try:
        activity_data = redis_client.hgetall(user_key)
        return activity_data if activity_data else None
    except redis.exceptions.ConnectionError as e:
        print(f"Error retrieving activity for user '{username}' (connection): {e}")
        return None
    except Exception as e:
        print(f"Error retrieving activity for user '{username}': {e}")
        return None

# --- Background Logging Task ---
def _log_to_redis_task(log_entry_dict):
    """
    Internal task function executed by the ThreadPoolExecutor.
    Handles the actual writing to Redis.
    """
    try:
        log_entry_json = json.dumps(log_entry_dict)
        # Use pipeline for atomic push+trim
        pipe = redis_client.pipeline()
        pipe.lpush(API_LOG_KEY, log_entry_json)
        pipe.ltrim(API_LOG_KEY, 0, MAX_LOG_ENTRIES - 1)
        pipe.execute()
    except redis.exceptions.ConnectionError as e:
        print(f"[{threading.current_thread().name}] Log Error: Redis connection error: {e}")
    except Exception as e:
        print(f"[{threading.current_thread().name}] Log Error: Failed to write log to Redis: {e}")
        # Avoid printing the full dict in logs generally, maybe just key info
        print(f"[{threading.current_thread().name}] Log Error: Failed entry (partial): username={log_entry_dict.get('username')}, endpoint={log_entry_dict.get('endpoint')}")


# --- Flask App Setup ---
app = Flask(__name__)

@app.before_request
def before_request_func():
    g.start_time = perf_counter()
    g.request_time = datetime.now(timezone.utc)
    g.username = None
    g.log_outcome = "unknown"
    g.log_error_message = None

@app.after_request
def after_request_logger(response):
    """
    Gathers log info and submits the logging task to the ThreadPoolExecutor.
    """
    if request.path == '/api/logs' or request.method == 'OPTIONS':
        return response

    elapsed_ms = (perf_counter() - g.start_time) * 1000

    # Create the log entry dictionary (synchronous, but fast)
    log_entry = {
        "username": getattr(g, 'username', None),
        "endpoint": request.path,
        "method": request.method,
        "status_code": response.status_code,
        "outcome": getattr(g, 'log_outcome', 'unknown'),
        "error_message": getattr(g, 'log_error_message', None),
        "time_elapsed_ms": round(elapsed_ms, 2),
        "request_timestamp_utc": getattr(g, 'request_time', datetime.now(timezone.utc)).isoformat(),
        "response_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "ip_address": request.remote_addr,
        "user_agent": request.user_agent.string,
        "request_args": request.args.to_dict()
    }

    if 'password' in log_entry['request_args']:
        log_entry['request_args']['password'] = '********'

    # --- Submit task to the executor ---
    # This is non-blocking. It schedules _log_to_redis_task to run on a pool thread.
    try:
        log_executor.submit(_log_to_redis_task, log_entry)
    except Exception as e:
        # Log errors during submission itself (e.g., if executor is shut down)
        print(f"Error submitting log task to executor: {e}")
    # -----------------------------------

    # Add CORS headers
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"

    # Return response immediately
    return response


# --- API Endpoints ---

@app.route("/api/schedule", methods=["GET"])
def api_schedule():
    bot_param = request.args.get("bot")
    if bot_param and bot_param.lower() == "true":
        
        g.log_outcome = "bot_check_success" # Set outcome for logging
        # No username needed for bot check
        return jsonify({"status": "Success", "message": "Schedule API route is up!", "data": None}), 200
    username = request.args.get("username")
    password = request.args.get("password")
    g.username = username # Store for logging

    # --- Validation ---
    if not username or not password:
        g.log_outcome = "validation_error"
        g.log_error_message = "Missing username or password"
        return jsonify({"error": "Missing username or password"}), 400

    # --- Authentication/Credential Check ---
    stored_users = get_all_stored_users()
    if username in stored_users:
        try:
            stored_pw = fernet.decrypt(stored_users[username].encode()).decode().strip()
        except Exception as e:
            print(f"Decryption error for user {username}: {e}")
            g.log_outcome = "internal_error"
            g.log_error_message = "Error decrypting stored credentials"
            return jsonify({"error": "Internal server error during credential check"}), 500
        
        if stored_pw != password.strip():
            g.log_outcome = "auth_error"
            g.log_error_message = "Invalid credentials provided"
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        # User not found in storage yet. Will store credentials only on successful scrape.
        pass 

    # --- Track Activity ---
    # Track activity even if cache hit occurs or auth fails here (helps see attempt patterns)
    track_user_activity(username) 

    # --- Cache Check ---
    cache_key = f"schedule:{username}"
    cached_data = get_from_app_cache(cache_key)
    if cached_data:
        print(f"Serving schedule data from cache for user: {username}")
        g.log_outcome = "cache_hit"
        return jsonify(cached_data), 200

    # --- Scraping ---
    print(f"Cache miss. Starting schedule scraping for user: {username}")
    g.log_outcome = "scrape_attempt"
    start_scrape_time = perf_counter()
    result = scrape_schedule(username, password, BASE_URL)
    scrape_duration = perf_counter() - start_scrape_time
    print(f"Scraping finished for {username} in {scrape_duration:.2f} seconds") 

    # --- Handle Scraping Result ---
    if "error" in result:
        error_msg = result["error"]
        print(f"Scraping error for user {username}: {error_msg}")
        g.log_error_message = error_msg
        # Determine response based on error type
        if "Authentication failed" in error_msg:
            g.log_outcome = "scrape_auth_error"
            # Even if user wasn't stored, this is GUC auth failing
            return jsonify({"error": f"Authentication failed on GUC site: {error_msg}"}), 401 
        elif any(e in error_msg for e in ["timed out", "Connection error", "HTTP error"]):
            g.log_outcome = "scrape_connection_error"
            return jsonify({"error": f"Failed to connect to GUC schedule service: {error_msg}"}), 504 
        elif any(e in error_msg for e in ["parse", "Failed to find"]):
             g.log_outcome = "scrape_parsing_error"
             return jsonify({"error": f"Failed to parse schedule page: {error_msg}"}), 502 
        else:
            g.log_outcome = "scrape_unknown_error"
            return jsonify({"error": f"An error occurred during scraping: {error_msg}"}), 500
    else:
        # --- Success ---
        print(f"Successfully scraped schedule for user: {username}")
        g.log_outcome = "scrape_success"
        
        # Store credentials only on the first successful scrape for this user
        if username not in stored_users:
            print(f"Storing credentials for new user: {username}")
            store_user_credentials(username, password)

        filtered = filter_schedule_details(result)
        response_data = (filtered, timings) # Package as tuple

        # Cache the successful result
        set_to_app_cache(cache_key, response_data, LONG_CACHE_TIMEOUT)
        print(f"Cached fresh schedule for user: {username}")
        return jsonify(response_data), 200




# --- Main Execution ---
if __name__ == "__main__":
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    # Example: gunicorn --workers 2 --threads 4 -b 0.0.0.0:5000 your_module:app
    app.run(debug=True, host='0.0.0.0', port=5000)

    # Optional: Add a shutdown hook for the executor if running in a persistent environment
    # Not strictly necessary for typical serverless, as daemon threads don't block exit
    # import atexit
    # atexit.register(lambda: log_executor.shutdown(wait=False)) # Don't wait on exit