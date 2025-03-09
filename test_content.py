import requests
import json
import time
from datetime import datetime

# API endpoint
api_url = "https://v2-guc-scrapper.vercel.app/api/cms_content"

# Test credentials - replace with valid credentials
username = input("Enter your username: ")  # Replace with a valid username
password = input("Enter your password: ")  # Replace with a valid password

# If you have a specific course URL, use it
# Otherwise, set to empty string to get the list of courses
course_url = input(
    "Enter the course URL: "
)  # Or use a specific course URL like "https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=1234&sid=5678"

# Record start time
start_time = time.time()
print(f"Request started at: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")

# Make the request
response = requests.get(
    api_url,
    params={"username": username, "password": password, "course_url": course_url},
)

# Calculate request time
request_time = time.time() - start_time
print(f"Request completed at: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}")
print(f"Total request time: {request_time:.2f} seconds")

# Print the status code
print(f"Status Code: {response.status_code}")

# Check if the request was successful
if response.status_code == 200:
    # Record parsing start time
    parsing_start = time.time()

    # Parse the JSON response
    data = response.json()

    # Calculate parsing time
    parsing_time = time.time() - parsing_start
    print(f"JSON parsing time: {parsing_time:.2f} seconds")

    # If we got a list of courses, print them in a more readable way
    if isinstance(data, list) and len(data) > 0 and "course_name" in data[0]:
        print("\nAvailable Courses:")
        for i, course in enumerate(data, 1):
            print(f"{i}. {course['course_name']}")
            print(f"   URL: {course['course_url']}")
        print(f"\nTotal courses found: {len(data)}")
    else:
        # For course content data, print summary instead of full content
        if isinstance(data, list) and len(data) > 0 and "week_name" in data[0]:
            total_content_items = sum(len(week.get("contents", [])) for week in data)
            print(f"\nCourse Content Summary:")
            print(f"Total weeks: {len(data)}")
            print(f"Total content items: {total_content_items}")

            # Print details of each week
            for week in data:
                print(f"\n- {week['week_name']}: {len(week.get('contents', []))} items")
        else:
            # For other types of data, print compact JSON
            print(json.dumps(data, indent=2))
else:
    # Print error details
    print(f"Error: {response.text}")

# Print total execution time
total_time = time.time() - start_time
print(f"\nTotal execution time: {total_time:.2f} seconds")
