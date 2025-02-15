import os
import re
import requests
import google.generativeai as genai

# --- Gemini Generative AI Setup ---
GEMINI_API_KEY = os.environ.get(
    "GEMINI_API_KEY", "AIzaSyAzSzm1L2ECUy_5Dm5hkMnvB-hozyMw5RI"
)
genai.configure(api_key=GEMINI_API_KEY)

generation_config = {
    "temperature": 0.9,  # Slightly lower temp for more focused intent detection
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 1024,  # Reduce for intent classification prompts
    "response_mime_type": "text/plain",
}

intent_model = genai.GenerativeModel(  # Dedicated model for intent classification
    model_name="gemini-2.0-pro-exp-02-05",
    generation_config=generation_config,
)

chat_generation_config = {  # Separate config for general chat
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 64,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

chat_model = genai.GenerativeModel(  # Separate model for general chat to optimize costs/performance if needed
    model_name="gemini-2.0-pro-exp-02-05",
    generation_config=chat_generation_config,
)


chat_session = chat_model.start_chat(history=[])

# --- API Configuration ---
API_BASE_URL = "https://v2-guc-scrapper.vercel.app/api"

# Global session state
session_state = {
    "username": None,
    "password": None,
    "version": None,
}


def set_credentials(username, password, version):
    session_state["username"] = username
    session_state["password"] = password
    session_state["version"] = version
    return f"Credentials set for user '{username}' with API version '{version}'. Login successful!"


def call_api(endpoint, params=None, method="GET", data=None):
    url = f"{API_BASE_URL}{endpoint}"
    if params is None:
        params = {}
    if session_state.get("username") and "username" not in params:
        params["username"] = session_state["username"]
    if session_state.get("password") and "password" not in params:
        params["password"] = session_state["password"]
    if session_state.get("version") and "version_number" not in params:
        params["version_number"] = session_state["version"]
    try:
        if method.upper() == "GET":
            response = requests.get(url, params=params)
        elif method.upper() == "POST":
            response = requests.post(url, params=params, json=data)
        else:
            return f"Unsupported HTTP method: {method}"
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        return f"API Error {response.status_code}: {response.text}"
    except requests.exceptions.RequestException as req_err:
        return f"Request Exception: {str(req_err)}"
    except Exception as e:
        return f"General Exception: {str(e)}"


def handle_command(user_input):
    """Handles explicit commands (login, set_version)."""
    lower_input = user_input.lower().strip()

    if lower_input.startswith("login"):
        parts = user_input.split()
        if len(parts) == 4:
            username, password, version = parts[1], parts[2], parts[3]
            login_result = call_api(
                "/login",
                params={"version_number": version},
                method="POST",
                data={"username": username, "password": password},
            )
            if (
                isinstance(login_result, dict)
                and login_result.get("status") == "success"
            ):
                return set_credentials(username, password, version)
            else:
                return f"Login failed: {login_result.get('message', login_result)}"  # More robust error display
        else:
            return "Usage: login <username> <password> <version_number>"

    elif lower_input.startswith("set_version"):
        parts = user_input.split()
        if len(parts) == 2:
            version = parts[1]
            session_state["version"] = version
            return f"API version set to {version}."
        else:
            return "Usage: set_version <version_number>"
    return None


def get_intent_gemini(user_input):
    """Uses Gemini to classify user intent."""
    prompt = f"""Classify the user's intent from the following categories:
    schedule, grades, attendance, exam_seats, guc_data, cms_data, cms_content, general_chat, unknown.
    If it's cms_content, try to extract a course URL if present.
    Just respond with the intent category and optionally the URL in JSON format.

    User Input: {user_input}
    Intent (JSON format, e.g., {{"intent": "schedule"}} or {{"intent": "cms_content", "course_url": "https://example.com"}} or {{"intent": "general_chat"}}):
    """
    try:
        response = intent_model.send_message(prompt)
        intent_json_str = response.text.strip()

        # Basic JSON parsing with fallback for potential Gemini formatting issues
        if intent_json_str.startswith("{") and intent_json_str.endswith("}"):
            try:
                import json

                intent_data = json.loads(intent_json_str)
                return intent_data
            except json.JSONDecodeError:
                print(
                    f"Warning: Gemini intent JSON response invalid: {intent_json_str}"
                )
                return {"intent": "unknown"}  # Treat as unknown if JSON invalid
        else:
            print(f"Warning: Gemini intent response not JSON: {intent_json_str}")
            return {"intent": "unknown"}  # Treat as unknown if not JSON

    except Exception as e:
        print(f"Error during Gemini intent classification: {e}")
        return {"intent": "unknown"}  # Treat as unknown on error


def detect_tool(user_input):
    """Detects tool using Gemini for intent classification."""
    intent_data = get_intent_gemini(user_input)
    intent = intent_data.get("intent", "unknown")
    course_url = intent_data.get("course_url")  # Will be None if not 'cms_content'

    if intent == "schedule":
        return "schedule", {}
    elif intent == "grades":
        return "grades", {}
    elif intent == "attendance":
        return "attendance", {}
    elif intent == "exam_seats":
        return "exam_seats", {}
    elif intent == "guc_data":
        return "guc_data", {}
    elif intent == "cms_data":
        return "cms_data", {}
    elif intent == "cms_content":
        return "cms_content", {"course_url": course_url}  # Pass extracted URL
    elif (
        intent == "general_chat" or intent == "unknown"
    ):  # Handle unknown or explicitly general chat
        return None, {}  # No tool needed

    return None, {}  # Default no tool if intent not matched


tool_endpoints = {
    "schedule": "/schedule",
    "grades": "/grades",
    "attendance": "/attendance",
    "exam_seats": "/exam_seats",
    "guc_data": "/guc_data",
    "cms_data": "/cms_data",
    "cms_content": "/cms_content",
}


def format_schedule_response(schedule_data):
    if not schedule_data:
        return "No lectures found in your schedule."
    formatted_schedule = "Here is your schedule:\n"
    for lecture in schedule_data:
        formatted_schedule += (
            f"- **{lecture.get('course', 'Course')}**: {lecture.get('time', 'Time')}, "
            f"Location: {lecture.get('location', 'TBD')}, Type: {lecture.get('type', 'Lecture')}\n"  # Example including 'type'
        )
    return formatted_schedule


def format_grades_response(grades_data):
    if not grades_data:
        return "No grades data available."
    formatted_grades = "Here are your grades:\n"
    for course_grade in grades_data:
        formatted_grades += (
            f"- **{course_grade.get('course_name', 'Course')}**: Grade: {course_grade.get('grade', 'N/A')}, "
            f"Credits: {course_grade.get('credits', 'N/A')}, Semester: {course_grade.get('semester', 'N/A')}\n"  # Example: Credits & Semester
        )
    return formatted_grades


def format_attendance_response(attendance_data):
    if not attendance_data:
        return "No attendance data found."
    formatted_attendance = "Your Attendance Summary:\n"
    for course_attendance in attendance_data:
        formatted_attendance += (
            f"- **{course_attendance.get('course_name', 'Course')}**: Attendance: {course_attendance.get('percentage', 'N/A')}, "
            f"Status: {course_attendance.get('status', 'N/A')}\n"  # Example: Attendance Status
        )
    return formatted_attendance


def format_exam_seats_response(exam_seats_data):
    if not exam_seats_data:
        return "No exam seat information available yet."
    formatted_seats = "Your Exam Seating Arrangements:\n"
    for exam in exam_seats_data:
        formatted_seats += (
            f"- **{exam.get('course_name', 'Course')}**: Exam Date: {exam.get('date', 'TBD')}, "  # Example Exam Date
            f"Seat: {exam.get('seat_number', 'TBD')}, Room: {exam.get('room', 'TBD')}\n"
        )
    return formatted_seats


def format_guc_data_response(guc_data):
    if not guc_data:
        return "No general GUC data retrieved."
    # Use Gemini to summarize and make GUC data more user-friendly
    try:
        prompt = f"Please summarize the following GUC data in a concise and user-friendly way, highlighting the most important information:\n\n{str(guc_data)}"
        summary_response = chat_model.send_message(
            prompt
        )  # Use chat model for richer summary
        return "GUC Data Summary:\n" + summary_response.text
    except Exception as e:
        print(f"Error summarizing GUC data with Gemini: {e}")
        return "GUC Data:\n" + str(guc_data)  # Fallback if summarization fails


def format_cms_data_response(cms_data):
    if not cms_data:
        return "No CMS data retrieved."
    # Similar summarization for CMS data (customize prompt if needed)
    try:
        prompt = f"Summarize the following CMS data to be easily understandable:\n\n{str(cms_data)}"
        summary_response = chat_model.send_message(prompt)
        return "CMS Data Summary:\n" + summary_response.text
    except Exception as e:
        print(f"Error summarizing CMS data with Gemini: {e}")
        return "CMS Data:\n" + str(cms_data)  # Fallback


def format_cms_content_response(cms_content):
    if not cms_content:
        return "No CMS content found for the provided URL."
    return (
        "CMS Content:\n" + cms_content
    )  # Simple content display - could summarize if too long


response_formatters = {  # Mapping tool to response formatter function
    "schedule": format_schedule_response,
    "grades": format_grades_response,
    "attendance": format_attendance_response,
    "exam_seats": format_exam_seats_response,
    "guc_data": format_guc_data_response,
    "cms_data": format_cms_data_response,
    "cms_content": format_cms_content_response,
}


def process_api_response(tool, result):
    """Processes API response based on tool, formats, and handles errors."""
    if isinstance(result, str):  # API call error message
        return f"API Error: {result}"  # Improved error prefix

    if (
        not isinstance(result, dict) or result.get("status") != "success"
    ):  # API success check
        return f"API Request Failed: {result.get('message', 'Unknown error')}"  # Better error message

    data = result.get("data")
    if data is None:
        return "API returned successfully but no data found."

    formatter = response_formatters.get(tool)  # Get the specific formatter function
    if formatter:
        return formatter(data)  # Use formatter to generate user-friendly response
    else:  # No formatter defined for this tool (should not happen with current tool list)
        return "Data retrieved but no specific formatting available:\n" + str(data)


def main():
    print("🎓 Dynamic Smart Assistant (GUC Edition) 🎓")
    print("-" * 40)
    print(
        "I am your intelligent assistant for GUC student services. I can help you with:"
    )
    print("- Checking your schedule")
    print("- Viewing your grades")
    print("- Getting attendance information")
    print("- Finding exam seat arrangements")
    print("- Accessing general GUC data & notifications")
    print("- Retrieving CMS course data and content")
    print("\n✨ Let's get started! ✨")
    print("\nFirst, you may need to login using the 'login' command.")
    print("For general questions or anything else, just ask!\n")
    print("Type 'help' for available commands or 'exit' to quit.")

    while True:
        user_input = input("\nYou: ").strip()
        if user_input.lower() in ["exit", "quit"]:
            print("Assistant: Goodbye! 👋")
            break

        if user_input.lower() == "help":
            print("Assistant: Available commands:")
            print(
                "  - `login <username> <password> <version_number>`: Log in to access personalized data."
            )
            print("  - `set_version <version_number>`: Change the API version.")
            print(
                "  - Just ask questions like 'What's my schedule?', 'Show my grades', etc."
            )
            print("  - `exit` or `quit`: End the chat session.")
            continue

        command_result = handle_command(user_input)
        if command_result:
            print("Assistant:", command_result)
            continue

        tool, extra_params = detect_tool(user_input)
        if tool:
            if tool == "cms_content" and not extra_params.get("course_url"):
                print(
                    "Assistant: Please provide a course URL with your CMS content request (e.g., 'Show CMS content for <course_url>')."
                )
                continue
            endpoint = tool_endpoints[tool]
            api_result = call_api(endpoint, params=extra_params)
            formatted_response = process_api_response(tool, api_result)
            print("Assistant:", formatted_response)

        else:  # General chat with Gemini if no tool detected
            try:
                response = chat_session.send_message(user_input)
                print("Assistant:", response.text)
            except Exception as e:
                print(
                    f"Assistant: 🤖 Gemini AI Chat Error: {e}"
                )  # Specific error for Gemini


if __name__ == "__main__":
    main()
