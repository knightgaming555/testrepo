import os
from flask import Flask, request, jsonify
import redis
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime
from api.scraping import authenticate_user  # Your actual auth function
import logging

# Load env vars
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("login_api")

# --- Test credentials for simulation ---
TEST_CREDENTIALS = {
    "test_user": "test_password",
    "admin": "admin123",
    "student": "student123",
    "mohamed.elsaadi": "Messo_1245",
}

# Dictionary to simulate stored credentials that might be outdated
STORED_CREDENTIALS = {
    "mohamed.elsaadi": "Messo_1245",  # This will simulate our stored password
}


def simulate_authenticate_user(username, password, check_stored=False):
    """
    Simulated authentication function for testing purposes.
    Uses hardcoded credentials instead of connecting to the university website.

    If check_stored is True, it simulates the behavior of checking against
    the stored password vs. the "university server" (TEST_CREDENTIALS).
    """
    logger.info(f"Simulating authentication for user: {username}")

    # Simulate a successful response from university server when credentials match
    university_auth_success = (
        username in TEST_CREDENTIALS and TEST_CREDENTIALS[username] == password
    )

    if check_stored:
        # Check if credentials match what we have stored
        stored_password_match = (
            username in STORED_CREDENTIALS and STORED_CREDENTIALS[username] == password
        )

        if university_auth_success and not stored_password_match:
            # This simulates the case where password was changed on university side
            # but we have old password stored
            logger.warning(
                f"Password mismatch detected for {username}! University accepts new password."
            )
            # Update our stored password
            STORED_CREDENTIALS[username] = password
            logger.info(f"Updated stored password for {username}")
            return {
                "success": True,
                "stored_password_updated": True,
                "message": "Password updated and authentication successful",
            }
        elif university_auth_success:
            logger.info(
                f"Authentication successful for {username} (password matches stored)"
            )
            return {
                "success": True,
                "stored_password_updated": False,
                "message": "Authentication successful",
            }
        else:
            logger.info(f"Authentication failed for {username}")
            return {
                "success": False,
                "stored_password_updated": False,
                "message": "Invalid credentials",
            }

    # Simple authentication
    return university_auth_success


# --- Configuration ---
class Config:
    DEBUG = True
    CACHE_REFRESH_SECRET = os.environ.get("CACHE_REFRESH_SECRET", "my_refresh_secret")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
    BASE_SCHEDULE_URL_CONFIG = os.environ.get(
        "BASE_SCHEDULE_URL",
        "https://apps.guc.edu.eg/student_ext/Scheduling/GroupSchedule.aspx",
    )
    BASE_ATTENDANCE_URL_CONFIG = os.environ.get(
        "BASE_ATTENDANCE_URL",
        "https://apps.guc.edu.eg/student_ext/Attendance/ClassAttendance_ViewStudentAttendance_001.aspx",
    )


config = Config()

# --- Redis and Encryption ---
redis_client = redis.from_url(os.environ.get("REDIS_URL"))
fernet = Fernet(config.ENCRYPTION_KEY)


def log_event(message):
    print(f"{datetime.now().isoformat()} - {message}")


# --- Flask App ---
app = Flask(__name__)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    logger.info(f"Login attempt for {username}")

    def store_user_credentials(username, password):
        # Ensure password is a string before encoding
        if isinstance(password, bytes):
            password = password.decode()

        encrypted = fernet.encrypt(password.encode()).decode()
        redis_client.hset("user_credentials", username, encrypted)
        logger.info(f"Stored credentials for {username}")

    def get_stored_password(username):
        encrypted = redis_client.hget("user_credentials", username)
        if encrypted:
            try:
                # Fix: Handle both string and bytes types properly
                if isinstance(encrypted, bytes):
                    # If it's already bytes, don't encode it again
                    return fernet.decrypt(encrypted).decode()
                else:
                    # If it's a string, encode it
                    return fernet.decrypt(encrypted.encode()).decode()
            except Exception as e:
                logger.error(f"Failed to decrypt password for {username}: {str(e)}")
        return None

    def is_user_authorized(username):
        whitelist_raw = redis_client.get("WHITELIST")
        if whitelist_raw:
            whitelist = [u.strip() for u in whitelist_raw.decode().split(",")]
            return username in whitelist
        return False

    version_number_raw = redis_client.get("VERSION_NUMBER")
    version_number2 = version_number_raw.decode() if version_number_raw else "1.0"
    req_version = request.args.get("version_number")
    if req_version != version_number2:
        logger.warning(f"Incorrect version number: {req_version} vs {version_number2}")
        return (
            jsonify(
                {"status": "error", "message": "Incorrect version number", "data": None}
            ),
            403,
        )
    if not username or not password:
        logger.warning("Missing username or password")
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )
    if not is_user_authorized(username):
        logger.warning(f"User {username} is not authorized")
        return (
            jsonify(
                {"status": "error", "message": "User is not authorized", "data": None}
            ),
            403,
        )

    # Authenticate with provided credentials
    auth_success = authenticate_user(username, password)

    if auth_success:
        # Check if the password has changed
        stored_password = get_stored_password(username)

        if stored_password and stored_password != password:
            logger.info(f"Password change detected for {username}")

        try:
            # Store the newest credentials regardless
            store_user_credentials(username, password)
            log_event(f"User {username} logged in successfully.")
            logger.info(f"Login successful for {username}")
            return jsonify({"status": "success", "username": username}), 200
        except Exception as e:
            logger.error(f"Error storing credentials for {username}: {str(e)}")
            # Still return success since authentication worked
            return (
                jsonify(
                    {
                        "status": "success",
                        "username": username,
                        "note": "Credentials not stored due to error",
                    }
                ),
                200,
            )
    else:
        logger.warning(f"Invalid credentials for {username}")
        return (
            jsonify(
                {"status": "error", "message": "Invalid credentials", "data": None}
            ),
            401,
        )


@app.route("/api/test-login", methods=["POST"])
def test_login():
    """
    Test endpoint for login functionality without affecting production data.
    This endpoint authenticates but doesn't store credentials.
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return (
            jsonify({"status": "error", "message": "Missing username or password"}),
            400,
        )

    # Check if authentication would succeed
    auth_success = authenticate_user(username, password)

    if auth_success:
        return (
            jsonify(
                {
                    "status": "success",
                    "message": "Credentials are valid",
                    "would_store": True,
                    "test_only": True,
                }
            ),
            200,
        )
    else:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Invalid credentials",
                    "would_store": False,
                    "test_only": True,
                }
            ),
            401,
        )


@app.route("/test-login-form", methods=["GET", "POST"])
def test_login_form():
    """
    Serves a web form to test login functionality directly from a browser.
    Uses simulated authentication for testing purposes.
    """
    result = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        logger.info(f"Login attempt for username: {username}")

        if not username or not password:
            result = {"status": "error", "message": "Missing username or password"}
            logger.warning("Login attempt missing username or password")
        else:
            # Choose which authentication to use
            use_simulation = request.form.get("use_simulation") == "on"
            check_stored = request.form.get("check_stored") == "on"

            if use_simulation:
                # Use simulated authentication
                logger.info("Using simulated authentication")
                if check_stored:
                    auth_result = simulate_authenticate_user(
                        username, password, check_stored=True
                    )
                    auth_success = auth_result["success"]
                    auth_mode = "Simulated with stored password check"

                    # If password was updated in the simulation
                    if auth_result.get("stored_password_updated"):
                        result = {
                            "status": "success",
                            "message": f"SUCCESS: Password updated and authentication successful ({auth_mode})",
                            "details": f"Your new password has been stored. Previous stored password: {STORED_CREDENTIALS.get(username, 'None')}",
                            "would_store": True,
                            "test_only": True,
                            "auth_mode": auth_mode,
                            "password_updated": True,
                        }
                        logger.info(
                            f"Password updated for user {username} during authentication"
                        )
                        return html_response(result)
                else:
                    auth_success = simulate_authenticate_user(username, password)
                    auth_mode = "Simulated (simple)"
            else:
                # Use real authentication
                logger.info("Using real authentication against university server")
                auth_success = authenticate_user(username, password)
                auth_mode = "Real"

            if auth_success:
                result = {
                    "status": "success",
                    "message": f"Credentials are valid ({auth_mode} authentication)",
                    "would_store": True,
                    "test_only": True,
                    "auth_mode": auth_mode,
                }
                logger.info(
                    f"Authentication successful for {username} using {auth_mode}"
                )
            else:
                result = {
                    "status": "error",
                    "message": f"Invalid credentials ({auth_mode} authentication)",
                    "would_store": False,
                    "test_only": True,
                    "auth_mode": auth_mode,
                }
                logger.warning(
                    f"Authentication failed for {username} using {auth_mode}"
                )

    return html_response(result)


def html_response(result=None):
    """Helper function to generate HTML for the test form response"""
    # Simple HTML form with simulation option
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
            button { padding: 10px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
            .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
            .success { background-color: #dff0d8; border: 1px solid #d6e9c6; color: #3c763d; }
            .error { background-color: #f2dede; border: 1px solid #ebccd1; color: #a94442; }
            .info-box { background-color: #d9edf7; border: 1px solid #bce8f1; color: #31708f; padding: 10px; margin-bottom: 20px; border-radius: 4px; }
            .checkbox-group { margin-top: 10px; }
            .checkbox-group label { display: inline; margin-left: 5px; }
            .highlight { font-weight: bold; color: #d9534f; }
        </style>
    </head>
    <body>
        <h1>Test Login Form</h1>
        <p>This form tests credentials without actually storing them in the system.</p>
        
        <div class="info-box">
            <h3>Test Credentials (Simulation Mode):</h3>
            <ul>
                <li><strong>Username:</strong> test_user | <strong>Password:</strong> test_password</li>
                <li><strong>Username:</strong> admin | <strong>Password:</strong> admin123</li>
                <li><strong>Username:</strong> student | <strong>Password:</strong> student123</li>
                <li><strong class="highlight">Username:</strong> mohamed.elsaadi | <strong>Password:</strong> Messo_1245</li>
            </ul>
            <p><strong>Password Update Test:</strong> For mohamed.elsaadi, try using a different password with "Check Stored Password" enabled.</p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="use_simulation" name="use_simulation" checked>
                <label for="use_simulation">Use simulated authentication (doesn't connect to university website)</label>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="check_stored" name="check_stored" checked>
                <label for="check_stored">Check against stored password (simulates password change detection)</label>
            </div>
            
            <button type="submit" style="margin-top: 15px;">Test Login</button>
        </form>
    """

    if result:
        status_class = "success" if result["status"] == "success" else "error"
        details_html = (
            f"<p>{result.get('details', '')}</p>" if result.get("details") else ""
        )
        password_updated = "✓ Yes" if result.get("password_updated") else "✗ No"

        html += f"""
        <div class="result {status_class}">
            <h3>Result: {result["status"].upper()}</h3>
            <p>{result["message"]}</p>
            {details_html}
            <p>Would store credentials: {"Yes" if result.get("would_store") else "No"}</p>
            <p>Authentication mode: {result.get("auth_mode", "Unknown")}</p>
            <p>Password updated: {password_updated}</p>
        </div>
        """

    html += """
    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(debug=True)
