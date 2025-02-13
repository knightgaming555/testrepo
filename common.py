# common.py
import os
from datetime import datetime
from cryptography.fernet import Fernet
import redis
from dotenv import load_dotenv

load_dotenv()


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

# Redis client
redis_client = redis.from_url(os.environ.get("REDIS_URL"))

# Set up Fernet for encryption/decryption.
fernet = Fernet(config.ENCRYPTION_KEY)


def get_config_value(key, default_value):
    value = redis_client.get(key)
    if value is not None:
        return value.decode()
    else:
        redis_client.set(key, default_value)
        return default_value


def set_config_value(key, value):
    redis_client.set(key, value)


def get_all_stored_users():
    stored = redis_client.hgetall("user_credentials")
    return {k.decode(): v.decode() for k, v in stored.items()}


def store_user_credentials(username, password):
    encrypted_password = fernet.encrypt(password.encode()).decode()
    redis_client.hset("user_credentials", username, encrypted_password)


# In-memory logs for scraper events and API requests.
scraper_logs = []
api_logs = []
LOG_HISTORY_LENGTH = 100


def log_scraper_event(message):
    log_message = f"{datetime.now().isoformat()} - {message}"
    scraper_logs.insert(0, log_message)
    if len(scraper_logs) > LOG_HISTORY_LENGTH:
        scraper_logs.pop()
