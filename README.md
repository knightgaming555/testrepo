# V2 GUC Scrapper API Documentation

## Introduction

Welcome to the V2 GUC Scrapper API documentation. This API provides access to various GUC (German University in Cairo) student data including schedules, grades, attendance, and more.

Base URL: `https://v2-guc-scrapper.vercel.app`

## Authentication

All endpoints require authentication using GUC credentials:

- `username`: Your GUC username
- `password`: Your GUC password

## Endpoints

### 1. Login

**Endpoint:** `/login`  
**Method:** `POST`  
**Description:** Authenticate with GUC credentials  
**Request Body:**

```json
{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**

```json
{
  "status": "success",
  "token": "auth_token"
}
```

### 2. Schedule

**Endpoint:** `/schedule`  
**Method:** `GET`  
**Description:** Get student schedule  
**Parameters:**

- `username` (required)
- `password` (required)
  **Response:**

```json
{
  "schedule": [
    {
      "course": "CSEN 401",
      "day": "Sunday",
      "time": "10:00 AM - 12:00 PM",
      "location": "C3.301"
    }
  ]
}
```

### 3. Grades

**Endpoint:** `/grades`  
**Method:** `GET`  
**Description:** Get student grades  
**Parameters:**

- `username` (required)
- `password` (required)
  **Response:**

```json
{
  "grades": [
    {
      "course": "CSEN 401",
      "grade": "A",
      "credits": 3
    }
  ]
}
```

### 4. Attendance

**Endpoint:** `/attendance`  
**Method:** `GET`  
**Description:** Get student attendance records  
**Parameters:**

- `username` (required)
- `password` (required)
  **Response:**

```json
{
  "attendance": [
    {
      "course": "CSEN 401",
      "present": 12,
      "absent": 2
    }
  ]
}
```

### 5. Exam Seats

**Endpoint:** `/exam-seats`  
**Method:** `GET`  
**Description:** Get exam seating information  
**Parameters:**

- `username` (required)
- `password` (required)
  **Response:**

```json
{
  "exam_seats": [
    {
      "course": "CSEN 401",
      "date": "2023-12-15",
      "time": "09:00 AM",
      "location": "C3.101",
      "seat": "A12"
    }
  ]
}
```

## Error Handling

The API returns standard HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid parameters
- `401 Unauthorized`: Invalid credentials
- `500 Internal Server Error`: Server error

Error response format:

```json
{
  "status": "error",
  "message": "Error description"
}
```

## Rate Limiting

The API has a rate limit of 100 requests per minute per IP address. If exceeded, you'll receive a `429 Too Many Requests` response.

## Examples

### Python Example

```python
import requests

base_url = "https://v2-guc-scrapper.vercel.app"
credentials = {
    "username": "your_username",
    "password": "your_password"
}

# Login
response = requests.post(f"{base_url}/login", json=credentials)
token = response.json()["token"]

# Get schedule
headers = {"Authorization": f"Bearer {token}"}
schedule = requests.get(f"{base_url}/schedule", headers=headers)
print(schedule.json())
```

### JavaScript Example

```javascript
const axios = require("axios");

const baseUrl = "https://v2-guc-scrapper.vercel.app";
const credentials = {
  username: "your_username",
  password: "your_password",
};

// Login
axios
  .post(`${baseUrl}/login`, credentials)
  .then((response) => {
    const token = response.data.token;

    // Get schedule
    return axios.get(`${baseUrl}/schedule`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  })
  .then((response) => console.log(response.data))
  .catch((error) => console.error(error));
```

## Support

For any issues or questions, please contact the API maintainers.
