import requests
import threading
import time
import json


def make_request(endpoint_name, endpoint_url, params, results):
    """
    Makes a single API request and stores the results.

    Args:
        endpoint_name (str): Name of the endpoint (for identification).
        endpoint_url (str): The URL of the endpoint.
        params (dict):  Query parameters for the request.
        results (dict):  A dictionary to store the results (shared among threads).
    """
    try:
        start_time = time.time()
        response = requests.get(endpoint_url, params=params)
        end_time = time.time()

        response.raise_for_status()

        try:
            json_data = response.json()
            response_body = json.dumps(json_data, indent=4)  # Pretty print for storage
        except json.JSONDecodeError:
            response_body = response.text

        results[endpoint_name] = {
            "status_code": response.status_code,
            "response_time": end_time - start_time,
            "response_body": response_body,
            "error": None,
        }

    except requests.exceptions.RequestException as e:
        results[endpoint_name] = {
            "status_code": None,  # No status code if request fails completely
            "response_time": None,
            "response_body": None,
            "error": str(e),
        }


def test_api_endpoints_concurrently(username, password, version_number="1.33"):
    """
    Tests two GUC API endpoints concurrently using threads.

    Args:
        username (str): The GUC username.
        password (str): The GUC password.
        version_number (str): The API version number.

    Returns:
        dict: A dictionary containing the results of each API call.
    """
    base_url = "https://v2-guc-scrapper.vercel.app/api"
    endpoints = {
        "guc_data": f"{base_url}/guc_data",
        "schedule": f"{base_url}/schedule",
    }

    params = {
        "version_number": version_number,
        "username": username,
        "password": password,
    }

    results = {}  # Shared dictionary to store results from threads
    threads = []

    # Create and start threads for each endpoint
    for endpoint_name, endpoint_url in endpoints.items():
        thread = threading.Thread(
            target=make_request, args=(endpoint_name, endpoint_url, params, results)
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    return results


def main():
    username = "mohamed.elsaadi"  # Replace with your username
    password = "Messo_1245"  # Replace with your password

    results = test_api_endpoints_concurrently(username, password)

    # Print the results
    for endpoint_name, result in results.items():
        print(f"Results for {endpoint_name}:")
        print(f"  Status Code: {result['status_code']}")
        if result["response_time"] is not None:
            print(f"  Response Time: {result['response_time']:.4f} seconds")
        if result["response_body"]:
            print(f"  Response Body:\n{result['response_body']}")
        if result["error"]:
            print(f"  Error: {result['error']}")
        print("-" * 30)


if __name__ == "__main__":
    main()
