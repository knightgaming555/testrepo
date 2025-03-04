import requests
import time
import concurrent.futures
from pprint import pprint

BASE_URL = "http://127.0.0.1:5000"

# Test credentials and URLs
TEST_CASES = [
    {
        "username": "mohamed.elsaadi",
        "password": "Messo@1245",
        "course_url": "https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=2&sid=64",
    },
    {
        "username": "mohamed.elsaadi",
        "password": "Messo@1245",
        "course_url": "https://cms.guc.edu.eg/apps/student/CourseViewStn?id=141&sid=64",
    },
]


def test_single_request(params):
    """Test a single API request"""
    start_time = time.time()
    response = requests.get(f"{BASE_URL}/api/cms_content", params=params)
    duration = time.time() - start_time

    return {
        "status_code": response.status_code,
        "duration": duration,
        "response": response.json() if response.ok else None,
        "url": response.url,
    }


def test_concurrent_requests(num_concurrent=3):
    """Test multiple concurrent requests"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
        futures = []
        for _ in range(num_concurrent):
            for test_case in TEST_CASES:
                futures.append(executor.submit(test_single_request, test_case))

        results = []
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


def run_performance_test():
    print("\n=== Starting Performance Tests ===\n")

    # Test 1: Single Request
    print("1. Testing single request:")
    result = test_single_request(TEST_CASES[0])
    print(f"Status Code: {result['status_code']}")
    print(f"Duration: {result['duration']:.2f} seconds")
    print(f"URL: {result['url']}")
    if result["response"]:
        print("\nSample Response:")
        pprint(result["response"])

    # Test 2: Cached Request
    print("\n2. Testing cached request (should be faster):")
    result = test_single_request(TEST_CASES[0])
    print(f"Duration: {result['duration']:.2f} seconds")

    # Test 3: Concurrent Requests
    print("\n3. Testing concurrent requests:")
    concurrent_results = test_concurrent_requests()
    avg_duration = sum(r["duration"] for r in concurrent_results) / len(
        concurrent_results
    )
    print(
        f"Average duration for {len(concurrent_results)} concurrent requests: {avg_duration:.2f} seconds"
    )

    # Test 4: Error Cases
    print("\n4. Testing error cases:")
    error_cases = [
        {},  # Missing all parameters
        {"username": "test_user"},  # Missing password and URL
        {
            "username": "invalid",
            "password": "invalid",
            "course_url": "https://example.com/course/1",
        },  # Invalid credentials
    ]

    for case in error_cases:
        result = test_single_request(case)
        print(f"\nTest case: {case}")
        print(f"Status Code: {result['status_code']}")
        if result["response"]:
            print(f"Response: {result['response']}")


if __name__ == "__main__":
    try:
        run_performance_test()
    except requests.exceptions.ConnectionError:
        print(
            "\nError: Could not connect to the server. Make sure it's running at http://127.0.0.1:5000"
        )
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
