import requests
from bs4 import BeautifulSoup
import re


def extract_announcements(html_content):
    """
    Parses the provided HTML to extract announcements.

    - For each <p> tag, it looks for a leading number followed by a dash or dot.
    - Announcements with a number are cleaned (removing the number and punctuation)
      and sorted in ascending order.
    - Announcements without a number are preserved in their original order and
      appended after the sorted announcements.

    Args:
        html_content (str): HTML string containing the announcements.

    Returns:
        list: A list of announcement strings, cleaned and sorted.
    """
    soup = BeautifulSoup(html_content, "html.parser")
    numbered = []
    non_numbered = []

    # Regex to capture a leading number followed by a dash, dot, or similar punctuation.
    pattern = re.compile(r"^\s*(\d+)[\-\–\.]\s*(.+)$")

    # Process each paragraph tag.
    for p in soup.find_all("p"):
        # Use a space as a separator to keep inline elements separated.
        text = p.get_text(separator=" ", strip=True)
        match = pattern.match(text)
        if match:
            num = int(match.group(1))
            cleaned_text = match.group(2).strip()
            numbered.append((num, cleaned_text))
        else:
            non_numbered.append(text)

    # Sort numbered announcements by their numeric value.
    numbered.sort(key=lambda x: x[0])

    # Prepare final sorted list: first the sorted numbered ones, then any non-numbered ones.
    sorted_announcements = [text for _, text in numbered] + non_numbered
    return sorted_announcements


def test_announcements_api():
    """
    Fetches the announcements from the API endpoint, extracts and sorts them,
    and then prints the refined announcement texts.
    """
    url = "https://v2-guc-scrapper.vercel.app/api/announcements"
    params = {
        "username": "Your user",
        "password": "Your pass",
        "course_url": "https://cms.guc.edu.eg/apps/student/CourseViewStn.aspx?id=2&sid=64",
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        print("Status Code:", response.status_code)
        data = response.json()

        if "announcements_html" in data:
            html_content = data["announcements_html"]
            announcements = extract_announcements(html_content)

            print("\nRefined Announcements:\n")
            for announcement in announcements:
                print(announcement)
                print("\n" + "=" * 40 + "\n")
        else:
            print("Error: 'announcements_html' key not found in the response.")
    except requests.exceptions.RequestException as e:
        print("Error during API call:", e)


if __name__ == "__main__":
    test_announcements_api()
