from flask import Flask, request, Response, abort, jsonify
import requests
from requests_ntlm import HttpNtlmAuth
from io import BytesIO
import re
import concurrent.futures
import PyPDF2  # Lightweight alternative to fitz

app = Flask(__name__)

# Set your OCR.space API key here.
OCR_API_KEY = "K85557323988957"  # Replace with your actual key


@app.route("/api/proxy", methods=["GET"])
def download_file():
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")
    if not username or not password or not file_url:
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )
    try:
        response = requests.get(
            file_url, auth=HttpNtlmAuth(username, password), stream=True
        )
        if response.status_code != 200:
            abort(response.status_code, f"Error from CMS server: {response.text}")
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        file_name = file_url.split("/")[-1] or "downloaded_file"

        def generate():
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk

        headers = {
            "Content-Disposition": f'attachment; filename="{file_name}"',
            "Content-Type": content_type,
        }
        return Response(generate(), headers=headers, status=200)
    except Exception as e:
        abort(500, f"Error fetching file: {str(e)}")


@app.route("/api/extract", methods=["GET"])
def extract_text():
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")
    if not username or not password or not file_url:
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )
    try:
        response = requests.get(file_url, auth=HttpNtlmAuth(username, password))
        if response.status_code != 200:
            abort(response.status_code, f"Error from CMS server: {response.text}")
        pdf_bytes = BytesIO(response.content)
        pdf_bytes.seek(0)
        reader = PyPDF2.PdfReader(pdf_bytes)
        num_pages = len(reader.pages)

        first_page = reader.pages[0]
        first_page_text = first_page.extract_text() or ""
        if first_page_text.strip():

            def extract_page_text(page, page_num):
                return page.extract_text() or ""

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=num_pages
            ) as executor:
                future_to_index = {
                    executor.submit(extract_page_text, reader.pages[i], i + 1): i
                    for i in range(num_pages)
                }
                results = ["" for _ in range(num_pages)]
                for future in concurrent.futures.as_completed(future_to_index):
                    index = future_to_index[future]
                    results[index] = future.result()
            extracted_text = "\n".join(results)
        else:

            def ocr_page(page, page_num):
                writer = PyPDF2.PdfWriter()
                writer.add_page(page)
                page_buffer = BytesIO()
                writer.write(page_buffer)
                page_buffer.seek(0)
                files = {
                    "file": (f"page_{page_num}.pdf", page_buffer, "application/pdf")
                }
                data = {
                    "apikey": OCR_API_KEY,
                    "OCREngine": "2",
                    "scale": "true",
                    "language": "eng",
                    "detectOrientation": "true",
                    "isOverlayRequired": "false",
                }
                ocr_response = requests.post(
                    "https://api.ocr.space/parse/image", data=data, files=files
                )
                page_result = ocr_response.json()
                if (
                    page_result.get("ParsedResults")
                    and len(page_result["ParsedResults"]) > 0
                ):
                    return page_result["ParsedResults"][0]["ParsedText"]
                else:
                    return ""

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=num_pages
            ) as executor:
                future_to_index = {
                    executor.submit(ocr_page, reader.pages[i], i + 1): i
                    for i in range(num_pages)
                }
                results = ["" for _ in range(num_pages)]
                for future in concurrent.futures.as_completed(future_to_index):
                    index = future_to_index[future]
                    results[index] = future.result()
            extracted_text = "\n".join(results)
            extracted_text = extracted_text.replace("\f", "\n")
            extracted_text = re.sub(r"\(cid:\d+\)", "", extracted_text)
        return jsonify({"text": extracted_text})
    except Exception as e:
        abort(500, f"Error extracting PDF text: {str(e)}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
