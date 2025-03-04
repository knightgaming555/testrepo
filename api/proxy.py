from flask import Flask, request, Response, abort, jsonify
import requests
from requests_ntlm import HttpNtlmAuth
from io import BytesIO
import re
import logging
import concurrent.futures
import PyPDF2  # Lightweight alternative to fitz

app = Flask(__name__)

# Configure logging to output debug messages.
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Set your OCR.space API key here.
OCR_API_KEY = "K85557323988957"  # Replace with your actual key


@app.route("/api/proxy", methods=["GET"])
def download_file():
    logger.debug("Entered download_file endpoint")
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")
    logger.debug("Parameters: username=%s, file_url=%s", username, file_url)
    if not username or not password or not file_url:
        logger.error("Missing required parameters")
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )
    try:
        logger.info("Fetching file from %s", file_url)
        response = requests.get(
            file_url, auth=HttpNtlmAuth(username, password), stream=True
        )
        logger.debug("Response status code: %s", response.status_code)
        if response.status_code != 200:
            logger.error("Error from CMS server: %s", response.text)
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
        logger.info("File fetched successfully, sending response")
        return Response(generate(), headers=headers, status=200)
    except Exception as e:
        logger.exception("Error fetching file")
        abort(500, f"Error fetching file: {str(e)}")


@app.route("/api/extract", methods=["GET"])
def extract_text():
    logger.debug("Entered extract_text endpoint")
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")
    logger.debug("Parameters: username=%s, file_url=%s", username, file_url)
    if not username or not password or not file_url:
        logger.error("Missing required parameters")
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )

    try:
        logger.info("Fetching PDF from %s", file_url)
        response = requests.get(file_url, auth=HttpNtlmAuth(username, password))
        logger.debug("Response status code: %s", response.status_code)
        if response.status_code != 200:
            logger.error("Error from CMS server: %s", response.text)
            abort(response.status_code, f"Error from CMS server: {response.text}")

        pdf_bytes = BytesIO(response.content)
        pdf_bytes.seek(0)
        reader = PyPDF2.PdfReader(pdf_bytes)
        num_pages = len(reader.pages)
        logger.info("PDF loaded successfully, number of pages: %d", num_pages)

        # Check first page for selectable text.
        first_page = reader.pages[0]
        first_page_text = first_page.extract_text() or ""
        if first_page_text.strip():
            logger.info("Selectable text found on first page; using text extraction")

            # Define a function to extract text concurrently.
            def extract_page_text(page, page_num):
                logger.debug("Extracting text from page %d", page_num)
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
            logger.info(
                "No selectable text on first page; falling back to OCR concurrently"
            )

            # Define a function to perform OCR on a single page by creating a one-page PDF.
            def ocr_page(page, page_num):
                logger.debug("Performing OCR on page %d", page_num)
                writer = PyPDF2.PdfWriter()
                writer.add_page(page)
                page_buffer = BytesIO()
                writer.write(page_buffer)
                page_buffer.seek(0)
                files = {
                    "file": (f"page_{page_num}.pdf", page_buffer, "application/pdf")
                }
                # Additional parameters to potentially improve OCR accuracy.
                data = {
                    "apikey": OCR_API_KEY,
                    "OCREngine": "2",
                    "scale": "true",  # Upscale image before processing
                    "language": "eng",  # Set expected language (change if needed)
                    "detectOrientation": "true",  # Helps if the page is rotated
                    "isOverlayRequired": "false",
                }
                logger.debug(
                    "Sending OCR request for page %d with data: %s", page_num, data
                )
                ocr_response = requests.post(
                    "https://api.ocr.space/parse/image", data=data, files=files
                )
                logger.debug(
                    "OCR.space response for page %d, status: %s",
                    page_num,
                    ocr_response.status_code,
                )
                page_result = ocr_response.json()
                logger.debug(
                    "OCR.space response JSON for page %d: %s", page_num, page_result
                )
                if (
                    page_result.get("ParsedResults")
                    and len(page_result["ParsedResults"]) > 0
                ):
                    return page_result["ParsedResults"][0]["ParsedText"]
                else:
                    logger.error("OCR.space extraction failed for page %d", page_num)
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
            # Cleanup common artifacts.
            extracted_text = extracted_text.replace("\f", "\n")
            extracted_text = re.sub(r"\(cid:\d+\)", "", extracted_text)
            logger.info("OCR completed on PDF with concurrent page-by-page requests")

        logger.debug("Extracted text length: %d characters", len(extracted_text))
        return jsonify({"text": extracted_text})
    except Exception as e:
        logger.exception("Error extracting PDF text")
        abort(500, f"Error extracting PDF text: {str(e)}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
