from flask import Flask, request, Response, abort, jsonify
import requests
from requests_ntlm import HttpNtlmAuth
from io import BytesIO
import re
import fitz  # PyMuPDF
import logging
import concurrent.futures

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
        logger.info("Opening PDF with PyMuPDF")
        pdf_bytes.seek(0)
        doc = fitz.open(stream=pdf_bytes.read(), filetype="pdf")
        logger.info("PDF opened successfully, number of pages: %d", doc.page_count)
        extracted_text = ""
        for i, page in enumerate(doc, start=1):
            logger.debug("Extracting text from page %d", i)
            page_text = page.get_text("text")
            if page_text:
                extracted_text += page_text + "\n"

        # Cleanup common artifacts.
        extracted_text = extracted_text.replace("\f", "\n")
        extracted_text = re.sub(r"\(cid:\d+\)", "", extracted_text)

        if extracted_text.strip():
            logger.info("Selectable text extracted successfully")
        else:
            logger.info(
                "No selectable text found; falling back to OCR.space per page concurrently"
            )

            # Function to perform OCR on a single page.
            def ocr_page(page, page_num):
                logger.debug("Performing OCR on page %d", page_num)
                pix = page.get_pixmap()
                img_data = pix.tobytes("png")
                files = {"file": (f"page_{page_num}.png", img_data)}
                data = {
                    "apikey": OCR_API_KEY,
                    "OCREngine": "2",
                }
                logger.debug("Sending OCR request for page %d", page_num)
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

            # Use a ThreadPoolExecutor to process OCR for all pages concurrently.
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Create a list of (page, page_num) tuples.
                pages = [(page, i) for i, page in enumerate(doc, start=1)]
                results = list(executor.map(lambda args: ocr_page(*args), pages))
            extracted_text = "\n".join(results)
            logger.info("OCR completed on PDF with concurrent page-by-page requests")

        logger.debug("Extracted text length: %d characters", len(extracted_text))
        return jsonify({"text": extracted_text})
    except Exception as e:
        logger.exception("Error extracting PDF text")
        abort(500, f"Error extracting PDF text: {str(e)}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
