from flask import Flask, request, Response, abort, jsonify
import requests
from requests_ntlm import HttpNtlmAuth
from io import BytesIO
import re
import concurrent.futures
import PyPDF2  # Lightweight PDF extractor

app = Flask(__name__)

# Set your OCR.space API key here (unused now)
OCR_API_KEY = "K85557323988957"  # Replace with your actual key if needed


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
        print("Fetching file from URL:", file_url)
        response = requests.get(file_url, auth=HttpNtlmAuth(username, password))
        if response.status_code != 200:
            abort(response.status_code, f"Error from CMS server: {response.text}")
        content = response.content
        # Determine file type by extension (lowercase)
        file_extension = file_url.split("/")[-1].split(".")[-1].lower()
        print("File extension detected:", file_extension)
        extracted_text = ""
        if file_extension == "pdf":
            print("Extracting text from PDF using PyPDF2...")
            pdf_bytes = BytesIO(content)
            pdf_bytes.seek(0)
            try:
                reader = PyPDF2.PdfReader(pdf_bytes)
                num_pages = len(reader.pages)
                print("Number of pages:", num_pages)

                def extract_page_text(page, page_num):
                    text = page.extract_text() or ""
                    print(
                        f"Extracted text from page {page_num}: {len(text)} characters"
                    )
                    return text

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
            except Exception as e:
                print("PyPDF2 extraction failed with error:", e)
                print("Falling back to pdfminer.six for extraction...")
                from pdfminer.high_level import extract_text

                pdf_bytes.seek(0)
                extracted_text = extract_text(pdf_bytes)
        elif file_extension == "docx":
            print("Extracting text from DOCX using python-docx...")
            import docx

            doc = docx.Document(BytesIO(content))
            paragraphs = [
                para.text for para in doc.paragraphs if para.text.strip() != ""
            ]
            extracted_text = "\n".join(paragraphs)
        elif file_extension == "pptx":
            print("Extracting text from PPTX using python-pptx...")
            from pptx import Presentation

            prs = Presentation(BytesIO(content))
            slides_text = []
            for i, slide in enumerate(prs.slides, start=1):
                slide_text = []
                for shape in slide.shapes:
                    if hasattr(shape, "text") and shape.text.strip():
                        slide_text.append(shape.text)
                slides_text.append("\n".join(slide_text))
                print(f"Slide {i} text extracted.")
            extracted_text = "\n".join(slides_text)
        else:
            print("Unsupported file type for extraction:", file_extension)
            extracted_text = "Unsupported file type for extraction."
        print("Extraction complete.")
        return jsonify({"text": extracted_text})
    except Exception as e:
        abort(500, f"Error extracting PDF text: {str(e)}")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
