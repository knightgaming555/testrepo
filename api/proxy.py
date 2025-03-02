from flask import Flask, request, Response, abort, jsonify
import requests
from requests_ntlm import HttpNtlmAuth
from io import BytesIO
import PyPDF2

app = Flask(__name__)


@app.route("/api/proxy", methods=["GET"])
def download_file():
    # Retrieve query parameters.
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")

    if not username or not password or not file_url:
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )

    try:
        # Perform a GET request with NTLM authentication.
        response = requests.get(
            file_url, auth=HttpNtlmAuth(username, password), stream=True
        )

        if response.status_code != 200:
            abort(response.status_code, f"Error from CMS server: {response.text}")

        # Retrieve content type from the CMS response or use a default.
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
    # Retrieve query parameters.
    username = request.args.get("username")
    password = request.args.get("password")
    file_url = request.args.get("fileUrl")

    if not username or not password or not file_url:
        abort(
            400, "Missing one or more required parameters: username, password, fileUrl"
        )

    try:
        # Fetch the PDF using NTLM authentication.
        response = requests.get(file_url, auth=HttpNtlmAuth(username, password))
        if response.status_code != 200:
            abort(response.status_code, f"Error from CMS server: {response.text}")

        # Read PDF content into a BytesIO buffer.
        pdf_bytes = BytesIO(response.content)

        # Use PyPDF2 to extract text from the PDF.
        reader = PyPDF2.PdfReader(pdf_bytes)
        extracted_text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                extracted_text += page_text + "\n"

        # Return the extracted text as JSON.
        return jsonify({"text": extracted_text})
    except Exception as e:
        abort(500, f"Error extracting PDF text: {str(e)}")


if __name__ == "__main__":
    # Run the server on all available interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True)
