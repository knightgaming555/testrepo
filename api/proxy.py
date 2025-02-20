from flask import Flask, request, Response, abort
import requests
from requests_ntlm import HttpNtlmAuth

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


if __name__ == "__main__":
    # Run the proxy server on all available interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True)
