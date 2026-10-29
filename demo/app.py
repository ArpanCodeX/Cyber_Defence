import json
import os
from urllib import request as http_request
from urllib.error import URLError
from flask import Flask, jsonify, request
app = Flask(__name__)

EVENT_API_URL = os.getenv("EVENT_API_URL", "")
EVENT_SITE_KEY = os.getenv("EVENT_SITE_KEY", "")
EVENT_SITE_ID = os.getenv("EVENT_SITE_ID", "demo")

def report_event():
    if not EVENT_API_URL or not EVENT_SITE_KEY:
        return None
    payload = {
        "site_id": EVENT_SITE_ID,
        "source_ip": request.headers.get("X-Demo-Client-IP", request.remote_addr or "127.0.0.1"),
        "path": request.full_path.rstrip("?") or "/",
        "method": request.method,
        "body": request.get_data(as_text=True)[:10000],
        "failed_login": request.path == "/login" and request.args.get("failed") == "1",
    }
    try:
        req = http_request.Request(
            EVENT_API_URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-Site-Key": EVENT_SITE_KEY},
            method="POST",
        )
        with http_request.urlopen(req, timeout=1) as response:
            return response.status, json.loads(response.read())
    except (URLError, TimeoutError, ValueError):
        return None

@app.get("/health")
def health():
    return jsonify(status="healthy")

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def site(path):
    reported = report_event()
    if reported and reported[0] in (403, 429):
        return jsonify(error="request blocked by security policy", security_event=reported[1]), reported[0]
    return jsonify(service="authorized demo website", path="/" + path, method=request.method)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)