# importing required libraries

from flask import Flask, request, render_template, redirect, url_for
from flask_cors import CORS
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import os
from dotenv import load_dotenv
from src.convert import convertion

# Load environment variables from .env file
load_dotenv()

warnings.filterwarnings("ignore")

# Import the new pipeline
from src.pipeline.manager import PhishingDetectionPipeline, SAFE, WARNING, PHISHING

# Initialize the pipeline
pipeline = PhishingDetectionPipeline()

app = Flask(__name__)

# Enable CORS for all API endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration from environment variables
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(24))
app.config["TELEGRAM_BOT_TOKEN"] = os.getenv("TELEGRAM_BOT_TOKEN")
app.config["TELEGRAM_CHAT_ID"] = os.getenv("TELEGRAM_CHAT_ID")


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/result", methods=["POST", "GET"])
def predict():
    if request.method == "POST":
        url = request.form["name"]

        # Analyze using the 5-layer pipeline (+ sandbox)
        result = pipeline.analyze(url)

        # Determine Verdict Flags
        status = result["status"]
        is_safe = status == SAFE

        # AJAX Response (For Progressive Timeline)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            from flask import jsonify

            return jsonify(
                {"status": status, "is_safe": is_safe, "url": url, "details": result}
            )

        # Fallback: Legacy Template Rendering
        if status == SAFE:
            name = [url, "Safe", "Continue", 1]
        elif status == WARNING:
            name = [url, "Suspicious", "View Anyway (Risk)", 0]
        else:
            name = [url, "Phishing", "Back to Safety", 0]

        return render_template("index.html", name=name, details=result)

    return render_template("index.html")


@app.route("/usecases", methods=["GET", "POST"])
def usecases():
    return render_template("usecases.html")


@app.route("/sandbox/<scan_id>")
def sandbox_results(scan_id):
    """
    Display dedicated sandbox analysis page.
    NO DATA IS STORED - reads from in-memory store only.
    """
    import re

    if not scan_id or "/" in scan_id or "\\" in scan_id or ".." in scan_id:
        return render_template("error.html", message="Invalid scan ID"), 400

    if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", scan_id):
        return render_template("error.html", message="Invalid scan ID"), 400

    status = pipeline.get_sandbox_status(scan_id)

    if not status:
        return render_template(
            "error.html", message="Scan not found or expired. Please scan again."
        ), 404

    sandbox_data = {
        "source_url": status.get("source_url", "Unknown"),
        "final_url": status.get("final_url"),
        "ip_address": status.get("ip_address"),
        "domain": status.get("domain"),
        "page_title": status.get("page_title"),
        "redirect_count": status.get("redirect_count", 0),
        "load_time": status.get("load_time", 0),
        "timestamp": status.get("timestamp"),
        "has_login_form": status.get("has_login_form", False),
        "has_password_field": status.get("has_password_field", False),
        "has_email_field": status.get("has_email_field", False),
        "suspicious_keywords": status.get("suspicious_keywords", []),
        "screenshot_base64": status.get("screenshot_base64"),
        "error": status.get("error"),
    }

    layers = status.get("layers", {})
    forensics = status.get("forensics", {})
    final_status = status.get("final_status", "Safe")
    sandbox_success = status.get("success", False)

    verdict = "safe"
    verdict_text = "Safe"
    verdict_icon = "bx-shield-check"

    if sandbox_data.get("has_login_form") or sandbox_data.get("has_password_field"):
        verdict = "warning"
        verdict_text = "Warning"
        verdict_icon = "bx-error"

    if final_status == "Phishing":
        verdict = "danger"
        verdict_text = "Dangerous"
        verdict_icon = "bx-error-circle"
    elif final_status == "Warning":
        verdict = "warning"
        verdict_text = "Warning"
        verdict_icon = "bx-error"
    elif not sandbox_success:
        verdict = "info"
        verdict_text = "Partial Results"
        verdict_icon = "bx-info-circle"

    return render_template(
        "sandbox_results.html",
        sandbox=sandbox_data,
        scan_id=scan_id,
        verdict=verdict,
        verdict_text=verdict_text,
        verdict_icon=verdict_icon,
        result={"status": final_status, "sandbox_success": sandbox_success},
        layers=layers,
        forensics=forensics,
    )


@app.route("/scan_email", methods=["POST"])
def scan_email():
    """
    Endpoint for identifying and scanning URLs within email text.
    """
    from src.pipeline.email_utils import extract_urls_from_text

    email_text = request.form.get("email_text", "")
    if not email_text:
        return render_template("index.html", error="No text provided")

    extracted_urls = extract_urls_from_text(email_text)

    extracted_urls = extracted_urls[:10]

    scan_results = []

    for url in extracted_urls:
        try:
            res = pipeline.analyze(url)
            status = res["status"]

            verdict_class = "text-success"
            icon = "bx-check-circle"

            if status == "Phishing":
                verdict_class = "text-danger"
                icon = "bx-x-circle"
            elif status == "Warning":
                verdict_class = "text-warning"
                icon = "bx-error"

            scan_results.append(
                {
                    "url": url,
                    "status": status,
                    "class": verdict_class,
                    "icon": icon,
                    "details": res,
                }
            )
        except Exception as e:
            scan_results.append(
                {
                    "url": url,
                    "status": "Error",
                    "class": "text-secondary",
                    "icon": "bx-help-circle",
                    "details": str(e),
                }
            )

    return render_template(
        "index.html",
        email_results=scan_results,
        email_text_preview=email_text[:100] + "...",
    )


@app.route("/api/scan_email", methods=["POST"])
def api_scan_email():
    """
    AJAX endpoint for enhanced email scanning.
    Returns JSON response for progressive UI.
    """
    from flask import jsonify
    from src.pipeline.email_analyzer import EmailAnalyzer

    email_text = request.form.get("email_text", "")

    if not email_text:
        return jsonify({"success": False, "error": "No email content provided"}), 400

    MAX_EMAIL_SIZE = 100 * 1024
    if len(email_text) > MAX_EMAIL_SIZE:
        return jsonify(
            {
                "success": False,
                "error": f"Email content exceeds {MAX_EMAIL_SIZE // 1024}KB limit",
            }
        ), 400

    attachment = request.files.get("attachment") if request.files else None

    try:
        analyzer = EmailAnalyzer()
        result = analyzer.analyze(email_text, attachment)
        return jsonify(result)
    except Exception as e:
        import traceback
        import sys

        error_trace = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        print(f"[Email Scan Error] {error_trace}", file=sys.stderr)

        return jsonify(
            {
                "success": False,
                "error": str(e),
                "trace": error_trace if app.debug else None,
            }
        ), 500


@app.route("/rescan", methods=["POST"])
def rescan_url():
    """Re-scan a URL from sandbox page."""
    url = request.form.get("url")
    if url:
        return render_template("index.html", rescan_url=url)
    return redirect(url_for("home"))


# ─────────────────────────────────────────────────────────────────────────────
# ULTRA-FAST PROGRESSIVE SCAN ENDPOINTS
# NO DATA IS STORED - All results are in-memory only
# ─────────────────────────────────────────────────────────────────────────────


@app.route("/scan/fast", methods=["POST"])
def scan_fast():
    """
    FAST PATH: Runs layers 1-5 only (zero sandbox) and returns a preliminary
    verdict within ~1-3 seconds. Also launches sandbox in the background.
    NO DATA IS STORED - all processing is in-memory.
    """
    from flask import jsonify

    url = (
        request.form.get("name") or request.json.get("name", "")
        if request.is_json
        else request.form.get("name", "")
    )
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        result = pipeline.analyze_fast(url)
        scan_id = result["scan_id"]

        # Kick off sandbox in background — does NOT block this response
        if pipeline.sandbox:
            pipeline.run_sandbox_background(url, scan_id)

        return jsonify(
            {
                "status": result["status"],
                "is_safe": result["status"] == "Safe",
                "is_warning": result["status"] == "Warning",
                "url": url,
                "scan_id": scan_id,
                "preliminary": True,
                "layers": result.get("layers", {}),
                "forensics": result.get("forensics", {}),
            }
        )
    except Exception as e:
        import traceback

        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/scan/status/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    """
    Polling endpoint: Returns sandbox completion status for a given scan_id.
    Frontend calls this every ~1.5s after receiving the fast verdict.
    NO DATA IS STORED - all data is in-memory only.
    """
    from flask import jsonify
    import re

    if not re.match(r"^[a-zA-Z0-9_\-]{1,64}$", scan_id):
        return jsonify({"error": "Invalid scan ID"}), 400

    status = pipeline.get_sandbox_status(scan_id)
    if status is None:
        return jsonify({"done": False, "scan_id": scan_id})

    return jsonify(
        {
            "done": True,
            "success": status.get("success", False),
            "scan_id": scan_id,
            "screenshot": status.get("screenshot_base64"),
            "source_url": status.get("source_url"),
            "final_url": status.get("final_url"),
            "ip_address": status.get("ip_address"),
            "domain": status.get("domain"),
            "page_title": status.get("page_title"),
            "redirect_count": status.get("redirect_count", 0),
            "load_time": status.get("load_time", 0),
            "timestamp": status.get("timestamp"),
            "has_login_form": status.get("has_login_form", False),
            "has_password_field": status.get("has_password_field", False),
            "has_email_field": status.get("has_email_field", False),
            "suspicious_keywords": status.get("suspicious_keywords", []),
            "sandbox_message": status.get("sandbox_message"),
            "error": status.get("error"),
            "layers": status.get("layers", {}),
            "forensics": status.get("forensics", {}),
            "final_status": status.get("final_status", "Safe"),
        }
    )


@app.route("/scan-file", methods=["POST"])
def scan_file():
    """
    Upload and analyze a file for security threats.
    NO DATA IS STORED - All processing in memory.
    Files are never written to disk.
    """
    from flask import jsonify
    from src.pipeline.file_scanner import FileSecurityScanner

    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return jsonify({"error": "No file provided"}), 400

    filename = uploaded_file.filename
    if not filename:
        return jsonify({"error": "No file provided"}), 400

    try:
        file_bytes = uploaded_file.read()
    except Exception as e:
        return jsonify({"error": "Could not read file"}), 400

    scanner = FileSecurityScanner(phishing_pipeline=pipeline)

    try:
        result = scanner.analyze(file_bytes, filename)
    except Exception as e:
        import traceback

        print(traceback.format_exc())
        return jsonify({"error": "File could not be analyzed", "details": str(e)}), 500
    finally:
        del file_bytes

    return jsonify(result)


@app.route("/api/scan_qr", methods=["POST"])
def api_scan_qr():
    """
    Analyze QR code for security threats.
    NO DATA IS STORED - All processing in memory.

    Accepts:
    - qr_content: Direct text content from QR code
    - qr_image: Base64 encoded QR image
    """
    from flask import jsonify, request
    from src.pipeline.qr_analyzer import QRAnalyzer

    # Get data from form or JSON body
    if request.is_json:
        data = request.get_json()
        qr_content = data.get("qr_content", "") or ""
        qr_image = data.get("qr_image", "") or ""
    else:
        qr_content = request.form.get("qr_content", "") or ""
        qr_image = request.form.get("qr_image", "") or ""

    print(
        f"[QR API] Request - content: '{str(qr_content)[:30]}...', image length: {len(qr_image)}"
    )

    # Validate image size (limit to 10MB base64)
    if qr_image and len(qr_image) > 10 * 1024 * 1024:
        print("[QR API] Image too large")
        return jsonify(
            {
                "success": False,
                "error": "Image too large. Please use a smaller image.",
                "risk_score": 0,
                "risk_level": "Safe",
            }
        ), 400

    if not qr_content and not qr_image:
        print("[QR API] No content provided")
        return jsonify({"error": "No QR content or image provided"}), 400

    try:
        analyzer = QRAnalyzer()

        if qr_image and not qr_content:
            print("[QR API] Decoding image...")
            qr_content = analyzer.decode_from_image(qr_image)
            print(f"[QR API] Decoded: {qr_content}")
            if not qr_content:
                print("[QR API] No QR code found in image")
                return jsonify(
                    {
                        "success": False,
                        "error": "No QR code found in the image. Please ensure the image contains a visible QR code.",
                        "risk_score": 0,
                        "risk_level": "Safe",
                    }
                ), 200  # Return 200 with success:false, not 400

        print(f"[QR API] Analyzing: {str(qr_content)[:50]}...")
        result = analyzer.analyze(qr_content, qr_image)
        print(f"[QR API] Result: {result.get('risk_level')}")

        del qr_image

        return jsonify(result)

    except Exception as e:
        import traceback

        print(f"[QR API] Error: {traceback.format_exc()}")
        return jsonify(
            {"success": False, "error": str(e), "risk_score": 0, "risk_level": "Safe"}
        ), 500


if __name__ == "__main__":
    app.run(debug=True)
