# importing required libraries

from flask import Flask, request, render_template, redirect, url_for
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import os
from src.convert import convertion

warnings.filterwarnings("ignore")

# Import the new pipeline
from src.pipeline.manager import PhishingDetectionPipeline, SAFE, WARNING, PHISHING

# Initialize the pipeline
pipeline = PhishingDetectionPipeline()

app = Flask(__name__)


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

    if not status.get("success"):
        return render_template(
            "error.html", message="Sandbox analysis failed or not completed."
        ), 404

    sandbox_data = {
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
        "screenshot_base64": status.get("screenshot_base64"),
    }

    layers = status.get("layers", {})
    forensics = status.get("forensics", {})
    final_status = status.get("final_status", "Safe")

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

    return render_template(
        "sandbox_results.html",
        sandbox=sandbox_data,
        scan_id=scan_id,
        verdict=verdict,
        verdict_text=verdict_text,
        verdict_icon=verdict_icon,
        result={"status": final_status},
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


if __name__ == "__main__":
    app.run(debug=True)
