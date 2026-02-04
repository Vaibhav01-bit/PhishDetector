 #importing required libraries

from flask import Flask, request, render_template, send_from_directory, redirect, url_for
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
import os
from convert import convertion
warnings.filterwarnings('ignore')

# Import the new pipeline
from pipeline.manager import PhishingDetectionPipeline, SAFE, WARNING, PHISHING

# Initialize the pipeline
pipeline = PhishingDetectionPipeline()

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result',methods=['POST','GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        
        # Analyze using the 5-layer pipeline (+ sandbox)
        result = pipeline.analyze(url)
        
        # Map pipeline result to the legacy format expected by the template
        # format: [url, status_text, button_text, is_safe_flag]
        
        status = result['status']
        if status == SAFE:
            name = [url, "Safe", "Continue", 1]
        elif status == WARNING:
            name = [url, "Suspicious", "View Anyway (Risk)", 0] # 0 is falsy
        else:
            name = [url, "Phishing", "Back to Safety", 0]

        return render_template("index.html", name=name, details=result)
        
    return render_template("index.html")

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

@app.route('/sandbox_screenshot/<filename>')
def serve_screenshot(filename):
    """Serve sandbox screenshot files securely."""
    screenshot_dir = os.path.join(app.root_path, 'static', 'sandbox_screenshots')
    
    # Security: Only allow .jpg files and prevent path traversal
    if not filename.endswith('.jpg') or '/' in filename or '\\' in filename:
        return "Invalid filename", 400
    
    return send_from_directory(screenshot_dir, filename)

@app.route('/sandbox/<scan_id>')
def sandbox_results(scan_id):
    """Display dedicated sandbox analysis page."""
    from pipeline.sandbox import SandboxAnalyzer
    import json
    import os
    
    # Security: Validate scan_id format
    if not scan_id or '/' in scan_id or '\\' in scan_id or '..' in scan_id:
        return render_template('error.html', 
                             message="Invalid scan ID"), 400
    
    analyzer = SandboxAnalyzer()
    sandbox_data = analyzer.get_result(scan_id)
    
    if not sandbox_data:
        return render_template('error.html', 
                             message="Sandbox result not found. The scan may have expired."), 404
    
    # Try to load full pipeline results (includes 5-layer analysis)
    full_results = None
    try:
        # Check if there's a corresponding full result file
        result_path = os.path.join('static', 'sandbox_results', f"{scan_id}_full.json")
        if os.path.exists(result_path):
            with open(result_path, 'r', encoding='utf-8') as f:
                full_results = json.load(f)
    except Exception as e:
        print(f"Could not load full results: {e}")
    
    # Determine verdict for display
    verdict = "safe"
    verdict_text = "Safe"
    verdict_icon = "bx-shield-check"
    
    # Enhanced verdict logic based on behavioral flags
    if sandbox_data.get('has_login_form') or sandbox_data.get('has_password_field'):
        verdict = "warning"
        verdict_text = "Warning"
        verdict_icon = "bx-error"
    
    # If we have full results, use the overall status
    if full_results and full_results.get('status'):
        status = full_results['status']
        if status == 'PHISHING':
            verdict = "danger"
            verdict_text = "Dangerous"
            verdict_icon = "bx-error-circle"
        elif status == 'WARNING':
            verdict = "warning"
            verdict_text = "Warning"
            verdict_icon = "bx-error"
    
    return render_template('sandbox_results.html', 
                         sandbox=sandbox_data,
                         scan_id=scan_id,
                         verdict=verdict,
                         verdict_text=verdict_text,
                         verdict_icon=verdict_icon,
                         result=full_results,
                         layers=full_results.get('layers') if full_results else None,
                         forensics=full_results.get('forensics') if full_results else None)

@app.route('/rescan', methods=['POST'])
def rescan_url():
    """Re-scan a URL from sandbox page."""
    url = request.form.get('url')
    if url:
        # Redirect to result page with POST data
        return render_template('index.html', rescan_url=url)
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
