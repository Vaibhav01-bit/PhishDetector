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
        
        # Determine Verdict Flags
        status = result['status']
        is_safe = (status == SAFE)
        
        # AJAX Response (For Progressive Timeline)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            from flask import jsonify
            return jsonify({
                "status": status,
                "is_safe": is_safe,
                "url": url,
                "details": result # Pass full details if needed later
            })

        # Fallback: Legacy Template Rendering
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
        result_path = os.path.join(app.root_path, 'static', 'sandbox_results', f"{scan_id}_full.json")
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

@app.route('/scan_email', methods=['POST'])
def scan_email():
    """
    Endpoint for identifying and scanning URLs within email text.
    """
    from pipeline.email_utils import extract_urls_from_text
    
    email_text = request.form.get('email_text', '')
    if not email_text:
        return render_template('index.html', error="No text provided")
        
    extracted_urls = extract_urls_from_text(email_text)
    
    # Limit number of URLs to prevent abuse
    extracted_urls = extracted_urls[:10]
    
    scan_results = []
    
    for url in extracted_urls:
        # Run pipeline on each URL
        try:
            res = pipeline.analyze(url)
            status = res['status']
            
            # Simple verdict for the summary list
            verdict_class = "text-success"
            icon = "bx-check-circle"
            
            if status == "Phishing":
                verdict_class = "text-danger"
                icon = "bx-x-circle"
            elif status == "Warning":
                verdict_class = "text-warning"
                icon = "bx-error"
                
            scan_results.append({
                'url': url,
                'status': status,
                'class': verdict_class,
                'icon': icon,
                'details': res
            })
        except Exception as e:
            scan_results.append({
                'url': url,
                'status': "Error",
                'class': "text-secondary",
                'icon': "bx-help-circle",
                'details': str(e)
            })
            
    return render_template('index.html', email_results=scan_results, email_text_preview=email_text[:100] + "...")

@app.route('/rescan', methods=['POST'])
def rescan_url():
    """Re-scan a URL from sandbox page."""
    url = request.form.get('url')
    if url:
        # Redirect to result page with POST data
        return render_template('index.html', rescan_url=url)
    return redirect(url_for('home'))


# ─────────────────────────────────────────────────────────────────────────────
# ULTRA-FAST PROGRESSIVE SCAN ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/scan/fast', methods=['POST'])
def scan_fast():
    """
    FAST PATH: Runs layers 1-5 only (zero sandbox) and returns a preliminary
    verdict within ~1-3 seconds. Also launches sandbox in the background.
    """
    from flask import jsonify
    url = request.form.get('name') or request.json.get('name', '') if request.is_json else request.form.get('name', '')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        result = pipeline.analyze_fast(url)
        scan_id = result['scan_id']

        # Kick off sandbox in background — does NOT block this response
        if pipeline.sandbox:
            pipeline.run_sandbox_background(url, scan_id)

        return jsonify({
            'status':      result['status'],
            'is_safe':     result['status'] == 'Safe',
            'is_warning':  result['status'] == 'Warning',
            'url':         url,
            'scan_id':     scan_id,
            'preliminary': True,
            'layers':      result.get('layers', {}),
            'forensics':   result.get('forensics', {})
        })
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500


@app.route('/scan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    """
    Polling endpoint: Returns sandbox completion status for a given scan_id.
    Frontend calls this every ~1.5s after receiving the fast verdict.
    """
    from flask import jsonify
    import re

    # Security: validate scan_id format (alphanumeric + underscore/hyphen only)
    if not re.match(r'^[a-zA-Z0-9_\-]{1,64}$', scan_id):
        return jsonify({'error': 'Invalid scan ID'}), 400

    status = pipeline.get_sandbox_status(scan_id)
    if status is None:
        # Not done yet
        return jsonify({'done': False, 'scan_id': scan_id})

    # Build screenshot URL if available
    screenshot_url = None
    if status.get('screenshot_path'):
        screenshot_url = f"/sandbox_screenshot/{status['screenshot_path']}"

    return jsonify({
        'done':              True,
        'success':           status.get('success', False),
        'scan_id':           scan_id,
        'screenshot_url':    screenshot_url,
        'sandbox_page_url':  f"/sandbox/{scan_id}" if status.get('success') else None,
        'has_login_form':    status.get('has_login_form', False),
        'has_password_field':status.get('has_password_field', False),
        'error':             status.get('error')
    })


if __name__ == "__main__":
    app.run(debug=True)
