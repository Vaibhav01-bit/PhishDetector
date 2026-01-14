 #importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
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
        
        # Analyze using the 5-layer pipeline
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

if __name__ == "__main__":
    app.run(debug=True)
