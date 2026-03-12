import sys
import os
sys.path.append(os.getcwd())
from pipeline.manager import PhishingDetectionPipeline
import logging

logging.basicConfig(level=logging.INFO)

def test_pipeline():
    pipeline = PhishingDetectionPipeline()
    url = "http://google.com"
    print(f"Analyzing {url}...")
    result = pipeline.analyze(url)
    print("Result:", result)
    
    url_phish = "http://phishing-site.example.com"
    print(f"Analyzing {url_phish}...")
    result_phish = pipeline.analyze(url_phish)
    print("Result:", result_phish)

if __name__ == "__main__":
    test_pipeline()
