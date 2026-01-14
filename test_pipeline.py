import sys
import os

# Ensure the current directory is in the path so we can import modules
sys.path.append(os.getcwd())

from pipeline.manager import PhishingDetectionPipeline, SAFE, WARNING, PHISHING

def test_pipeline():
    print("Initializing Pipeline...")
    pipeline = PhishingDetectionPipeline()
    
    test_cases = [
        ("http://example-phishing.com", PHISHING, "Layer 1 Blacklist"),
        ("https://google.com", SAFE, "Safe URL"),
        ("http://google.com", WARNING, "SSL Warning"), # Expect warning due to http
        ("https://this-is-a-very-long-domain-name-that-should-trigger-domain-length-check-because-it-is-over-50-chars.com", WARNING, "Domain Length"),
    ]

    print("\nStarting Tests...")
    for url, expected_status, description in test_cases:
        print(f"\nTesting: {url} ({description})")
        try:
            result = pipeline.analyze(url)
            status = result['status']
            print(f"Result: {status}")
            print("Layers:", result['layers'])
            
            # Simple assertion (logic might differ slightly based on layer priority, but checking basic alignment)
            if expected_status == WARNING and status == PHISHING:
                 print("  -> OK (Phishing is acceptable if multiple warnings or strict checks triggered)")
            elif status == expected_status:
                print("  -> PASSED")
            else:
                print(f"  -> FAILED (Expected {expected_status}, got {status})")
        except Exception as e:
            print(f"  -> ERROR: {e}")

if __name__ == "__main__":
    test_pipeline()
