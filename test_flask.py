import sys
import os

# Add to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from run import app

def test_result_route():
    print("Testing /result route...")
    client = app.test_client()
    
    # Try different payloads
    urls_to_test = [
        "http://google.com",
        "google", # A malformed URL
        "",
    ]
    
    for url in urls_to_test:
        print(f"\n--- POST /result with name='{url}' ---")
        try:
            response = client.post('/result', data={'name': url})
            print(f"Status Code: {response.status_code}")
            if response.status_code == 500:
                print("500 Error encountered! Traceback should be above.")
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    app.config['TESTING'] = True
    test_result_route()
