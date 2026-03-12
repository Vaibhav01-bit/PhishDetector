import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from run import app

def test_api_route():
    print("Testing /api/scan/fast route...")
    client = app.test_client()
    
    urls_to_test = [
        "http://google.com",
        "invalid_url",
        ""
    ]
    
    for url in urls_to_test:
        print(f"\n--- POST /api/scan/fast with name='{url}' ---")
        try:
            response = client.post('/api/scan/fast', json={'name': url})
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.data.decode('utf-8')[:200]}")
        except Exception as e:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    app.config['TESTING'] = True
    test_api_route()
