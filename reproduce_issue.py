
import threading
import sys
import os
import time

sys.path.append(os.getcwd())
from pipeline.sandbox import SandboxAnalyzer

def worker():
    print(f"[{threading.current_thread().name}] Starting sandbox analysis...")
    analyzer = SandboxAnalyzer()
    try:
        # simulate Flask request handling in a thread
        result = analyzer.analyze("https://example.com")
        print(f"[{threading.current_thread().name}] Result success: {result.get('success')}")
        if not result.get('success'):
            print(f"[{threading.current_thread().name}] Error: {result.get('error')}")
    except Exception as e:
        print(f"[{threading.current_thread().name}] CRITICAL ERROR: {e}")

if __name__ == "__main__":
    # Flask default is multithreaded, so reproduce with a thread
    t = threading.Thread(target=worker, name="FlaskWorkerMock")
    t.start()
    t.join()
