
import time
from pipeline.brand_impersonation import BrandImpersonationDetector

def benchmark():
    detector = BrandImpersonationDetector()
    
    test_urls = [
        "https://www.google.com",
        "https://example.com/some/random/path",
        "https://secure-paypal-login-attempt.com/verify?token=123",
        "https://very-long-domain-name-that-is-suspiciously-long-and-might-cause-issues.com/very/long/path/with/many/segments/and/tokens/that/increases/complexity",
        "https://amazon-security-alert-urgent-update-required.com/login/account/verify/identity?ref=1234567890&session=abcdefghijklmnopqrstuvwxyz",
        "https://apple-id-verification-secure.com/" * 50 # Extremely long URL to stress test
    ]
    
    print(f"{'URL Type':<30} | {'Time (ms)':<10}")
    print("-" * 45)
    
    # Warmup
    detector.check("https://google.com")
    
    for url in test_urls:
        start_time = time.time()
        # Truncate to avoid excessive processing on the extreme case if it's still linear but huge
        # But we want to test speed, so let's pass it fully but expect it to be faster now
        check_url = url[:2000] 
        detector.check(check_url)
        end_time = time.time()
        
        duration_ms = (end_time - start_time) * 1000
        print(f"{url[:30]:<30} | {duration_ms:.2f}")

if __name__ == "__main__":
    print("Running Verification Benchmarks...")
    benchmark()
