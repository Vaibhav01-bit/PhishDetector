"""Quick test of brand impersonation detection"""
from pipeline.brand_impersonation import BrandImpersonationDetector

detector = BrandImpersonationDetector()

# Test cases
tests = [
    ("https://www.youtube.com/watch", False, "Legitimate YouTube"),
    ("https://youtubee-login.com", True, "YouTube typosquatting"),
    ("https://paypal.com/myaccount", False, "Legitimate PayPal"),
    ("https://paypal-login-secure.com", True, "PayPal phishing"),
    ("https://google.com", False, "Legitimate Google"),
    ("https://g00gle-accounts.com", True, "Google homoglyph"),
]

print("Brand Impersonation Detection - Quick Test")
print("=" * 80)

passed = 0
failed = 0

for url, expected, description in tests:
    result = detector.check(url)
    actual = result['is_impersonation']
    status = "✓" if actual == expected else "✗"
    
    if actual == expected:
        passed += 1
    else:
        failed += 1
    
    print(f"\n{status} {description}")
    print(f"  URL: {url}")
    print(f"  Expected: {expected}, Got: {actual}, Score: {result['risk_score']}")
    if result['message']:
        print(f"  Message: {result['message']}")

print("\n" + "=" * 80)
print(f"Results: {passed} passed, {failed} failed")
print("=" * 80)
