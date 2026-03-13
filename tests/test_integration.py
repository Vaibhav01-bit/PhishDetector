"""Test brand impersonation integration with full pipeline"""

from src.pipeline.manager import PhishingDetectionPipeline

pipeline = PhishingDetectionPipeline()

# Test URLs
test_urls = [
    "https://www.youtube.com/watch",
    "https://youtubee-login.com/verify",
    "https://paypal.com",
    "https://paypal-login-secure.com/update",
    "https://google.com",
    "https://g00gle-verify.com/account",
]

print("Pipeline Integration Test - Brand Impersonation")
print("=" * 80)

for url in test_urls:
    result = pipeline.analyze(url)
    print(f"\nURL: {url}")
    print(f"Status: {result['status']}")
    print(f"Layer 2: {result['layers']['layer2']['message']}")
    print("-" * 80)
