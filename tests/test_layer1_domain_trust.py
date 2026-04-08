import os
import sys

sys.path.append(os.getcwd())
from src.pipeline.layers import Layer1_Blacklist, SAFE, WARNING, PHISHING


def test_layer1_domain_trust():
    layer = Layer1_Blacklist()
    layer.blacklist = {"example-phishing.com", "blacklisted-domain.test"}

    test_cases = [
        (
            "https://google.com",
            SAFE,
            "Trusted verified domain should be safe",
        ),
        (
            "http://example-phishing.com",
            PHISHING,
            "Explicit blacklist entry should be phishing",
        ),
        (
            "https://unknown-example-site.com",
            WARNING,
            "Unknown domain should not be marked safe",
        ),
        (
            "https://promo-winner.vercel.app",
            WARNING,
            "Free hosting domain should be suspicious",
        ),
        (
            "https://xk29dkfjoffers.com",
            WARNING,
            "Random low-quality domain with suspicious keyword should be suspicious",
        ),
    ]

    print("Starting Layer 1 Domain Trust Tests...\n", flush=True)
    all_passed = True

    for url, expected_status, description in test_cases:
        status, message = layer.check(url)
        result = "PASSED" if status == expected_status else "FAILED"
        print(f"[{result}] {description}", flush=True)
        print(f"  URL: {url}", flush=True)
        print(f"  Expected: {expected_status}, Got: {status}", flush=True)
        print(f"  Message: {message}\n", flush=True)
        if status != expected_status:
            all_passed = False

    if all_passed:
        print("All Layer 1 trust tests passed!", flush=True)
    else:
        print("Some Layer 1 trust tests failed.", flush=True)


if __name__ == "__main__":
    test_layer1_domain_trust()
