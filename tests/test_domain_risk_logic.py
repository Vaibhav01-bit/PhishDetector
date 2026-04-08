import os
import sys

sys.path.append(os.getcwd())
from src.pipeline.layers import Layer2_Domain, SAFE, PHISHING, WARNING


def test_domain_risk_logic():
    layer = Layer2_Domain()

    test_cases = [
        (
            "https://softlab.ontopoffers.com/v51gb/?shiny",
            PHISHING,
            "Suspicious offers-domain with random path and query token",
        ),
        (
            "https://promo-rewards-hub.com/a9xk2/?clickid=xyz",
            PHISHING,
            "Suspicious reward domain with random path and tracking query",
        ),
        (
            "https://mio.amigotuyoprestamos.com/",
            PHISHING,
            "Financial keyword on unknown main domain with subdomain usage",
        ),
        (
            "https://www.paypal.com/myaccount/home",
            SAFE,
            "Official trusted brand should stay safe",
        ),
        (
            "https://pay.google.com/gp/w/u/0/home/signup",
            SAFE,
            "Trusted payment domain should stay safe",
        ),
        (
            "https://example.com/products",
            SAFE,
            "Generic domain without scam-style path should stay safe",
        ),
        (
            "https://randomsite-example.com/download?ref=123",
            WARNING,
            "Unknown domain with tracking query should be suspicious but not forced phishing",
        ),
    ]

    print("Starting Domain Risk Logic Tests...\n", flush=True)
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
        print("All domain risk tests passed!", flush=True)
    else:
        print("Some domain risk tests failed.", flush=True)


if __name__ == "__main__":
    test_domain_risk_logic()
