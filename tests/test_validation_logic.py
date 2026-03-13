import sys
import os

sys.path.append(os.getcwd())
from src.pipeline.layers import Layer0_Validation, SAFE, WARNING, INVALID


def test_validation():
    l0 = Layer0_Validation()

    test_cases = [
        ("https://google.com", SAFE, "Normal URL"),
        ("  https://google.com  ", SAFE, "URL with Whitespace"),
        ("Scanning:https://google.com", SAFE, "URL with 'Scanning:' prefix"),
        ("URL: https://google.com", SAFE, "URL with 'URL:' prefix"),
        ("Checking: Scanning:  https://google.com", SAFE, "URL with multiple prefixes"),
        ("https://www.youtube.com/https://www.youtube.com/", WARNING, "Nested URL"),
        (
            "https://example.com/login?redirect=http://malicious.com",
            WARNING,
            "Nested URL in query",
        ),
        (
            "Scanning:https://www.youtube.com/https://www.youtube.com/",
            WARNING,
            "Prefixed Nested URL",
        ),
        ("http:///missing-slash", INVALID, "Malformed URL (missing slash)"),
        ("https://.com", INVALID, "Malformed URL (starts with dot)"),
        ("https://google..com", INVALID, "Malformed URL (consecutive dots)"),
        ("ftp://unsafe.com", INVALID, "Unsupported scheme"),
        ("", INVALID, "Empty URL"),
    ]

    print("Starting Validation & Sanitization Tests...\n", flush=True)
    all_passed = True
    for url_input, expected_status, description in test_cases:
        sanitized_url = l0.sanitize(url_input)
        status, message = l0.check(sanitized_url)
        result = "PASSED" if status == expected_status else "FAILED"
        print(f"[{result}] {description}", flush=True)
        print(f"  URL: {url_input}", flush=True)
        print(f"  Expected: {expected_status}, Got: {status}", flush=True)
        print(f"  Message: {message}\n", flush=True)
        if status != expected_status:
            all_passed = False

    if all_passed:
        print("All validation tests passed!", flush=True)
    else:
        print("Some validation tests failed.", flush=True)


if __name__ == "__main__":
    test_validation()
