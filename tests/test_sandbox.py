"""
Test script to verify Sandbox Analysis implementation.
Run this after installing Playwright to test the sandbox functionality.
"""

from src.pipeline.sandbox import SandboxAnalyzer
from src.pipeline.sandbox_utils import (
    is_private_ip,
    normalize_url,
    validate_url_format,
    resolve_domain_ip,
)


def test_utility_functions():
    """Test utility functions."""
    print("=" * 60)
    print("Testing Utility Functions")
    print("=" * 60)

    # Test IP validation
    print("\n1. Testing IP Validation:")
    test_ips = [
        ("127.0.0.1", True),
        ("192.168.1.1", True),
        ("8.8.8.8", False),
        ("10.0.0.1", True),
    ]

    for ip, expected_private in test_ips:
        result = is_private_ip(ip)
        status = "✓" if result == expected_private else "✗"
        print(f"  {status} {ip}: {'Private' if result else 'Public'}")

    # Test URL normalization
    print("\n2. Testing URL Normalization:")
    test_urls = ["HTTPS://GOOGLE.COM/", "google.com", "http://example.com/"]

    for url in test_urls:
        normalized = normalize_url(url)
        print(f"  {url} → {normalized}")

    # Test URL validation
    print("\n3. Testing URL Validation:")
    test_validation_urls = [
        "https://google.com",
        "http://example.com",
        "ftp://invalid.com",
        "https://user@evil.com",
    ]

    for url in test_validation_urls:
        is_valid, msg = validate_url_format(url)
        status = "✓" if is_valid else "✗"
        print(f"  {status} {url}: {msg}")

    print("\n" + "=" * 60)


def test_sandbox_analyzer():
    """Test Sandbox Analyzer with safe URLs."""
    print("\n" + "=" * 60)
    print("Testing Sandbox Analyzer")
    print("=" * 60)

    print("\nNOTE: This test requires Playwright to be installed.")
    print("Run: pip install playwright && playwright install chromium\n")

    # Test URLs (safe sites)
    test_urls = ["https://example.com", "https://google.com"]

    analyzer = SandboxAnalyzer()

    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        print("-" * 60)

        try:
            result = analyzer.analyze(url)

            if result.get("success"):
                print(f"✓ Success!")
                print(f"  Scan ID: {result['scan_id']}")
                print(f"  Final URL: {result['final_url']}")
                print(f"  IP Address: {result['ip_address']}")
                print(f"  Page Title: {result['page_title']}")
                print(f"  Load Time: {result['load_time']}ms")
                print(f"  Screenshot: {result['screenshot_path']}")
                print(f"  Login Form: {result['has_login_form']}")
                print(f"  Password Field: {result['has_password_field']}")
            else:
                print(f"✗ Failed: {result.get('error')}")

        except Exception as e:
            print(f"✗ Error: {str(e)}")
            if "playwright" in str(e).lower():
                print("\n⚠️  Playwright not installed!")
                print("   Run: pip install playwright")
                print("   Then: playwright install chromium")
                break

    print("\n" + "=" * 60)


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("SANDBOX ANALYSIS - TEST SUITE")
    print("=" * 60)

    # Test utilities (no dependencies required)
    test_utility_functions()

    # Ask user if they want to test sandbox
    print("\n" + "=" * 60)
    response = (
        input("\nTest Sandbox Analyzer? (requires Playwright) [y/N]: ").strip().lower()
    )

    if response == "y":
        test_sandbox_analyzer()
    else:
        print("\nSkipping Sandbox Analyzer test.")
        print("To test later, run this script again or install Playwright:")
        print("  pip install playwright")
        print("  playwright install chromium")

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
