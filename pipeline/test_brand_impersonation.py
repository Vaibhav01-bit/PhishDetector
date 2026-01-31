"""
Comprehensive Test Suite for Brand Impersonation Detection
Tests legitimate URLs, phishing URLs, and edge cases
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.brand_impersonation import BrandImpersonationDetector


class TestBrandImpersonation:
    """Test suite for brand impersonation detection."""
    
    def __init__(self):
        self.detector = BrandImpersonationDetector()
        self.passed = 0
        self.failed = 0
        self.test_results = []
    
    def test(self, name, url, expected_impersonation, description=""):
        """
        Run a single test case.
        
        Args:
            name: Test name
            url: URL to test
            expected_impersonation: Expected result (True/False)
            description: Optional description
        """
        result = self.detector.check(url)
        actual = result['is_impersonation']
        passed = actual == expected_impersonation
        
        if passed:
            self.passed += 1
            status = "✓ PASS"
        else:
            self.failed += 1
            status = "✗ FAIL"
        
        self.test_results.append({
            'name': name,
            'status': status,
            'url': url,
            'expected': expected_impersonation,
            'actual': actual,
            'risk_score': result['risk_score'],
            'message': result['message'],
            'reasons': result['reasons'],
            'description': description
        })
        
        return passed
    
    def run_all_tests(self):
        """Run all test cases."""
        print("=" * 100)
        print("BRAND IMPERSONATION DETECTION - COMPREHENSIVE TEST SUITE")
        print("=" * 100)
        print()
        
        # ===== LEGITIMATE URLS (Should NOT trigger - False Positives Check) =====
        print("📋 TEST CATEGORY 1: LEGITIMATE BRAND URLS (Should NOT trigger)")
        print("-" * 100)
        
        self.test(
            "YouTube Official",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            False,
            "Official YouTube video URL"
        )
        
        self.test(
            "Google Accounts",
            "https://accounts.google.com/signin/v2/identifier",
            False,
            "Official Google sign-in page"
        )
        
        self.test(
            "PayPal Official",
            "https://www.paypal.com/myaccount/home",
            False,
            "Official PayPal account page"
        )
        
        self.test(
            "Amazon Official",
            "https://www.amazon.com/gp/product/B08N5WRWNW",
            False,
            "Official Amazon product page"
        )
        
        self.test(
            "Facebook Official",
            "https://www.facebook.com/login",
            False,
            "Official Facebook login (login in path is OK for official domain)"
        )
        
        self.test(
            "Netflix Official",
            "https://www.netflix.com/browse",
            False,
            "Official Netflix browse page"
        )
        
        self.test(
            "Microsoft Login",
            "https://login.microsoftonline.com/common/oauth2/authorize",
            False,
            "Official Microsoft OAuth login"
        )
        
        self.test(
            "Apple iCloud",
            "https://www.icloud.com/mail",
            False,
            "Official Apple iCloud mail"
        )
        
        print()
        
        # ===== PHISHING URLS (Should trigger - Detection Rate Check) =====
        print("📋 TEST CATEGORY 2: PHISHING URLS WITH BRAND IMPERSONATION (Should trigger)")
        print("-" * 100)
        
        self.test(
            "YouTube Typosquatting",
            "https://youtubee-login.com/verify",
            True,
            "Extra 'e' in youtube + login keyword"
        )
        
        self.test(
            "PayPal Numeric Substitution",
            "https://paypa1-secure.com/reset",
            True,
            "Number '1' instead of 'l' + secure keyword"
        )
        
        self.test(
            "Google Homoglyph",
            "https://g00gle-accounts.com/signin",
            True,
            "Zeros instead of 'o' + accounts keyword"
        )
        
        self.test(
            "PayPal Login Phishing",
            "https://paypal-login-secure.com/update",
            True,
            "Hyphens + multiple intent keywords"
        )
        
        self.test(
            "YouTube Verify Phishing",
            "https://youtube-verify.com/account",
            True,
            "Hyphen + verify keyword"
        )
        
        self.test(
            "Amazon Security Alert",
            "https://amazon-security-alert.com/suspended",
            True,
            "Multiple hyphens + security + suspended keywords"
        )
        
        self.test(
            "Facebook Confirm",
            "https://facebook-confirm-identity.com/verify",
            True,
            "Multiple hyphens + confirm + verify keywords"
        )
        
        self.test(
            "Netflix Account Update",
            "https://netflix-account-update.com/billing",
            True,
            "Multiple hyphens + account + update + billing keywords"
        )
        
        self.test(
            "Apple ID Locked",
            "https://apple-id-locked.com/unlock",
            True,
            "Hyphens + locked keyword (urgency)"
        )
        
        self.test(
            "Microsoft Verify",
            "https://microsoft-verify-account.com/login",
            True,
            "Multiple hyphens + verify + account + login"
        )
        
        print()
        
        # ===== EDGE CASES (Mixed scenarios) =====
        print("📋 TEST CATEGORY 3: EDGE CASES")
        print("-" * 100)
        
        self.test(
            "Brand in Path Only",
            "https://example.com/youtube/video",
            False,
            "Brand keyword in path of non-brand domain (low risk)"
        )
        
        self.test(
            "User Channel Name",
            "https://myyoutubechannel.com",
            False,
            "Contains 'youtube' but clearly a user channel (low risk)"
        )
        
        self.test(
            "News Article About Brand",
            "https://technews.com/google-announces-new-feature",
            False,
            "Brand in URL path as news topic"
        )
        
        self.test(
            "Subdomain Impersonation",
            "https://paypal.phishing-site.com/login",
            True,
            "Brand as subdomain of different domain"
        )
        
        self.test(
            "Similar Brand Name",
            "https://paypals.com/login",
            True,
            "Plural form of brand + login keyword"
        )
        
        self.test(
            "Brand with TLD Trick",
            "https://youtube.xyz/verify",
            True,
            "Official-looking but suspicious TLD + verify"
        )
        
        self.test(
            "Legitimate Subdomain",
            "https://developer.google.com/apis",
            False,
            "Legitimate Google subdomain"
        )
        
        self.test(
            "CDN Domain",
            "https://fbcdn.net/images/photo.jpg",
            False,
            "Official Facebook CDN domain"
        )
        
        print()
        
        # ===== ADVANCED PHISHING TECHNIQUES =====
        print("📋 TEST CATEGORY 4: ADVANCED PHISHING TECHNIQUES")
        print("-" * 100)
        
        self.test(
            "Repeated Characters",
            "https://gooogle.com/signin",
            True,
            "Repeated 'o' in google"
        )
        
        self.test(
            "Mixed Case Trick",
            "https://PayPal-Secure.com/verify",
            True,
            "Mixed case with hyphen (normalized to lowercase)"
        )
        
        self.test(
            "Multiple Brands",
            "https://google-paypal-verify.com/login",
            True,
            "Multiple brand names in one domain"
        )
        
        self.test(
            "Urgent Action Required",
            "https://netflix-urgent-action.com/expired",
            True,
            "Urgency keywords + expired"
        )
        
        self.test(
            "Suspended Account",
            "https://amazon-account-suspended.com/restore",
            True,
            "Account suspended urgency tactic"
        )
        
        print()
        
        # Print detailed results
        self._print_results()
    
    def _print_results(self):
        """Print detailed test results."""
        print("=" * 100)
        print("DETAILED TEST RESULTS")
        print("=" * 100)
        print()
        
        for result in self.test_results:
            print(f"{result['status']} {result['name']}")
            print(f"   URL: {result['url']}")
            print(f"   Expected: {result['expected']} | Actual: {result['actual']} | Risk Score: {result['risk_score']}")
            if result['description']:
                print(f"   Description: {result['description']}")
            if result['message']:
                print(f"   Message: {result['message']}")
            if result['reasons']:
                print(f"   Reasons: {', '.join(result['reasons'][:2])}")  # Show first 2 reasons
            print()
        
        print("=" * 100)
        print("SUMMARY")
        print("=" * 100)
        total = self.passed + self.failed
        pass_rate = (self.passed / total * 100) if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"Passed: {self.passed} ✓")
        print(f"Failed: {self.failed} ✗")
        print(f"Pass Rate: {pass_rate:.1f}%")
        print()
        
        if self.failed == 0:
            print("🎉 ALL TESTS PASSED! 🎉")
        else:
            print("⚠️  Some tests failed. Review the results above.")
        
        print("=" * 100)


def main():
    """Run the test suite."""
    tester = TestBrandImpersonation()
    tester.run_all_tests()
    
    # Return exit code based on results
    return 0 if tester.failed == 0 else 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
