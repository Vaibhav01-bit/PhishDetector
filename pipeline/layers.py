import os
import re
import socket
import ssl
import whois
import requests
import pickle
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from feature import FeatureExtraction
from .brand_impersonation import BrandImpersonationDetector

# Define risk levels
SAFE = "Safe"
WARNING = "Warning"
PHISHING = "Phishing"
INVALID = "Invalid"

LEGITIMATE_DOMAINS = {
    "google.com",
    "www.google.com",
    "mail.google.com",
    "accounts.google.com",
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "facebook.com",
    "www.facebook.com",
    "fb.com",
    "www.fb.com",
    "amazon.com",
    "www.amazon.com",
    "smile.amazon.com",
    "microsoft.com",
    "www.microsoft.com",
    "office.com",
    "live.com",
    "outlook.com",
    "apple.com",
    "www.apple.com",
    "icloud.com",
    "twitter.com",
    "www.twitter.com",
    "x.com",
    "www.x.com",
    "instagram.com",
    "www.instagram.com",
    "linkedin.com",
    "www.linkedin.com",
    "github.com",
    "www.github.com",
    "netflix.com",
    "www.netflix.com",
    "paypal.com",
    "www.paypal.com",
    "reddit.com",
    "www.reddit.com",
    "wikipedia.org",
    "www.wikipedia.org",
    "whatsapp.com",
    "www.whatsapp.com",
    "tiktok.com",
    "www.tiktok.com",
    "zoom.us",
    "www.zoom.us",
    "dropbox.com",
    "www.dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "stackoverflow.com",
    "www.stackoverflow.com",
    "yahoo.com",
    "www.yahoo.com",
    "bing.com",
    "www.bing.com",
    "baidu.com",
    "www.baidu.com",
    "spotify.com",
    "www.spotify.com",
    "twitch.tv",
    "www.twitch.tv",
    "discord.com",
    "www.discord.com",
    "slack.com",
    "www.slack.com",
    "adobe.com",
    "www.adobe.com",
    "salesforce.com",
    "www.salesforce.com",
    "chase.com",
    "www.chase.com",
    "wellsfargo.com",
    "www.wellsfargo.com",
    "bankofamerica.com",
    "www.bankofamerica.com",
    "citi.com",
    "www.citi.com",
    "capitalone.com",
    "www.capitalone.com",
}


class Layer0_Validation:
    def sanitize(self, url):
        """
        Cleans the input URL by removing common debugging prefixes and whitespace.
        """
        if not url:
            return ""

        # 1. Trim whitespace
        url = url.strip()

        # 2. Remove common prefixes (case-insensitive)
        # This handles cases like "Scanning:https://...", "URL: https://...", etc.
        prefixes = ["scanning:", "checking:", "url:", "link:"]

        # We repeat the check in case there are multiple prefixes like "Scanning: URL: http..."
        changed = True
        while changed:
            changed = False
            url_lower = url.lower()
            for prefix in prefixes:
                if url_lower.startswith(prefix):
                    url = url[len(prefix) :].strip()
                    changed = True
                    break

        return url

    def check(self, url):
        """
        Validates URL structure and detects nested URLs.
        """
        if not url:
            return INVALID, "Empty URL provided."

        try:
            # 1. Structural Validation using urlparse
            parsed = urlparse(url)

            # Must have scheme and network location (domain)
            if not parsed.scheme or not parsed.netloc:
                return INVALID, "Malformed URL: Missing scheme or domain."

            if parsed.scheme not in ["http", "https"]:
                return INVALID, f"Unsupported scheme: {parsed.scheme}"

            # 2. Nested URL Detection
            # Check if http:// or https:// appears in the path, query, or fragment
            # We look for the pattern after the initial scheme
            url_lower = url.lower()
            # Remove the very first occurrence of the scheme to check for subsequent ones
            body = url_lower[len(parsed.scheme) + 3 :]

            if "http://" in body or "https://" in body:
                return WARNING, "Suspicious nested URL structure detected."

            # 3. Check for obvious malformation in netloc
            if parsed.netloc.startswith(".") or parsed.netloc.endswith("."):
                return INVALID, "Malformed URL: Invalid domain structure."

            if ".." in parsed.netloc:
                return (
                    INVALID,
                    "Malformed URL: Invalid domain structure (consecutive dots).",
                )

            return SAFE, "URL format validated."
        except Exception as e:
            return INVALID, f"URL validation failed: {str(e)}"


class Layer1_Blacklist:
    def __init__(self, blacklist_path="blacklist.txt"):
        self.blacklist_path = blacklist_path
        self.blacklist = self._load_blacklist()

    def _load_blacklist(self):
        try:
            with open(self.blacklist_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def check(self, url):
        # Normalize the input URL to match the blacklist format
        # 1. Parse URL
        try:
            # Ensure scheme exists for urlparse
            if not url.startswith(("http://", "https://")):
                temp_url = "http://" + url
            else:
                temp_url = url

            parsed = urlparse(temp_url)
            domain = parsed.netloc or temp_url

            # 2. Normalize
            domain_str = str(domain).lower()
            if domain_str.startswith("www."):
                domain_str = domain_str.replace("www.", "", 1)

            domain = domain_str.strip()

            if domain in self.blacklist:
                return PHISHING, "Domain found in blacklist."
            return SAFE, "Domain not in blacklist."
        except Exception:
            # If parsing fails, fall back to simple check or safe
            return SAFE, "Domain analysis skipped (invalid format)."


class Layer2_Domain:
    # Static whitelist for brand impersonation checks (kept for backward compatibility)
    BRAND_DOMAINS = {
        "paypal": ["paypal.com", "paypal-objects.com"],
        "google": ["google.com", "gmail.com", "accounts.google.com"],
        "apple": ["apple.com", "icloud.com"],
        "microsoft": ["microsoft.com", "live.com", "office.com"],
        "amazon": ["amazon.com", "ssl-images-amazon.com"],
        "facebook": ["facebook.com", "fb.com"],
        "instagram": ["instagram.com"],
        "netflix": ["netflix.com"],
        "chase": ["chase.com"],
        "wellsfargo": ["wellsfargo.com"],
    }

    # Static list of known decentralized content gateways
    DECENTRALIZED_GATEWAYS = [
        "ipfs.io",
        "cloudflare-ipfs.com",
        "gateway.pinata.cloud",
        "dweb.link",
        "github.io",
        "vercel.app",
        "netlify.app",
        "pages.dev",
        "on.fleek.co",
    ]

    def __init__(self):
        """Initialize Layer 2 with brand impersonation detector."""
        self.brand_detector = BrandImpersonationDetector()

    def check(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or url
        domain = domain.lower()  # Normalize for analysis

        # 0. Check for Decentralized Gateway
        # If matched, treat as neutral infrastructure (WARNING/Suspicious mainly for opacity)
        if any(
            domain == gateway or domain.endswith("." + gateway)
            for gateway in self.DECENTRALIZED_GATEWAYS
        ):
            return (
                WARNING,
                "Hosted on a decentralized or shared platform. Content may change dynamically.",
            )

        score = 0
        reasons = []

        # Feature 1: Brand Impersonation Detection (NEW - Enhanced)
        # Use the advanced brand impersonation detector
        brand_result = self.brand_detector.check(url, domain)

        if brand_result["is_impersonation"]:
            # Strong indicator of phishing attempt
            score += 2
            reasons.append(brand_result["message"])
            # Add specific reasons from the detector
            if brand_result["details"].get("typosquatting_detected"):
                reasons.append("Typosquatting pattern detected")
            if brand_result["details"].get("intent_keywords"):
                keywords_list = brand_result["details"]["intent_keywords"]
                keywords = ", ".join(str(k) for k in keywords_list[:3])  # Limit to 3
                reasons.append(str(f"Phishing keywords: {keywords}"))
            if brand_result["details"].get("homoglyphs_detected"):
                reasons.append("Character substitution detected")

        # Feature 2: Long Domain
        if len(domain) > 50:
            score += 1
            reasons.append("Domain is unusually long.")

        # Feature 3: High Subdomain Count
        subdomains = domain.split(".")
        # Filter out empty strings from split (e.g., trailing dot)
        subdomains = [s for s in subdomains if s]
        if len(subdomains) > 4:
            score += 1
            reasons.append("High number of subdomains.")

        # Feature 4: Suspicious TLD Weighting
        high_risk_tlds = [
            ".xyz",
            ".top",
            ".club",
            ".info",
            ".cn",
            ".help",
            ".work",
            ".gq",
        ]
        low_risk_tlds = [".gov", ".edu", ".mil"]

        if any(domain.endswith(tld) for tld in high_risk_tlds):
            score += 1
            reasons.append("Suspicious or high-risk Top Level Domain (TLD).")

        elif any(domain.endswith(tld) for tld in low_risk_tlds):
            score -= 1  # Reduce risk for trusted TLDs

        # Ensure score floor is 0
        score = max(0, score)

        if score >= 2:
            return WARNING, f"Suspicious domain features: {', '.join(reasons)}"
        return SAFE, "Domain analysis passed."


class Layer3_SSL:
    def check(self, url):
        # Simplified check: Rely on scheme.
        # This avoids SSRF risks and performance overhead of connection checks.
        if url.startswith("https://"):
            return SAFE, "Valid HTTPS Scheme."

        return WARNING, "Insecure (HTTP) or Unknown Scheme."


class Layer4_ML_Model:
    def __init__(self, model_path="newmodel.pkl"):
        self.model_path = model_path
        self.model = None
        self.rf_model = None
        self.xgb_model = None
        self._load_models()

    def _load_models(self):
        """Load primary model and optionally ensemble models."""
        try:
            self.model = pickle.load(open(self.model_path, "rb"))
        except Exception as e:
            print(f"Warning: Could not load model: {e}")
            self.model = None

        try:
            self.rf_model = pickle.load(open("rf_model.pkl", "rb"))
        except:
            self.rf_model = None

        try:
            self.xgb_model = pickle.load(open("xgb_model.pkl", "rb"))
        except:
            self.xgb_model = None

    def _is_legitimate_domain(self, url):
        """Check if URL is from a known legitimate domain."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]

            if domain in LEGITIMATE_DOMAINS:
                return True

            for legit in LEGITIMATE_DOMAINS:
                if domain.endswith("." + legit):
                    return True

            return False
        except:
            return False

    def _sanitize_url(self, url):
        """Sanitize URL before feature extraction."""
        if not url:
            return ""

        url = str(url).strip()

        prefixes = ["scanning:", "checking:", "url:", "link:", "visit:", "open:"]

        changed = True
        while changed:
            changed = False
            url_lower = url.lower()
            for prefix in prefixes:
                if url_lower.startswith(prefix):
                    url = url[len(prefix) :].strip()
                    changed = True
                    break

        url = re.sub(r"^\s*https?://+", "https://", url, flags=re.IGNORECASE)

        return url

    def check(self, url):
        if not self.model:
            return WARNING, "ML Model not loaded."

        sanitized_url = self._sanitize_url(url)

        if self._is_legitimate_domain(sanitized_url):
            return SAFE, "Known legitimate domain (whitelist)."

        try:
            obj = FeatureExtraction(sanitized_url, fetch_content=False)
            features = obj.getFeaturesList()

            if len(features) != 30:
                features = [1] * 30

            x = np.array(features).reshape(1, 30)

            if self.model is not None:
                y_pred = self.model.predict(x)[0]
            elif self.rf_model is not None:
                y_pred = self.rf_model.predict(x)[0]
            else:
                return WARNING, "No ML model available."

            if y_pred == 1:
                return SAFE, "ML Model predicts Safe."
            else:
                return PHISHING, "ML Model predicts Phishing."
        except Exception as e:
            return WARNING, f"ML Extraction failed: {str(e)}"


class Layer5_Behavioral:
    def check(self, url):
        reasons = []
        parsed = urlparse(url)

        # Check for '@' symbol in URL
        if "@" in url:
            return (
                PHISHING,
                "URL contains '@' symbol (often used to obscure destination).",
            )

        # Check for IP address as domain
        domain = parsed.netloc
        try:
            socket.inet_aton(domain)
            return PHISHING, "URL uses IP address instead of domain name."
        except:
            pass  # Not an IP

        # Check for multiple redirects (Basic check)
        if "//" in parsed.path:
            return WARNING, "URL path contains '//' which may indicate redirection."

        return SAFE, "Behavioral analysis passed."
