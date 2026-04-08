import os
import re
import socket
import ssl
import whois
import requests
import pickle
import numpy as np
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from src.feature import FeatureExtraction
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
    "ebay.com",
    "www.ebay.com",
    "ledger.com",
    "www.ledger.com",
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
    """
    Layer 1: Domain Trust Analysis.
    Classification model:
    - Trusted domain -> SAFE
    - Blacklisted domain -> PHISHING
    - Unknown or suspicious domain -> WARNING
    """

    FREE_HOSTING_DOMAINS = {
        "wixsite.com",
        "wixstudio.com",
        "netlify.app",
        "vercel.app",
        "github.io",
    }

    SUSPICIOUS_DOMAIN_KEYWORDS = {
        "offers",
        "free",
        "loan",
        "reward",
        "bonus",
        "gift",
        "promo",
        "deal",
        "finance",
        "credit",
        "bank",
        "pay",
    }

    def __init__(self, blacklist_path="blacklist.txt"):
        self.blacklist_path = blacklist_path
        self.blacklist = self._load_blacklist()
        self.brand_detector = BrandImpersonationDetector()

    def _load_blacklist(self):
        try:
            with open(self.blacklist_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def _normalize_domain(self, url):
        if not url.startswith(("http://", "https://")):
            temp_url = "http://" + url
        else:
            temp_url = url

        parsed = urlparse(temp_url)
        domain = parsed.netloc or temp_url
        domain = str(domain).lower().strip()
        if domain.startswith("www."):
            domain = domain.replace("www.", "", 1)
        if ":" in domain:
            domain = domain.split(":", 1)[0]
        return domain

    def _is_trusted_domain(self, domain):
        if domain in LEGITIMATE_DOMAINS:
            return True

        for trusted in LEGITIMATE_DOMAINS:
            if domain.endswith("." + trusted):
                return True

        if self.brand_detector._is_official_domain(domain):
            return True

        registrable_domain = self.brand_detector._extract_registrable_domain(domain)
        if registrable_domain in LEGITIMATE_DOMAINS:
            return True

        return False

    def _find_suspicious_keyword(self, registrable_domain):
        root_label = registrable_domain.split(".")[0].lower() if registrable_domain else ""
        for keyword in self.SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in root_label:
                return keyword
        return None

    def _looks_random_domain(self, registrable_domain):
        root_label = registrable_domain.split(".")[0].lower() if registrable_domain else ""
        if not root_label:
            return False

        if re.fullmatch(r"[a-z0-9]{8,}", root_label):
            vowel_count = sum(1 for ch in root_label if ch in "aeiou")
            digit_count = sum(1 for ch in root_label if ch.isdigit())
            if digit_count >= 2:
                return True
            if vowel_count <= max(1, len(root_label) // 6):
                return True

        return False

    def check(self, url):
        try:
            domain = self._normalize_domain(url)
            registrable_domain = self.brand_detector._extract_registrable_domain(domain)
            reasons = []

            if domain in self.blacklist:
                return PHISHING, "Domain found in blacklist."

            if registrable_domain in self.blacklist:
                return PHISHING, "Main domain found in blacklist."

            if self._is_trusted_domain(domain):
                return SAFE, "Trusted verified domain."

            if domain in self.FREE_HOSTING_DOMAINS or domain.endswith(
                tuple("." + host for host in self.FREE_HOSTING_DOMAINS)
            ):
                reasons.append("Uses a free/shared hosting platform.")

            suspicious_keyword = self._find_suspicious_keyword(registrable_domain)
            if suspicious_keyword:
                reasons.append(
                    f"Contains suspicious domain keyword '{suspicious_keyword}'."
                )

            if len(registrable_domain) > 20:
                reasons.append("Main domain is unusually long.")

            if self._looks_random_domain(registrable_domain):
                reasons.append("Main domain looks random or low quality.")

            if not reasons:
                reasons.append("Unknown domain is not in the trusted list.")
            else:
                reasons.insert(0, "Unknown domain is not in the trusted list.")

            return WARNING, " ".join(reasons)
        except Exception:
            return WARNING, "Domain trust analysis incomplete. Treating domain as unknown."


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
        "wixstudio.com",
        "wixsite.com",
        "pages.dev",
        "on.fleek.co",
    ]

    SUSPICIOUS_DOMAIN_KEYWORDS = {
        "offers",
        "deal",
        "reward",
        "bonus",
        "free",
        "gift",
        "win",
        "promo",
    }

    FINANCIAL_DOMAIN_KEYWORDS = {
        "loan",
        "bank",
        "credit",
        "pay",
        "finance",
        "prestamos",
    }

    TRACKING_QUERY_KEYS = {
        "ref",
        "refid",
        "clickid",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "campaign",
        "aff",
        "affiliate",
        "source",
    }

    SAFE_SUBDOMAIN_TOKENS = {
        "www",
        "mail",
        "app",
        "api",
        "docs",
        "support",
        "help",
        "blog",
        "news",
        "m",
        "cdn",
        "static",
        "assets",
        "images",
        "img",
        "files",
        "download",
        "portal",
        "dashboard",
        "login",
        "auth",
        "secure",
        "account",
        "accounts",
        "developer",
    }

    SAFE_PATH_WORDS = {
        "login",
        "verify",
        "secure",
        "payment",
        "account",
        "support",
        "update",
        "download",
        "docs",
        "help",
        "about",
        "contact",
        "blog",
        "products",
        "pricing",
        "features",
        "dashboard",
        "portal",
    }

    def __init__(self):
        """Initialize Layer 2 with brand impersonation detector."""
        self.brand_detector = BrandImpersonationDetector()

    def check(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or url
        domain = domain.lower()
        registrable_domain = self.brand_detector._extract_registrable_domain(domain)
        subdomain = self.brand_detector._extract_subdomain(domain)
        hosted_on_shared_platform = any(
            domain == gateway or domain.endswith("." + gateway)
            for gateway in self.DECENTRALIZED_GATEWAYS
        )
        is_trusted_domain = self._is_trusted_domain(domain)

        risk_score = 0
        reasons = []

        # Feature 1: Brand Impersonation Detection (NEW - Enhanced)
        # Use the advanced brand impersonation detector
        brand_result = self.brand_detector.check(url, domain)

        if brand_result["details"].get("force_phishing") or brand_result["risk_score"] >= 60:
            return PHISHING, "; ".join(brand_result["reasons"][:4]) or brand_result["message"]

        if brand_result["risk_score"] >= 30:
            risk_score += 20
            reasons.extend(brand_result["reasons"][:3])

        if hosted_on_shared_platform:
            risk_score += 20
            reasons.append(
                f"Hosted on shared/free platform '{registrable_domain}'."
            )

        suspicious_domain_keyword = self._find_suspicious_domain_keyword(
            registrable_domain
        )
        if suspicious_domain_keyword:
            risk_score += 30
            reasons.append(
                f"Suspicious domain keyword detected: '{suspicious_domain_keyword}'."
            )

        financial_domain_keyword = self._find_financial_domain_keyword(
            registrable_domain
        )
        if financial_domain_keyword and not is_trusted_domain:
            risk_score += 40
            reasons.append(
                f"Financial keyword detected in domain: '{financial_domain_keyword}'."
            )

        if not is_trusted_domain:
            risk_score += 20
            reasons.append("Unknown or untrusted domain.")

        if financial_domain_keyword and not is_trusted_domain:
            risk_score += 10
            reasons.append(
                "Sensitive financial/payment domain is not an official trusted source."
            )

        random_path_segment = self._find_random_path_segment(parsed.path)
        if random_path_segment:
            risk_score += 30
            reasons.append(
                f"Random-looking path detected: '{random_path_segment}'."
            )

        suspicious_query = self._analyze_query_string(parsed.query)
        if suspicious_query:
            risk_score += 10
            reasons.append(suspicious_query)

        suspicious_subdomain = self._is_suspicious_subdomain(subdomain)
        if suspicious_subdomain:
            risk_score += 15
            reasons.append(
                f"Suspicious subdomain structure detected: '{subdomain}'."
            )

        if subdomain and not is_trusted_domain:
            risk_score += 10
            reasons.append(
                f"Subdomain usage detected on non-trusted main domain '{registrable_domain}'."
            )

        if financial_domain_keyword and not is_trusted_domain:
            return PHISHING, "; ".join(reasons[:4])

        if (
            suspicious_domain_keyword
            and random_path_segment
            and not is_trusted_domain
        ):
            return PHISHING, "; ".join(reasons[:4])

        # Feature 2: Long Domain
        if len(domain) > 50:
            risk_score += 10
            reasons.append("Domain is unusually long.")

        # Feature 3: High Subdomain Count
        subdomains = domain.split(".")
        # Filter out empty strings from split (e.g., trailing dot)
        subdomains = [s for s in subdomains if s]
        if len(subdomains) > 4:
            risk_score += 10
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
            risk_score += 10
            reasons.append("Suspicious or high-risk Top Level Domain (TLD).")

        elif any(domain.endswith(tld) for tld in low_risk_tlds):
            risk_score -= 10  # Reduce risk for trusted TLDs

        # Ensure score floor is 0
        risk_score = max(0, risk_score)

        if risk_score >= 60:
            return PHISHING, "; ".join(reasons[:4])
        if risk_score >= 30:
            return WARNING, f"Suspicious domain features: {', '.join(reasons)}"
        return SAFE, "Domain analysis passed."

    def _is_trusted_domain(self, domain):
        domain = (domain or "").lower()
        if not domain:
            return False

        if domain in LEGITIMATE_DOMAINS:
            return True

        for legit in LEGITIMATE_DOMAINS:
            if domain.endswith("." + legit):
                return True

        if self.brand_detector._is_official_domain(domain):
            return True

        registrable_domain = self.brand_detector._extract_registrable_domain(domain)
        if registrable_domain in LEGITIMATE_DOMAINS:
            return True

        return False

    def _find_suspicious_domain_keyword(self, registrable_domain):
        root_label = registrable_domain.split(".")[0].lower() if registrable_domain else ""
        for keyword in self.SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in root_label:
                return keyword
        return None

    def _find_financial_domain_keyword(self, registrable_domain):
        root_label = registrable_domain.split(".")[0].lower() if registrable_domain else ""
        for keyword in self.FINANCIAL_DOMAIN_KEYWORDS:
            if keyword in root_label:
                return keyword
        return None

    def _find_random_path_segment(self, path):
        if not path:
            return None

        segments = [segment.lower() for segment in path.split("/") if segment]
        for segment in segments:
            if segment in self.SAFE_PATH_WORDS:
                continue
            if re.fullmatch(r"[a-z0-9]{4,10}", segment):
                has_letter = any(ch.isalpha() for ch in segment)
                has_digit = any(ch.isdigit() for ch in segment)
                if has_letter and has_digit:
                    return segment
        return None

    def _analyze_query_string(self, query):
        if not query:
            return None

        query = query.strip().lower()
        parsed_query = parse_qs(query, keep_blank_values=True)
        if parsed_query:
            for key, values in parsed_query.items():
                if key in self.TRACKING_QUERY_KEYS:
                    return f"Tracking-like query parameter detected: '{key}'."
                for value in values:
                    if re.fullmatch(r"[a-z0-9]{3,12}", value or ""):
                        return f"Tracking-like query value detected: '{key}'."

        if "=" not in query and re.fullmatch(r"[a-z0-9]{4,12}", query):
            return f"Suspicious query token detected: '{query}'."

        return None

    def _is_suspicious_subdomain(self, subdomain):
        if not subdomain:
            return False

        parts = [part.lower() for part in re.split(r"[.\-_]", subdomain) if part]
        if len(parts) > 2:
            return True

        for part in parts:
            if part in self.SAFE_SUBDOMAIN_TOKENS:
                continue
            if part in self.brand_detector.brand_identifier_map:
                continue
            if re.fullmatch(r"[a-z0-9]{5,12}", part):
                has_letter = any(ch.isalpha() for ch in part)
                has_digit = any(ch.isdigit() for ch in part)
                if has_letter and has_digit:
                    return True
            if len(part) > 18:
                return True

        return False


class Layer3_SSL:
    def check(self, url):
        # Simplified check: Rely on scheme.
        # This avoids SSRF risks and performance overhead of connection checks.
        if url.startswith("https://"):
            return SAFE, "Valid HTTPS Scheme."

        return WARNING, "Insecure (HTTP) or Unknown Scheme."


class Layer4_ML_Model:
    def __init__(self, model_path="src/ml/newmodel.pkl"):
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
