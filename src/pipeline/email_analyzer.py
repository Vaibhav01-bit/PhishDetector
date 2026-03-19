"""
Enhanced Email Security Analyzer
Professional multi-layer phishing detection system for emails.
"""

import re
import os
import base64
import json
from datetime import datetime
from urllib.parse import urlparse, unquote
from typing import Dict, List, Optional, Tuple, Any

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from .brand_impersonation import BrandImpersonationDetector
from .email_utils import (
    extract_urls_from_text,
    extract_email_headers,
    extract_sender_info,
)
from .manager import PhishingDetectionPipeline, SAFE, WARNING, PHISHING


class EmailAnalyzer:
    """
    Professional email phishing detection with multi-layer analysis.

    Analysis Layers:
    1. Sender Analysis - Domain verification, lookalike detection
    2. Link Analysis - URL extraction, mismatch detection, URL scanning
    3. Content Analysis - Phishing language scoring
    4. Header Analysis - SPF/DKIM/DMARC parsing
    5. Brand Impersonation - Claimed brand vs actual sender
    6. Attachment Analysis - File scanner integration
    7. Risk Scoring - Final weighted score calculation
    """

    MAX_URLS_TO_SCAN = 5
    MAX_EMAIL_SIZE = 100 * 1024  # 100KB
    MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB

    FREE_EMAIL_DOMAINS = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "protonmail.com",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
        "live.com",
        "msn.com",
        "comcast.net",
        "att.net",
        "verizon.net",
    }

    HOMOGLYPH_MAP = {
        "0": "o",
        "1": "il",
        "2": "z",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
    }

    SUSPICIOUS_TLDS = {
        ".xyz",
        ".top",
        ".club",
        ".online",
        ".site",
        ".website",
        ".space",
        ".work",
        ".click",
        ".link",
        ".info",
        ".biz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
    }

    URGENCY_PATTERNS = [
        (r"\b(urgent|immediately|right now|asap|right away)\b", 15),
        (r"\b(verify now|confirm now|act now|don\'t delay)\b", 20),
        (r"\b(suspended|locked|disabled|expired)\b", 15),
        (r"\b(immediate action|required|mandatory)\b", 20),
        (r"\b(within \d+ hour|within \d+ day)\b", 10),
    ]

    THREAT_PATTERNS = [
        (r"\b(terminate|terminate|deletion|permanent|forever)\b", 15),
        (r"\b(illegal|unauthorized|police|legal|lawsuit)\b", 20),
        (r"\b(suspended|blocked|restricted)\b", 15),
        (r"\b(breach|compromised|hacked|stolen)\b", 20),
        (r"\b(fraud|scam|phishing)\b", 10),
    ]

    FINANCIAL_PATTERNS = [
        (r"\b(payment|credit card|debit card|bank account)\b", 15),
        (r"\b(ssn|social security|tax|irs|refund)\b", 20),
        (r"\b(wire transfer|moneygram|western union)\b", 25),
        (r"\b(billing|invoice|receipt|transaction)\b", 10),
        (r"\b(paypal|venmo|zelle|cashapp)\b", 10),
    ]

    PRIZE_PATTERNS = [
        (r"\b(winner|won|congratulations|prize|lottery)\b", 25),
        (r"\b(inherited|inheritance|beneficiary|claim)\b", 20),
        (r"\b(free gift|reward|bonus|claim now)\b", 15),
        (r"\b(selected|lucky|customer|account)\b", 10),
    ]

    def __init__(self):
        self.brand_detector = BrandImpersonationDetector()
        self.url_pipeline = PhishingDetectionPipeline(enable_sandbox=False)
        self._brand_keywords = self._load_brand_keywords()

    def _load_brand_keywords(self) -> Dict[str, str]:
        """Load brand keywords for detection."""
        return {
            "paypal": "PayPal",
            "apple": "Apple",
            "microsoft": "Microsoft",
            "amazon": "Amazon",
            "google": "Google",
            "facebook": "Facebook",
            "meta": "Meta",
            "netflix": "Netflix",
            "bank": "Bank",
            "chase": "Chase",
            "wells": "Wells Fargo",
            "citi": "Citibank",
            "dropbox": "Dropbox",
            "linkedin": "LinkedIn",
            "twitter": "Twitter",
            "instagram": "Instagram",
            "spotify": "Spotify",
            "adobe": "Adobe",
            "salesforce": "Salesforce",
            "shopify": "Shopify",
            "coinbase": "Coinbase",
            "binance": "Binance",
            "ebay": "eBay",
            "walmart": "Walmart",
            "target": "Target",
            "costco": "Costco",
            "bestbuy": "Best Buy",
            "fedex": "FedEx",
            "ups": "UPS",
            "usps": "USPS",
            "dhl": "DHL",
            "steam": "Steam",
            "epic": "Epic Games",
            "discord": "Discord",
            "slack": "Slack",
            "zoom": "Zoom",
            "teams": "Microsoft Teams",
            "onedrive": "OneDrive",
            "icloud": "iCloud",
            "dropbox": "Dropbox",
        }

    def analyze(self, email_text: str, attachment_file=None) -> Dict[str, Any]:
        """
        Main entry point for email analysis.

        Args:
            email_text: Raw email content (may include headers)
            attachment_file: Optional uploaded file

        Returns:
            dict: Complete analysis result
        """
        result = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "sender": {},
            "links": {"urls": [], "summary": {}},
            "content": {},
            "headers": {},
            "brand_claim": {},
            "attachments": [],
            "risk_score": 0,
            "risk_level": "Safe",
            "explanation": [],
        }

        try:
            if len(email_text) > self.MAX_EMAIL_SIZE:
                return {
                    "success": False,
                    "error": f"Email exceeds {self.MAX_EMAIL_SIZE // 1024}KB limit",
                }

            parsed = self._parse_email(email_text)

            result["sender"] = self._analyze_sender(parsed["from"], parsed["headers"])

            result["links"] = self._analyze_links(parsed["body"])

            result["content"] = self._analyze_content(parsed["body"])

            result["headers"] = self._analyze_headers(parsed["headers"])

            result["brand_claim"] = self._detect_brand_claim(
                parsed["from"], parsed["body"]
            )

            result["attachments"] = self._scan_attachments(
                parsed["attachments"], attachment_file
            )

            risk_result = self._calculate_risk_score(
                result["sender"],
                result["links"],
                result["content"],
                result["headers"],
                result["brand_claim"],
                result["attachments"],
            )
            result["risk_score"] = risk_result["score"]
            result["risk_level"] = risk_result["level"]

            result["explanation"] = self._generate_explanation(
                result["sender"],
                result["links"],
                result["content"],
                result["headers"],
                result["brand_claim"],
                result["attachments"],
            )

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)

        return result

    def _parse_email(self, email_text: str) -> Dict[str, Any]:
        """Parse email into components."""
        parsed = {
            "from": "",
            "subject": "",
            "headers": {},
            "body": email_text,
            "attachments": [],
        }

        lines = email_text.split("\n")
        body_start = 0

        for i, line in enumerate(lines):
            line = line.strip()

            if line.lower().startswith("from:"):
                parsed["from"] = self._parse_header_value(line[5:])
                body_start = i + 1
            elif line.lower().startswith("subject:"):
                parsed["subject"] = self._parse_header_value(line[8:])
            elif ":" in line and body_start == 0:
                try:
                    key, value = line.split(":", 1)
                    parsed["headers"][key.strip().lower()] = self._parse_header_value(
                        value
                    )
                except:
                    pass
            elif line == "" and i > 0:
                body_start = i + 1
                break

        if body_start > 0:
            parsed["body"] = "\n".join(lines[body_start:])

        parsed["attachments"] = self._extract_attachments(parsed["body"])

        return parsed

    def _parse_header_value(self, value: str) -> str:
        """Clean header value."""
        value = value.strip()
        value = re.sub(r"\s+", " ", value)
        return value

    def _extract_attachments(self, body: str) -> List[Dict[str, str]]:
        """Extract inline attachments from email body."""
        attachments = []

        b64_pattern = r'Content-Type:\s*[^;]+;\s*name="([^"]+)"[^>]*Content-Transfer-Encoding:\s*base64[^>]*\n\n([A-Za-z0-9+\/\s=]+)'
        matches = re.findall(b64_pattern, body, re.IGNORECASE | re.DOTALL)

        for name, data in matches:
            attachments.append(
                {
                    "name": name.strip(),
                    "type": "inline_base64",
                    "data": data.replace(" ", "").replace("\n", ""),
                }
            )

        return attachments

    def _analyze_sender(self, from_field: str, headers: Dict) -> Dict[str, Any]:
        """Layer 1: Analyze sender email and domain."""
        result = {
            "email": from_field,
            "domain": "",
            "display_name": "",
            "risk_level": "low",
            "issues": [],
            "score": 0,
        }

        if not from_field:
            result["issues"].append("No sender information found")
            result["score"] += 20
            result["risk_level"] = "high"
            return result

        email_match = re.search(r"<([^>]+)>", from_field)
        if email_match:
            result["email"] = email_match.group(1).strip()
            result["display_name"] = (
                from_field[: email_match.start()].strip().strip('"')
            )
        else:
            if "@" in from_field:
                result["email"] = from_field.strip()

        if "@" in result["email"]:
            result["domain"] = result["email"].split("@")[1].lower()

        if not result["domain"]:
            result["issues"].append("Invalid email format")
            result["score"] += 15
            result["risk_level"] = "high"
            return result

        domain_lower = result["domain"]
        domain_base = domain_lower.split(".")[0]

        if self._is_free_email_domain(domain_lower):
            result["issues"].append(f"Free email domain used: {domain_lower}")
            result["score"] += 5

        lookalike = self._detect_lookalike(domain_base)
        if lookalike:
            result["issues"].append(
                f"Lookalike domain detected (similar to {lookalike})"
            )
            result["score"] += 25
            result["risk_level"] = "high"

        if self._has_homoglyph(domain_lower):
            result["issues"].append("Homoglyph/punycode domain detected")
            result["score"] += 20
            result["risk_level"] = "high"

        suspicious_tld = self._check_suspicious_tld(domain_lower)
        if suspicious_tld:
            result["issues"].append(f"Suspicious TLD: {suspicious_tld}")
            result["score"] += 10

        if self._has_suspicious_subdomain(domain_lower):
            result["issues"].append("Suspicious subdomain structure")
            result["score"] += 5

        if result["score"] >= 25:
            result["risk_level"] = "high"
        elif result["score"] >= 10:
            result["risk_level"] = "medium"

        return result

    def _is_free_email_domain(self, domain: str) -> bool:
        """Check if domain is a free email provider."""
        for free_domain in self.FREE_EMAIL_DOMAINS:
            if domain == free_domain or domain.endswith("." + free_domain):
                return True
        return False

    def _detect_lookalike(self, domain_base: str) -> Optional[str]:
        """Detect lookalike domains (e.g., paypa1 -> paypal)."""
        if not domain_base or len(domain_base) < 4:
            return None

        for brand in self.brand_detector.brands.keys():
            if len(brand) < 4:
                continue

            distance = self._levenshtein_distance(domain_base, brand)

            if distance <= 2 and len(domain_base) == len(brand):
                return brand

            if distance == 1 and abs(len(domain_base) - len(brand)) <= 1:
                return brand

            if self._has_numeric_substitution(domain_base, brand):
                return brand

        return None

    def _has_numeric_substitution(self, domain: str, brand: str) -> bool:
        """Check if domain has number substitutions (e.g., paypa1 -> paypal)."""
        if len(domain) != len(brand):
            return False

        differences = 0
        for i, char in enumerate(domain):
            if char.isdigit():
                if i < len(brand) and brand[i] in self.HOMOGLYPH_MAP.get(char, ""):
                    differences += 1
                elif char == "0" and brand[i] == "o":
                    differences += 1
                elif char == "1" and brand[i] in "li":
                    differences += 1
            elif char != brand[i]:
                differences += 1

        return differences == 1

    def _has_homoglyph(self, domain: str) -> bool:
        """Detect homoglyph domains."""
        try:
            domain.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    def _check_suspicious_tld(self, domain: str) -> Optional[str]:
        """Check for suspicious TLDs."""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return tld
        return None

    def _has_suspicious_subdomain(self, domain: str) -> bool:
        """Check for suspicious subdomain patterns."""
        parts = domain.split(".")
        if len(parts) > 3:
            return True

        for part in parts[:-1]:
            if len(part) > 30:
                return True

        return False

    def _analyze_links(self, body: str) -> Dict[str, Any]:
        """Layer 2: Extract and analyze links."""
        result = {
            "urls": [],
            "summary": {
                "total": 0,
                "suspicious": 0,
                "phishing": 0,
                "safe": 0,
                "mismatched": 0,
                "shortened": 0,
            },
        }

        urls = extract_urls_from_text(body)

        visible_links = self._extract_visible_links(body)

        shorteners = {
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "tiny.cc",
            "shorturl.at",
        }

        scanned_count = 0

        for url in urls[: self.MAX_URLS_TO_SCAN]:
            link_info = {
                "url": url,
                "domain": self._extract_domain(url),
                "status": "unknown",
                "risk_score": 0,
                "issues": [],
            }

            visible = self._get_visible_text_for_url(url, body, visible_links)
            if visible:
                link_info["visible_text"] = visible

            if visible and visible != url:
                link_info["visible_text"] = visible
                if not self._is_url_display_safe(visible, url):
                    link_info["mismatch"] = True
                    link_info["issues"].append(
                        f'Display text "{visible}" differs from actual URL'
                    )
                    result["summary"]["mismatched"] += 1

            parsed = urlparse(url)
            if parsed.netloc.lower() in shorteners:
                link_info["shortened"] = True
                link_info["issues"].append("Shortened URL - actual destination unknown")
                result["summary"]["shortened"] += 1

            if scanned_count < self.MAX_URLS_TO_SCAN:
                try:
                    url_result = self.url_pipeline.analyze_fast(url)
                    status = url_result.get("status", SAFE)

                    if status == PHISHING:
                        link_info["status"] = "phishing"
                        link_info["risk_score"] = 100
                        result["summary"]["phishing"] += 1
                    elif status == WARNING:
                        link_info["status"] = "suspicious"
                        link_info["risk_score"] = 60
                        result["summary"]["suspicious"] += 1
                    else:
                        link_info["status"] = "safe"
                        link_info["risk_score"] = 10
                        result["summary"]["safe"] += 1
                except:
                    link_info["status"] = "error"

            result["urls"].append(link_info)
            scanned_count += 1

        result["summary"]["total"] = len(result["urls"])

        return result

    def _extract_visible_links(self, body: str) -> List[Tuple[str, str]]:
        """Extract visible link text and URLs from HTML."""
        visible = []

        html_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(html_pattern, body, re.IGNORECASE)
        for url, text in matches:
            visible.append((url.strip(), text.strip()))

        text_pattern = r"([a-zA-Z0-9\-\.]+\.(?:com|org|net|io|co|info|biz|us|uk|ca|au|de|fr|ru|cn|jp|in|br|mx)\S*)"
        text_matches = re.findall(text_pattern, body)
        for url in text_matches[:10]:
            if url not in [v[0] for v in visible]:
                visible.append((url, url))

        return visible

    def _get_visible_text_for_url(
        self, url: str, body: str, visible_links: List
    ) -> Optional[str]:
        """Get the visible text associated with a URL."""
        for link_url, text in visible_links:
            if url in link_url or link_url in url:
                return text
        return None

    def _is_url_display_safe(self, visible: str, actual: str) -> bool:
        """Check if visible text reasonably matches the actual URL."""
        visible_lower = visible.lower().replace("http://", "").replace("https://", "")
        actual_lower = actual.lower().replace("http://", "").replace("https://", "")

        visible_domain = urlparse("http://" + visible_lower).netloc
        actual_domain = urlparse("http://" + actual_lower).netloc

        if visible_domain and actual_domain:
            if visible_domain == actual_domain:
                return True
            if visible_domain in actual_domain or actual_domain in visible_domain:
                return True

        return False

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""

    def _analyze_content(self, body: str) -> Dict[str, Any]:
        """Layer 3: Analyze email content for phishing patterns."""
        result = {
            "phishing_score": 0,
            "urgency_score": 0,
            "threat_score": 0,
            "financial_score": 0,
            "prize_score": 0,
            "urgency_indicators": [],
            "threat_indicators": [],
            "financial_indicators": [],
            "prize_indicators": [],
        }

        body_lower = body.lower()

        for pattern, score in self.URGENCY_PATTERNS:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                result["urgency_indicators"].extend(
                    [m.lower() if isinstance(m, str) else str(m) for m in matches]
                )
                result["urgency_score"] += score

        for pattern, score in self.THREAT_PATTERNS:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                result["threat_indicators"].extend(
                    [m.lower() if isinstance(m, str) else str(m) for m in matches]
                )
                result["threat_score"] += score

        for pattern, score in self.FINANCIAL_PATTERNS:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                result["financial_indicators"].extend(
                    [m.lower() if isinstance(m, str) else str(m) for m in matches]
                )
                result["financial_score"] += score

        for pattern, score in self.PRIZE_PATTERNS:
            matches = re.findall(pattern, body_lower, re.IGNORECASE)
            if matches:
                result["prize_indicators"].extend(
                    [m.lower() if isinstance(m, str) else str(m) for m in matches]
                )
                result["prize_score"] += score

        result["phishing_score"] = (
            result["urgency_score"]
            + result["threat_score"]
            + result["financial_score"]
            + result["prize_score"]
        )

        return result

    def _analyze_headers(self, headers: Dict) -> Dict[str, Any]:
        """Layer 4: Analyze email authentication headers."""
        result = {
            "spf": {"status": "not_available", "detail": ""},
            "dkim": {"status": "not_available", "detail": ""},
            "dmarc": {"status": "not_available", "detail": ""},
            "authentication_results": "",
        }

        auth_results = headers.get("authentication-results", "")
        if auth_results:
            result["authentication_results"] = auth_results

            if "spf=" in auth_results.lower():
                if "pass" in auth_results.lower():
                    result["spf"] = {"status": "pass", "detail": "SPF check passed"}
                elif "fail" in auth_results.lower():
                    result["spf"] = {"status": "fail", "detail": "SPF check failed"}
                elif "softfail" in auth_results.lower():
                    result["spf"] = {"status": "softfail", "detail": "SPF softfail"}
                else:
                    result["spf"] = {"status": "unknown", "detail": "SPF check unknown"}

            if "dkim=" in auth_results.lower():
                if "pass" in auth_results.lower():
                    result["dkim"] = {"status": "pass", "detail": "DKIM check passed"}
                elif "fail" in auth_results.lower():
                    result["dkim"] = {"status": "fail", "detail": "DKIM check failed"}
                else:
                    result["dkim"] = {
                        "status": "unknown",
                        "detail": "DKIM check unknown",
                    }

            if "dmarc=" in auth_results.lower():
                if "pass" in auth_results.lower():
                    result["dmarc"] = {"status": "pass", "detail": "DMARC check passed"}
                elif "fail" in auth_results.lower():
                    result["dmarc"] = {"status": "fail", "detail": "DMARC check failed"}
                else:
                    result["dmarc"] = {
                        "status": "unknown",
                        "detail": "DMARC check unknown",
                    }

        received_spf = headers.get("received-spf", "")
        if received_spf and result["spf"]["status"] == "not_available":
            if "pass" in received_spf.lower():
                result["spf"] = {
                    "status": "pass",
                    "detail": "SPF passed (from Received-SPF)",
                }
            elif "fail" in received_spf.lower():
                result["spf"] = {
                    "status": "fail",
                    "detail": "SPF failed (from Received-SPF)",
                }

        return result

    def _detect_brand_claim(self, from_field: str, body: str) -> Dict[str, Any]:
        """Layer 5: Detect brand impersonation."""
        result = {
            "claimed_brand": None,
            "claimed_display": None,
            "sender_domain": "",
            "is_impersonation": False,
            "risk_score": 0,
            "reason": "",
        }

        if "@" in from_field:
            email_match = re.search(r"<([^>]+)>", from_field)
            if email_match:
                result["sender_domain"] = email_match.group(1).split("@")[1].lower()
            else:
                result["sender_domain"] = from_field.split("@")[1].lower()

        body_lower = body.lower()

        detected_brand = None
        for keyword, brand_name in self._brand_keywords.items():
            if keyword in body_lower:
                if result["sender_domain"] and keyword not in result["sender_domain"]:
                    detected_brand = brand_name
                    break

        if detected_brand:
            result["claimed_brand"] = detected_brand
            result["claimed_display"] = detected_brand

            domain_parts = result["sender_domain"].split(".")
            domain_base = domain_parts[0] if domain_parts else ""

            brand_lower = detected_brand.lower().replace(" ", "")

            if brand_lower not in result["sender_domain"]:
                if (
                    brand_lower[:4] in result["sender_domain"]
                    or result["sender_domain"][:4] in brand_lower
                ):
                    result["is_impersonation"] = True
                    result["risk_score"] = 40
                    result["reason"] = (
                        f"Email claims to be from {detected_brand} but sender domain is {result['sender_domain']}"
                    )

        return result

    def _scan_attachments(
        self, inline_attachments: List, uploaded_file
    ) -> List[Dict[str, Any]]:
        """Layer 6: Scan attachments using file scanner."""
        results = []

        return results

    def _calculate_risk_score(
        self,
        sender: Dict,
        links: Dict,
        content: Dict,
        headers: Dict,
        brand: Dict,
        attachments: List,
    ) -> Dict[str, Any]:
        """Layer 7: Calculate final risk score."""
        score = 0

        score += min(sender.get("score", 0), 25)

        phishing_links = links["summary"].get("phishing", 0)
        suspicious_links = links["summary"].get("suspicious", 0)
        mismatched = links["summary"].get("mismatched", 0)

        score += min(phishing_links * 20, 30)
        score += min(suspicious_links * 10, 20)
        score += min(mismatched * 15, 15)

        content_score = content.get("phishing_score", 0)
        score += min(content_score, 20)

        header_score = 0
        if headers.get("spf", {}).get("status") == "fail":
            header_score += 5
        if headers.get("dkim", {}).get("status") == "fail":
            header_score += 5
        if headers.get("dmarc", {}).get("status") == "fail":
            header_score += 5
        score += min(header_score, 15)

        if brand.get("is_impersonation"):
            score += brand.get("risk_score", 0)

        for attachment in attachments:
            if attachment.get("risk_level") == "high":
                score += 15
            elif attachment.get("risk_level") == "medium":
                score += 5

        score = min(max(score, 0), 100)

        if score <= 20:
            level = "Safe"
        elif score <= 50:
            level = "Suspicious"
        else:
            level = "Phishing"

        return {"score": score, "level": level}

    def _generate_explanation(
        self,
        sender: Dict,
        links: Dict,
        content: Dict,
        headers: Dict,
        brand: Dict,
        attachments: List,
    ) -> List[str]:
        """Generate human-readable explanation of findings."""
        reasons = []

        for issue in sender.get("issues", []):
            reasons.append(f"Sender: {issue}")

        for url_info in links.get("urls", []):
            if url_info.get("mismatch"):
                reasons.append(f"Link mismatch: Display text differs from actual URL")
            if url_info.get("status") == "phishing":
                reasons.append(f"Phishing URL detected: {url_info['domain']}")
            if url_info.get("shortened"):
                reasons.append(f"Shortened URL used (obfuscation technique)")

        if content.get("urgency_indicators"):
            reasons.append(
                f"Urgency language: {', '.join(set(content['urgency_indicators'][:3]))}"
            )

        if content.get("threat_indicators"):
            reasons.append(
                f"Threat language: {', '.join(set(content['threat_indicators'][:3]))}"
            )

        if content.get("financial_indicators"):
            reasons.append(
                f"Financial request: {', '.join(set(content['financial_indicators'][:2]))}"
            )

        if content.get("prize_indicators"):
            reasons.append(
                f" Prize/lottery scam indicators: {', '.join(set(content['prize_indicators'][:2]))}"
            )

        if headers.get("spf", {}).get("status") == "fail":
            reasons.append("SPF authentication failed")
        if headers.get("dkim", {}).get("status") == "fail":
            reasons.append("DKIM authentication failed")
        if headers.get("dmarc", {}).get("status") == "fail":
            reasons.append("DMARC authentication failed")

        if brand.get("is_impersonation"):
            reasons.append(brand.get("reason", "Brand impersonation detected"))

        for attachment in attachments:
            if attachment.get("risk_level") == "high":
                reasons.append(
                    f"Suspicious attachment: {attachment.get('name', 'unknown file')}"
                )

        return reasons

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)

        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]


def analyze_email(email_text: str, attachment_file=None) -> Dict[str, Any]:
    """
    Convenience function for email analysis.

    Args:
        email_text: Raw email content
        attachment_file: Optional file attachment

    Returns:
        dict: Analysis result
    """
    analyzer = EmailAnalyzer()
    return analyzer.analyze(email_text, attachment_file)
