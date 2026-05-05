"""
QR Code Security Analyzer
Analyzes QR codes for phishing, scams, and malicious content.
NO DATA IS STORED - All processing is in-memory only.
"""

import re
import base64
import io
from datetime import datetime
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image

    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

from .brand_impersonation import BrandImpersonationDetector


class QRAnalyzer:
    """
    Analyzes QR codes for security threats.

    Features:
    - QR type detection (URL, UPI, WiFi, SMS, App, Text)
    - URL phishing detection using existing pipeline
    - UPI payment fraud detection (rule-based)
    - Risk scoring with critical overrides
    """

    UPI_PATTERNS = [
        r"^([a-zA-Z0-9._-]+)@([a-zA-Z0-9.-]+)$",
        r"^([a-zA-Z0-9._-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$",
    ]

    BRAND_KEYWORDS = {
        "paytm": "Paytm",
        "phonepe": "PhonePe",
        "gpay": "Google Pay",
        "googlepay": "Google Pay",
        "amazonpay": "Amazon Pay",
        "amazon": "Amazon",
        "paypal": "PayPal",
        "mobikwik": "MobiKwik",
        "freecharge": "FreeCharge",
        "airtel": "Airtel",
        "jio": "Jio",
        "sbi": "SBI",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "axis": "Axis Bank",
        "kotak": "Kotak Bank",
        "yesbank": "Yes Bank",
        "indusind": "IndusInd Bank",
        "bob": "Bank of Baroda",
        "pnb": "Punjab National Bank",
        "canara": "Canara Bank",
    }

    HIGH_RISK_UPI_KEYWORDS = [
        "help",
        "support",
        "admin",
        "customer",
        "service",
        "secure",
        "verify",
        "account",
        "update",
        "confirm",
        "urgent",
        "alert",
        "suspended",
        "locked",
        "auth",
        "signin",
        "password",
        "reset",
        "recovery",
        "banking",
        "netbanking",
        "notification",
    ]

    SUSPICIOUS_UPI_KEYWORDS = [
        "payment",
        "pay",
        "login",
        "transaction",
        "amount",
    ]

    SUSPICIOUS_UPI_PATTERNS = [
        r"^[a-z]{15,}@upi$",
        r"^[a-z0-9]{20,}@",
        r"@[\d]+\.[a-z]{2,}",
    ]

    URL_SHORTENERS = [
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
        "cutt.ly",
        "rb.gy",
        "v.gd",
        "tr.im",
        "tinyurl.com",
    ]

    PAYMENT_KEYWORDS = [
        "payment",
        "pay",
        "transaction",
        "amount",
        "₹",
        "rs",
        "rupee",
        "debit",
        "credit",
        "bank",
        "transfer",
        "upi",
        "neft",
        "rtgs",
    ]

    def __init__(self):
        self.brand_detector = BrandImpersonationDetector()

    def analyze(self, qr_content: str, qr_image_base64: str = None) -> Dict[str, Any]:
        """
        Main entry point for QR code analysis.

        Args:
            qr_content: Decoded QR content (string)
            qr_image_base64: Optional base64 encoded QR image

        Returns:
            dict: Complete analysis result
        """
        result = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "qr_type": "unknown",
            "content": qr_content,
            "decoded_data": {},
            "url_analysis": None,
            "upi_details": None,
            "risk_score": 0,
            "risk_level": "Safe",
            "critical_flags": [],
            "explanation": [],
            "warnings": [],
        }

        try:
            if not qr_content or not qr_content.strip():
                return {
                    "success": False,
                    "error": "Empty QR content",
                    "risk_score": 0,
                    "risk_level": "Safe",
                }

            qr_type, decoded_data = self._detect_qr_type(qr_content)
            result["qr_type"] = qr_type
            result["decoded_data"] = decoded_data

            if qr_type == "url":
                url_result = self._analyze_url_qr(qr_content, decoded_data)
                result["url_analysis"] = url_result
                result["risk_score"] = url_result.get("risk_score", 0)
                result["critical_flags"] = url_result.get("critical_flags", [])
                result["explanation"] = url_result.get("explanation", [])
                result["warnings"] = url_result.get("warnings", [])

            elif qr_type == "upi":
                upi_result = self._analyze_upi_qr(qr_content, decoded_data)
                result["upi_details"] = upi_result
                result["risk_score"] = upi_result.get("risk_score", 0)
                result["critical_flags"] = upi_result.get("critical_flags", [])
                result["explanation"] = upi_result.get("explanation", [])
                result["warnings"] = upi_result.get("warnings", [])

            elif qr_type == "wifi":
                wifi_result = self._analyze_wifi_qr(qr_content, decoded_data)
                result["risk_score"] = wifi_result.get("risk_score", 0)
                result["critical_flags"] = wifi_result.get("critical_flags", [])
                result["explanation"] = wifi_result.get("explanation", [])

            elif qr_type == "sms":
                sms_result = self._analyze_sms_qr(qr_content, decoded_data)
                result["risk_score"] = sms_result.get("risk_score", 0)
                result["critical_flags"] = sms_result.get("critical_flags", [])
                result["explanation"] = sms_result.get("explanation", [])

            elif qr_type == "app":
                app_result = self._analyze_app_qr(qr_content, decoded_data)
                result["url_analysis"] = app_result
                result["risk_score"] = app_result.get("risk_score", 0)
                result["critical_flags"] = app_result.get("critical_flags", [])
                result["explanation"] = app_result.get("explanation", [])

            else:
                text_result = self._analyze_text_qr(qr_content)
                result["risk_score"] = text_result.get("risk_score", 0)
                result["explanation"] = text_result.get("explanation", [])
                result["warnings"] = text_result.get("warnings", [])

            result["risk_level"] = self._calculate_risk_level(
                result["risk_score"], result["critical_flags"]
            )

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            result["risk_level"] = "Safe"

        return result

    def decode_from_image(self, image_base64: str) -> Optional[str]:
        """
        Decode QR code from base64 encoded image.

        Args:
            image_base64: Base64 encoded image data

        Returns:
            str: Decoded QR content or None
        """
        if not PYZBAR_AVAILABLE:
            return None

        try:
            image_data = base64.b64decode(image_base64)
            image = Image.open(io.BytesIO(image_data))

            if image.mode != "RGB":
                image = image.convert("RGB")

            decoded_objects = pyzbar_decode(image)

            if decoded_objects:
                return decoded_objects[0].data.decode("utf-8", errors="ignore")

            return None
        except Exception:
            return None

    def _detect_qr_type(self, content: str) -> Tuple[str, Dict[str, Any]]:
        """
        Detect the type of QR code content.

        Returns:
            tuple: (qr_type, decoded_data)
        """
        content_lower = content.lower().strip()

        if content_lower.startswith("http://") or content_lower.startswith("https://"):
            return "url", self._parse_url_data(content)

        if content_lower.startswith("www."):
            return "url", self._parse_url_data("https://" + content)

        if content_lower.startswith("upi://") or "@" in content:
            upi_match = re.match(r"upi://pay\?(.*)", content, re.IGNORECASE)
            if upi_match or "@" in content:
                return "upi", self._parse_upi_data(content)

        if content_lower.startswith("wifi:"):
            return "wifi", self._parse_wifi_data(content)

        if content_lower.startswith("smsto:") or content_lower.startswith("sms:"):
            return "sms", self._parse_sms_data(content)

        if content_lower.startswith("geo:"):
            return "geo", {"type": "location", "data": content}

        if "play.google.com" in content_lower or "apps.apple.com" in content_lower:
            return "app", self._parse_app_data(content)

        if content_lower.startswith("tel:"):
            return "phone", self._parse_phone_data(content)

        if content_lower.startswith("mailto:"):
            return "email", self._parse_email_data(content)

        return "text", {"type": "plain_text", "data": content}

    def _parse_url_data(self, url: str) -> Dict[str, Any]:
        """Parse URL content."""
        parsed = urlparse(url)
        return {
            "type": "url",
            "original_url": url,
            "domain": parsed.netloc.lower(),
            "path": parsed.path,
            "query": parsed.query,
            "is_shortened": any(
                shortener in parsed.netloc.lower() for shortener in self.URL_SHORTENERS
            ),
        }

    def _parse_upi_data(self, content: str) -> Dict[str, Any]:
        """Parse UPI payment data."""
        data = {"type": "upi", "raw": content}

        if content.lower().startswith("upi://"):
            query_params = parse_qs(content.split("?")[1] if "?" in content else "")
            data["pa"] = query_params.get("pa", [None])[0]
            data["pn"] = query_params.get("pn", [None])[0]
            data["am"] = query_params.get("am", [None])[0]
            data["cu"] = query_params.get("cu", [None])[0]
            data["mam"] = query_params.get("mam", [None])[0]
            data["tr"] = query_params.get("tr", [None])[0]
            data["tn"] = query_params.get("tn", [None])[0]
        else:
            parts = content.split("@")
            if len(parts) >= 2:
                data["pa"] = content
                data["pn"] = None
                data["am"] = None

        if data.get("pa"):
            upi_id = data["pa"]
            data["upi_id"] = upi_id
            data["is_valid_format"] = self._is_valid_upi_format(upi_id)

        return data

    def _parse_wifi_data(self, content: str) -> Dict[str, Any]:
        """Parse WiFi configuration data."""
        data = {"type": "wifi"}

        match = re.match(
            r"WIFI:(?:T:([^;]*);)?(?:S:([^;]*);)?(?:P:([^;]*);)?(?:H:([^;]*);)?(?:;)?",
            content,
            re.IGNORECASE,
        )
        if match:
            data["hidden"] = match.group(1)
            data["ssid"] = match.group(2)
            data["password"] = match.group(3)
            data["is_hidden"] = match.group(4)

        return data

    def _parse_sms_data(self, content: str) -> Dict[str, Any]:
        """Parse SMS content data."""
        data = {"type": "sms"}

        match = re.match(r"(smsto|sms):([+]?\d+)?[:]?(.*)", content, re.IGNORECASE)
        if match:
            data["phone"] = match.group(2)
            data["message"] = match.group(3)

        return data

    def _parse_app_data(self, content: str) -> Dict[str, Any]:
        """Parse app download data."""
        data = {"type": "app"}

        if "play.google.com" in content.lower():
            data["store"] = "google_play"
            data["url"] = content
        elif "apps.apple.com" in content.lower():
            data["store"] = "apple_app"
            data["url"] = content

        return data

    def _parse_phone_data(self, content: str) -> Dict[str, Any]:
        """Parse phone number data."""
        data = {"type": "phone"}
        data["number"] = content.replace("tel:", "")
        return data

    def _parse_email_data(self, content: str) -> Dict[str, Any]:
        """Parse email data."""
        data = {"type": "email"}
        content = content.replace("mailto:", "")
        if "?" in content:
            email, query = content.split("?", 1)
            data["email"] = email
            data["subject"] = parse_qs(query).get("subject", [None])[0]
        else:
            data["email"] = content
        return data

    def _analyze_url_qr(self, content: str, data: Dict) -> Dict[str, Any]:
        """Analyze URL type QR code."""
        result = {
            "risk_score": 0,
            "critical_flags": [],
            "explanation": [],
            "warnings": [],
            "url_analysis": None,
        }

        url = data.get("original_url", content)
        domain = data.get("domain", "")
        is_shortened = data.get("is_shortened", False)

        if is_shortened:
            result["risk_score"] += 15
            result["warnings"].append(f"Shortened URL detected ({domain})")

        if url.startswith("http://"):
            result["risk_score"] += 20
            if any(keyword in url.lower() for keyword in self.PAYMENT_KEYWORDS):
                result["risk_score"] += 30
                result["critical_flags"].append("HTTP_WITH_PAYMENT_KEYWORDS")

        brand_check = self._check_brand_domain(domain)
        if brand_check["is_fake"]:
            result["risk_score"] += 40
            result["critical_flags"].append("FAKE_BRAND_DOMAIN")
            result["explanation"].append(
                f"Fake {brand_check['brand']} domain detected: {domain}"
            )

        lookalike = self._detect_lookalike_domain(domain)
        if lookalike:
            result["risk_score"] += 35
            result["critical_flags"].append("LOOKALIKE_DOMAIN")
            result["explanation"].append(
                f"Lookalike domain detected (similar to {lookalike})"
            )

        result["url_analysis"] = {
            "url": url,
            "domain": domain,
            "is_shortened": is_shortened,
            "uses_https": url.startswith("https://"),
            "brand_check": brand_check,
        }

        return result

    def _analyze_upi_qr(self, content: str, data: Dict) -> Dict[str, Any]:
        """Analyze UPI payment QR code."""
        result = {
            "risk_score": 0,
            "critical_flags": [],
            "explanation": [],
            "warnings": [],
        }

        upi_id = data.get("pa") or data.get("upi_id")
        amount = data.get("am")
        payee_name = data.get("pn")

        if not upi_id:
            result["risk_score"] += 25
            result["warnings"].append("No UPI ID found in QR code")
            return result

        result["explanation"].append(f"UPI ID: {upi_id}")
        if amount:
            result["explanation"].append(f"Amount: ₹{amount}")
        if payee_name:
            result["explanation"].append(f"Payee: {payee_name}")

        if not self._is_valid_upi_format(upi_id):
            result["risk_score"] += 30
            result["critical_flags"].append("INVALID_UPI_FORMAT")

        brand_impersonation = self._check_brand_impersonation(upi_id)
        if brand_impersonation:
            result["risk_score"] += 60
            result["critical_flags"].append("BRAND_IMPERSONATION")
            result["explanation"].append(brand_impersonation)

        random_username = self._is_random_username(upi_id)
        if random_username:
            result["risk_score"] += 50
            result["critical_flags"].append("RANDOM_USERNAME")
            result["explanation"].append("Random username pattern detected")

        if not brand_impersonation and not random_username:
            high_risk = self._check_high_risk_keywords(upi_id)
            if high_risk:
                result["risk_score"] += 35
                result["warnings"].append(
                    f"High-risk keywords in UPI ID: {', '.join(high_risk)}"
                )

            suspicious_keywords = self._check_suspicious_upi_keywords(upi_id)
            if suspicious_keywords:
                result["risk_score"] += 25
                result["warnings"].append(
                    f"Suspicious keywords in UPI ID: {', '.join(suspicious_keywords)}"
                )

        suspicious_pattern = self._check_suspicious_upi_pattern(upi_id)
        if suspicious_pattern:
            result["risk_score"] += 35
            result["critical_flags"].append("SUSPICIOUS_UPI_PATTERN")

        return result

    def _analyze_wifi_qr(self, content: str, data: Dict) -> Dict[str, Any]:
        """Analyze WiFi QR code."""
        result = {"risk_score": 0, "critical_flags": [], "explanation": []}

        ssid = data.get("ssid", "Unknown")
        hidden = data.get("is_hidden", False)
        has_password = bool(data.get("password"))

        result["explanation"].append(f"WiFi Network: {ssid}")
        result["explanation"].append(f"Security: {'Hidden' if hidden else 'Visible'}")
        result["explanation"].append(
            f"Password Protected: {'Yes' if has_password else 'No'}"
        )

        if hidden:
            result["risk_score"] += 15
            result["warnings"] = result.get("warnings", []) + [
                "Hidden WiFi network - exercise caution"
            ]

        if not has_password:
            result["risk_score"] += 20
            result["warnings"] = result.get("warnings", []) + [
                "Open WiFi - data may be intercepted"
            ]

        return result

    def _analyze_sms_qr(self, content: str, data: Dict) -> Dict[str, Any]:
        """Analyze SMS QR code."""
        result = {"risk_score": 0, "critical_flags": [], "explanation": []}

        phone = data.get("phone", "Unknown")
        message = data.get("message", "")

        result["explanation"].append(f"Phone: {phone}")
        if message:
            result["explanation"].append(
                f"Message: {message[:50]}..."
                if len(message) > 50
                else f"Message: {message}"
            )

        result["risk_score"] += 15
        result["warnings"] = ["QR triggers SMS - potential premium rate scam"]
        result["critical_flags"].append("SMS_COMMAND")

        return result

    def _analyze_app_qr(self, content: str, data: Dict) -> Dict[str, Any]:
        """Analyze app download QR code."""
        result = {"risk_score": 0, "critical_flags": [], "explanation": []}

        store = data.get("store", "Unknown")
        url = data.get("url", content)

        result["explanation"].append(f"App Store: {store}")
        result["explanation"].append(f"URL: {url}")

        if not any(
            trusted in url.lower() for trusted in ["play.google.com", "apps.apple.com"]
        ):
            result["risk_score"] += 30
            result["warnings"] = ["Non-official app store - potential malware risk"]

        return result

    def _analyze_text_qr(self, content: str) -> Dict[str, Any]:
        """Analyze plain text QR code."""
        result = {"risk_score": 0, "explanation": [], "warnings": []}

        result["explanation"].append(
            f"Content: {content[:100]}..."
            if len(content) > 100
            else f"Content: {content}"
        )

        if any(
            keyword in content.lower()
            for keyword in ["password", "login", "credential"]
        ):
            result["risk_score"] += 30
            result["warnings"].append("Contains credential-related keywords")

        url_mentions = re.findall(r"https?://[^\s]+", content)
        if url_mentions:
            result["risk_score"] += 10
            result["warnings"].append(f"Contains URL: {url_mentions[0][:50]}...")

        return result

    def _is_valid_upi_format(self, upi_id: str) -> bool:
        """Check if UPI ID has valid format."""
        if not upi_id or "@" not in upi_id:
            return False

        parts = upi_id.split("@")
        if len(parts) != 2:
            return False

        name, provider = parts

        if len(name) < 2 or len(name) > 50:
            return False

        if len(provider) < 2:
            return False

        if not re.match(r"^[a-zA-Z0-9.-]+$", provider):
            return False

        return True

    def _check_suspicious_upi_keywords(self, upi_id: str) -> list:
        """Check for suspicious keywords in UPI ID (only flag if suspicious words are standalone)."""
        parts = upi_id.split("@")
        if len(parts) < 2:
            return []

        name_part = parts[0].lower()
        provider = parts[1].lower()

        found = []

        for keyword in self.SUSPICIOUS_UPI_KEYWORDS:
            if keyword in name_part:
                if name_part == keyword:
                    found.append(keyword)
                elif name_part.startswith(keyword + "0") or name_part.startswith(
                    keyword + "1"
                ):
                    found.append(keyword + " substitution")
                elif re.search(r"[\d]" + keyword, name_part):
                    found.append(keyword)

        return found

    def _check_suspicious_upi_pattern(self, upi_id: str) -> bool:
        """Check for suspicious patterns in UPI ID."""
        for pattern in self.SUSPICIOUS_UPI_PATTERNS:
            if re.match(pattern, upi_id, re.IGNORECASE):
                return True
        return False

    def _check_brand_impersonation(self, upi_id: str) -> Optional[str]:
        """Check if UPI ID impersonates a known brand."""
        upi_lower = upi_id.lower()
        parts = upi_id.split("@")
        if len(parts) < 2:
            return None

        username = parts[0].lower()
        provider = parts[1].lower()

        for keyword, brand in self.BRAND_KEYWORDS.items():
            if keyword in username:
                if keyword not in provider:
                    return f"Brand impersonation detected: '{keyword}' in username but '{provider}' is not {brand}"
                if provider == keyword or provider.startswith(keyword):
                    return None

                if self._is_generic_provider(provider):
                    return f"Brand impersonation detected: '{keyword}' with generic provider '{provider}'"

        if provider == "upi":
            for keyword, brand in self.BRAND_KEYWORDS.items():
                if keyword in username:
                    return f"Brand impersonation detected: '{keyword}' claims to be {brand} with generic @upi"

        return None

    def _is_generic_provider(self, provider: str) -> bool:
        """Check if provider is a generic UPI provider."""
        generic_providers = [
            "upi",
            "googlepay",
            "phonepe",
            "paytm",
            "amazonpay",
            "paypal",
            "bhim",
            "mobikwik",
            "freecharge",
        ]
        return provider in generic_providers

    def _is_random_username(self, upi_id: str) -> bool:
        """Check if username appears to be randomly generated."""
        parts = upi_id.split("@")
        if len(parts) < 2:
            return False

        username = parts[0]

        if len(username) < 8:
            return False

        digit_count = sum(1 for c in username if c.isdigit())
        digit_ratio = digit_count / len(username)

        if digit_ratio >= 0.30:
            return True

        consonant_count = sum(
            1 for c in username.lower() if c.isalpha() and c not in "aeiou"
        )
        consonant_ratio = consonant_count / len(username)
        if consonant_ratio >= 0.70 and len(username) >= 10:
            return True

        if re.match(r"^[a-z]{3,}[0-9]{4,}$", username):
            return True

        return False

    def _check_high_risk_keywords(self, upi_id: str) -> list:
        """Check for high-risk keywords in UPI ID."""
        parts = upi_id.split("@")
        if len(parts) < 2:
            return []

        name_part = parts[0].lower()

        found = []
        for keyword in self.HIGH_RISK_UPI_KEYWORDS:
            if keyword in name_part:
                if name_part == keyword or name_part.startswith(keyword):
                    found.append(keyword)
                elif len(name_part) <= len(keyword) + 2:
                    found.append(keyword)

        return found

    def _extract_brand_from_upi(self, upi_id: str) -> Optional[str]:
        """Extract brand name from UPI ID."""
        upi_lower = upi_id.lower()

        brand_keywords = {
            "paytm": "Paytm",
            "phonepe": "PhonePe",
            "gpay": "Google Pay",
            "googlepay": "Google Pay",
            "amazonpay": "Amazon Pay",
            "amazon": "Amazon",
            "paypal": "PayPal",
            "mobikwik": "MobiKwik",
            "freecharge": "FreeCharge",
            "airtel": "Airtel",
            "jio": "Jio",
            "sbi": "SBI",
            "hdfc": "HDFC Bank",
            "icici": "ICICI Bank",
            "axis": "Axis Bank",
            "kotak": "Kotak Bank",
        }

        for keyword, brand in brand_keywords.items():
            if keyword in upi_lower:
                return brand

        return None

    def _is_verified_merchant(self, upi_id: str) -> bool:
        """
        Check if UPI ID is a verified merchant.
        This uses pattern matching instead of a database.
        """
        verified_patterns = [
            r"^[a-z]{2,}@[a-z]+\.upi$",
            r"^[a-z]{2,}@[a-z]{4,}$",
        ]

        parts = upi_id.split("@")
        if len(parts) >= 2:
            provider = parts[1].lower()

            known_providers = [
                "okicici",
                "okhdfcbank",
                "oksbi",
                "okaxis",
                "okkotak",
                "paytm",
                "phonepe",
                "gpay",
                "freecharge",
            ]

            for known in known_providers:
                if known in provider:
                    return True

        return False

    def _check_brand_domain(self, domain: str) -> Dict[str, Any]:
        """Check if domain impersonates a brand."""
        result = {"is_fake": False, "brand": None, "details": {}}

        domain_base = domain.split(".")[0].lower()

        brand_domains = {
            "paypal": "PayPal",
            "amazon": "Amazon",
            "paytm": "Paytm",
            "phonepe": "PhonePe",
            "gpay": "Google Pay",
            "googlepay": "Google Pay",
            "flipkart": "Flipkart",
            "myntra": "Myntra",
            "snapdeal": "Snapdeal",
            " SBI ": "SBI",
            "hdfc": "HDFC Bank",
            "icici": "ICICI Bank",
            "axis": "Axis Bank",
        }

        official_domains = {
            "paypal": ["paypal.com", "paypal-objects.com"],
            "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
            "paytm": ["paytm.com", "paytm.in"],
            "phonepe": ["phonepe.com", "phonepe.in"],
            "gpay": ["pay.google.com", "gpay.app"],
            "flipkart": ["flipkart.com"],
            "hdfc": ["hdfcbank.com", "hdfcnetbanking.com"],
            "icici": ["icicibank.com", "icicinetbanking.com"],
            "axis": ["axisbank.com"],
        }

        for brand_key, brand_name in brand_domains.items():
            if brand_key in domain_base:
                is_official = False
                if brand_key in official_domains:
                    for official in official_domains[brand_key]:
                        if official in domain or domain.endswith("." + official):
                            is_official = True
                            break

                if not is_official:
                    result["is_fake"] = True
                    result["brand"] = brand_name
                    result["details"] = {
                        "domain": domain,
                        "claimed_brand": brand_key,
                        "is_official": False,
                    }
                    break

        return result

    def _detect_lookalike_domain(self, domain: str) -> Optional[str]:
        """Detect lookalike domains."""
        domain_base = domain.split(".")[0].lower()

        brands = [
            "paypal",
            "amazon",
            "paytm",
            "google",
            "facebook",
            "apple",
            "microsoft",
            "netflix",
            "instagram",
            "twitter",
            "linkedin",
        ]

        homoglyphs = {
            "0": "o",
            "1": "l",
            "i": "l",
            "e": "c",
            "a": "4",
            "s": "5",
            "o": "0",
            "i": "1",
        }

        for brand in brands:
            if len(brand) < 4:
                continue

            if domain_base == brand:
                continue

            distance = 0
            for i, char in enumerate(domain_base):
                if i < len(brand) and char != brand[i]:
                    if char in homoglyphs and homoglyphs[char] == brand[i]:
                        distance += 0.5
                    else:
                        distance += 1

            if distance <= 2 and len(domain_base) == len(brand):
                return brand

            if distance == 1:
                return brand

        return None

    def _calculate_risk_level(self, score: int, critical_flags: list) -> str:
        """Calculate final risk level with critical override."""
        if critical_flags:
            return "Phishing"

        if score <= 30:
            return "Safe"
        elif score <= 69:
            return "Suspicious"
        else:
            return "Phishing"


def analyze_qr(qr_content: str, qr_image_base64: str = None) -> Dict[str, Any]:
    """
    Convenience function for QR code analysis.

    Args:
        qr_content: Decoded QR content
        qr_image_base64: Optional base64 encoded QR image

    Returns:
        dict: Analysis result
    """
    analyzer = QRAnalyzer()
    return analyzer.analyze(qr_content, qr_image_base64)


def decode_qr_from_base64(image_base64: str) -> Optional[str]:
    """
    Convenience function to decode QR from base64 image.

    Args:
        image_base64: Base64 encoded image

    Returns:
        str: Decoded QR content or None
    """
    analyzer = QRAnalyzer()
    return analyzer.decode_from_image(image_base64)
