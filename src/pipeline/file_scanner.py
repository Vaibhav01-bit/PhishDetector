import math
import re
import os
import io
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from .file_parsers import (
    PDFParser,
    DOCXParser,
    XLSXParser,
    HTMLParser,
    TXTParser,
    ZIPParser,
)

SUPPORTED_EXTENSIONS = {
    ".pdf": PDFParser,
    ".docx": DOCXParser,
    ".doc": DOCXParser,
    ".docm": DOCXParser,
    ".xlsx": XLSXParser,
    ".xls": XLSXParser,
    ".xlsm": XLSXParser,
    ".html": HTMLParser,
    ".htm": HTMLParser,
    ".html5": HTMLParser,
    ".txt": TXTParser,
    ".log": TXTParser,
    ".csv": TXTParser,
    ".json": TXTParser,
    ".xml": TXTParser,
    ".zip": ZIPParser,
}

MALWARE_SIGNATURES = [
    b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
]

TRUSTED_DOMAINS = {
    # Social/Professional
    "github.com",
    "github.io",
    "linkedin.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "reddit.com",
    "medium.com",
    "tiktok.com",
    "pinterest.com",
    "tumblr.com",
    "snapchat.com",
    "whatsapp.com",
    "telegram.org",
    # Tech/Cloud
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "cloudflare.com",
    "vercel.app",
    "netlify.app",
    "heroku.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "digitalocean.com",
    "oracle.com",
    "ibm.com",
    "salesforce.com",
    "shopify.com",
    # Productivity
    "dropbox.com",
    "drive.google.com",
    "onedrive.live.com",
    "docs.google.com",
    "office.com",
    "notion.so",
    "slack.com",
    "trello.com",
    "asana.com",
    "airtable.com",
    "monday.com",
    "zoom.us",
    "teams.microsoft.com",
    # Email providers
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "protonmail.com",
    "fastmail.com",
    "zoho.com",
    "mail.com",
    # Common legitimate services
    "paypal.com",
    "stripe.com",
    "squareup.com",
    "venmo.com",
    "coinbase.com",
    "wikipedia.org",
    "cnn.com",
    "bbc.com",
    "nytimes.com",
    "reuters.com",
    "stackexchange.com",
    "stackoverflow.com",
    "atlassian.net",
    "jetbrains.com",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
    ".ga",
    ".pw",
    ".cc",
    ".ws",
    ".work",
    ".click",
    ".link",
    ".buzz",
    ".loan",
    ".men",
    ".date",
    ".racing",
    ".science",
    ".party",
    ".cricket",
    ".win",
    ".download",
    ".bid",
    ".stream",
    ".trade",
    ".accountant",
    ".review",
    ".faith",
    ".date",
    ".download",
}

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".js",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".ps1",
    ".jar",
    ".com",
    ".pif",
    ".msi",
    ".apk",
    ".dll",
    ".scr",
    ".hta",
    ".vba",
    ".vbe",
    ".wsf",
]

HIGH_ENTROPY_THRESHOLD = 7.0
MEDIUM_ENTROPY_THRESHOLD = 6.0

RISK_SCORE_WEIGHTS = {
    "malware_signature": 70,
    "executable_embedded": 50,
    "macro_detected": 40,
    "high_risk_phishing_url": 30,
    "suspicious_phishing_url": 15,
    "obfuscated_script": 20,
    "high_entropy": 15,
    "medium_entropy": 8,
    "dangerous_file_in_archive": 20,
    "suspicious_tld": 10,
}

RISK_LEVEL_THRESHOLDS = {
    "safe": 20,
    "suspicious": 50,
    "dangerous": 100,
}

MAX_URL_SCANS = 5


MAX_FILE_SIZES = {
    ".pdf": 20 * 1024 * 1024,  # 20MB for PDFs
    ".docx": 10 * 1024 * 1024,  # 10MB for DOCX
    ".doc": 10 * 1024 * 1024,
    ".docm": 10 * 1024 * 1024,
    ".xlsx": 10 * 1024 * 1024,  # 10MB for XLSX
    ".xls": 10 * 1024 * 1024,
    ".xlsm": 10 * 1024 * 1024,
    ".zip": 10 * 1024 * 1024,  # 10MB for ZIP
    ".html": 10 * 1024 * 1024,
    ".htm": 10 * 1024 * 1024,
    ".html5": 10 * 1024 * 1024,
    ".txt": 10 * 1024 * 1024,
    ".log": 10 * 1024 * 1024,
    ".csv": 10 * 1024 * 1024,
    ".json": 10 * 1024 * 1024,
    ".xml": 10 * 1024 * 1024,
}

DEFAULT_MAX_SIZE = 10 * 1024 * 1024  # 10MB default


class FileSecurityScanner:
    def __init__(self, phishing_pipeline=None):
        self.phishing_pipeline = phishing_pipeline

    def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        file_size = len(file_bytes)

        ext = os.path.splitext(filename)[1].lower()
        max_size = MAX_FILE_SIZES.get(ext, DEFAULT_MAX_SIZE)

        if file_size > max_size:
            return {
                "error": f"File exceeds maximum allowed size ({max_size // (1024 * 1024)}MB)",
                "error_code": "FILE_TOO_LARGE",
                "max_size_mb": max_size // (1024 * 1024),
                "file_size_mb": round(file_size / (1024 * 1024), 2),
            }

        ext = os.path.splitext(filename)[1].lower()

        if ext not in SUPPORTED_EXTENSIONS:
            return {
                "error": "Unsupported file format",
                "error_code": "UNSUPPORTED_FORMAT",
                "supported_formats": list(SUPPORTED_EXTENSIONS.keys()),
            }

        parser = SUPPORTED_EXTENSIONS[ext]()

        try:
            parsed = parser.parse(file_bytes)
        except Exception as e:
            return {
                "error": "File could not be analyzed",
                "error_code": "PARSE_ERROR",
                "details": str(e),
            }

        malware_result = self._scan_malware_signatures(file_bytes)
        entropy_result = self._calculate_entropy(file_bytes)

        url_analysis = self._analyze_urls(parsed["urls"])

        if self.phishing_pipeline and url_analysis["urls_to_scan"]:
            phishing_results = self._scan_urls_with_phishing_pipeline(
                url_analysis["urls_to_scan"]
            )
            url_analysis["phishing_scan_results"] = phishing_results

        risk_score = self._calculate_risk_score(
            malware_result=malware_result,
            url_analysis=url_analysis,
            scripts=parsed.get("scripts", []),
            macros_detected=parsed.get("macros_detected", False),
            entropy=entropy_result,
            ext=ext,
            dangerous_files=parsed.get("dangerous_files", []),
        )

        risk_level = self._get_risk_level(risk_score)

        summary = self._generate_summary(
            malware_result=malware_result,
            url_analysis=url_analysis,
            macros_detected=parsed.get("macros_detected", False),
            scripts=parsed.get("scripts", []),
            entropy=entropy_result,
            risk_level=risk_level,
        )

        result = {
            "filename": filename,
            "file_type": ext.upper().replace(".", ""),
            "file_size": file_size,
            "malware_scan": malware_result,
            "urls_found": url_analysis["all_urls_info"][:20],
            "url_analysis": {
                "total_urls": url_analysis["total_urls"],
                "trusted_urls": len(url_analysis["trusted_urls"]),
                "suspicious_urls": len(url_analysis["suspicious_urls"]),
                "high_risk_urls": len(url_analysis["high_risk_urls"]),
                "urls_to_scan": url_analysis.get("urls_to_scan", [])[:MAX_URL_SCANS],
                "urls_scanned_with_pipeline": len(
                    url_analysis.get("phishing_scan_results", [])
                ),
            },
            "scripts_detected": parsed.get("scripts", [])[:10],
            "macros_detected": parsed.get("macros_detected", False),
            "entropy_score": round(entropy_result, 2),
            "entropy_level": self._get_entropy_level(entropy_result),
            "file_type_risk": self._analyze_file_type_risk(ext),
            "risk_level": risk_level,
            "risk_score": risk_score,
            "summary": summary,
            "metadata": parsed.get("metadata", {}),
        }

        if "dangerous_files" in parsed:
            result["dangerous_files"] = parsed["dangerous_files"]

        return result

    def _scan_malware_signatures(self, file_bytes: bytes) -> Dict[str, Any]:
        suspicious_signatures = []

        for sig in MALWARE_SIGNATURES:
            if sig in file_bytes:
                suspicious_signatures.append(sig.decode("utf-8", errors="ignore")[:50])

        if suspicious_signatures:
            return {
                "status": "Malware Detected",
                "suspicious_signatures": suspicious_signatures,
            }

        if file_bytes[:2] == b"MZ":
            return {
                "status": "Suspicious",
                "suspicious_signatures": ["PE/COFF executable header detected"],
            }

        return {"status": "Clean", "suspicious_signatures": []}

    def _calculate_entropy(self, file_bytes: bytes) -> float:
        if not file_bytes:
            return 0.0

        byte_counts = [0] * 256
        for byte in file_bytes:
            byte_counts[byte] += 1

        entropy = 0.0
        file_len = len(file_bytes)

        for count in byte_counts:
            if count > 0:
                probability = count / file_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _get_entropy_level(self, entropy: float) -> str:
        if entropy >= HIGH_ENTROPY_THRESHOLD:
            return "High"
        elif entropy >= MEDIUM_ENTROPY_THRESHOLD:
            return "Medium"
        return "Low"

    def _extract_domain(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain if domain else None
        except:
            return None

    def _is_trusted_domain(self, domain: str) -> bool:
        domain = domain.lower()
        if domain in TRUSTED_DOMAINS:
            return True
        for trusted in TRUSTED_DOMAINS:
            if domain.endswith("." + trusted):
                return True
        return False

    def _has_suspicious_tld(self, domain: str) -> bool:
        domain = domain.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        return False

    def _is_suspicious_url_pattern(self, url: str, domain: str) -> bool:
        url_lower = url.lower()
        domain_lower = domain.lower()

        suspicious_keywords = [
            "login",
            "signin",
            "secure",
            "account",
            "update",
            "verify",
            "confirm",
            "bank",
            "paypal",
            "invoice",
            "payment",
            "billing",
            "support",
            "reset",
            "password",
            "credential",
            "auth",
            "admin",
            "wallet",
            "crypto",
            "bitcoin",
            "eth",
            "security",
            "alert",
            "unlock",
            "limited",
            "urgent",
            "immediate",
            "act-now",
        ]

        for keyword in suspicious_keywords:
            if keyword in url_lower or keyword in domain_lower:
                if not self._is_trusted_domain(domain_lower):
                    return True

        return False

    def _analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        trusted_urls = []
        suspicious_urls = []
        high_risk_urls = []
        urls_to_scan = []
        all_urls_info = []

        for url in urls:
            domain = self._extract_domain(url)

            if not domain:
                suspicious_urls.append(url)
                urls_to_scan.append(url)
                all_urls_info.append(
                    {
                        "url": url,
                        "domain": "unknown",
                        "status": "unknown",
                        "risk": "medium",
                    }
                )
                continue

            if self._is_trusted_domain(domain):
                trusted_urls.append(url)
                all_urls_info.append(
                    {"url": url, "domain": domain, "status": "trusted", "risk": "none"}
                )
                continue

            if self._has_suspicious_tld(domain):
                high_risk_urls.append(url)
                urls_to_scan.append(url)
                all_urls_info.append(
                    {
                        "url": url,
                        "domain": domain,
                        "status": "high_risk",
                        "risk": "high",
                        "reason": "Suspicious TLD",
                    }
                )
                continue

            if self._is_suspicious_url_pattern(url, domain):
                suspicious_urls.append(url)
                urls_to_scan.append(url)
                all_urls_info.append(
                    {
                        "url": url,
                        "domain": domain,
                        "status": "suspicious",
                        "risk": "medium",
                        "reason": "Suspicious pattern",
                    }
                )
                continue

            urls_to_scan.append(url)
            all_urls_info.append(
                {"url": url, "domain": domain, "status": "unknown", "risk": "low"}
            )

        urls_to_scan = urls_to_scan[:MAX_URL_SCANS]

        return {
            "total_urls": len(urls),
            "trusted_urls": trusted_urls,
            "suspicious_urls": suspicious_urls,
            "high_risk_urls": high_risk_urls,
            "urls_to_scan": urls_to_scan,
            "all_urls_info": all_urls_info,
        }

    def _scan_urls_with_phishing_pipeline(
        self, urls: List[str]
    ) -> List[Dict[str, Any]]:
        results = []

        if not self.phishing_pipeline:
            return results

        for url in urls:
            try:
                result = self.phishing_pipeline.analyze(url)
                status = result.get("status", "Unknown")

                risk_level = "low"
                if status == "Phishing":
                    risk_level = "high"
                elif status == "Warning":
                    risk_level = "medium"

                results.append(
                    {
                        "url": url,
                        "status": status,
                        "risk_level": risk_level,
                        "details": result,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "url": url,
                        "status": "Error",
                        "risk_level": "unknown",
                        "error": str(e),
                    }
                )

        return results

    def _analyze_file_type_risk(self, ext: str) -> Dict[str, Any]:
        if ext in DANGEROUS_EXTENSIONS:
            return {
                "file_type": ext.upper(),
                "risk_level": "High",
                "reason": "Executable file types can contain malicious code",
            }

        high_risk = [".html", ".htm", ".js", ".vbs", ".ps1", ".docm", ".xlsm", ".pptm"]
        medium_risk = [".pdf", ".docx", ".xlsx", ".zip", ".html5"]

        if ext in high_risk:
            return {
                "file_type": ext.upper(),
                "risk_level": "Medium",
                "reason": "Can contain embedded scripts or macros",
            }

        if ext in medium_risk:
            return {
                "file_type": ext.upper(),
                "risk_level": "Low",
                "reason": "Can contain hyperlinks or macros",
            }

        return {
            "file_type": ext.upper(),
            "risk_level": "Minimal",
            "reason": "Low risk file type",
        }

    def _calculate_risk_score(
        self,
        malware_result: Dict,
        url_analysis: Dict,
        scripts: List[str],
        macros_detected: bool,
        entropy: float,
        ext: str,
        dangerous_files: List[str],
    ) -> int:
        score = 0

        if malware_result["status"] == "Malware Detected":
            score += RISK_SCORE_WEIGHTS["malware_signature"]
        elif malware_result["status"] == "Suspicious":
            score += RISK_SCORE_WEIGHTS["executable_embedded"]

        phishing_results = url_analysis.get("phishing_scan_results", [])

        high_risk_count = 0
        suspicious_risk_count = 0

        for result in phishing_results:
            if result.get("risk_level") == "high":
                high_risk_count += 1
            elif result.get("risk_level") == "medium":
                suspicious_risk_count += 1

        score += min(high_risk_count * RISK_SCORE_WEIGHTS["high_risk_phishing_url"], 60)
        score += min(
            suspicious_risk_count * RISK_SCORE_WEIGHTS["suspicious_phishing_url"], 30
        )

        pattern_high_risk = len(url_analysis.get("high_risk_urls", []))
        pattern_suspicious = len(url_analysis.get("suspicious_urls", []))
        score += min(pattern_high_risk * 5, 20)
        score += min(pattern_suspicious * 3, 15)

        if len(scripts) > 0:
            obfuscated_count = sum(
                1
                for s in scripts
                if any(
                    x in s.lower()
                    for x in [
                        "eval",
                        "fromcharcode",
                        "atob",
                        "decode",
                        "obfusc",
                        "encrypted",
                    ]
                )
            )
            if obfuscated_count > 0:
                score += min(
                    obfuscated_count * RISK_SCORE_WEIGHTS["obfuscated_script"], 30
                )
            else:
                score += min(len(scripts) * 3, 10)

        if macros_detected:
            score += RISK_SCORE_WEIGHTS["macro_detected"]

        if entropy >= HIGH_ENTROPY_THRESHOLD:
            score += RISK_SCORE_WEIGHTS["high_entropy"]
        elif entropy >= MEDIUM_ENTROPY_THRESHOLD:
            score += RISK_SCORE_WEIGHTS["medium_entropy"]

        if dangerous_files:
            score += min(
                len(dangerous_files) * RISK_SCORE_WEIGHTS["dangerous_file_in_archive"],
                40,
            )

        if ext in DANGEROUS_EXTENSIONS:
            score += 20

        return min(score, 100)

    def _get_risk_level(self, score: int) -> str:
        if score >= RISK_LEVEL_THRESHOLDS["suspicious"]:
            return "Dangerous"
        elif score >= RISK_LEVEL_THRESHOLDS["safe"]:
            return "Suspicious"
        return "Safe"

    def _generate_summary(
        self,
        malware_result: Dict,
        url_analysis: Dict,
        macros_detected: bool,
        scripts: List[str],
        entropy: float,
        risk_level: str,
    ) -> str:
        parts = []

        if malware_result["status"] == "Malware Detected":
            return f"Malware detected! This file contains malicious code."

        if malware_result["status"] == "Suspicious":
            parts.append("Suspicious executable content detected")

        phishing_results = url_analysis.get("phishing_scan_results", [])
        high_risk_from_pipeline = sum(
            1 for r in phishing_results if r.get("risk_level") == "high"
        )

        if high_risk_from_pipeline > 0:
            return f"High-risk phishing links detected! {high_risk_from_pipeline} URL(s) flagged as dangerous by analysis."

        if url_analysis.get("high_risk_urls"):
            parts.append(
                f"{len(url_analysis['high_risk_urls'])} high-risk URL(s) with suspicious TLDs"
            )

        if url_analysis.get("suspicious_urls"):
            parts.append(
                f"{len(url_analysis['suspicious_urls'])} suspicious URL(s) with phishing patterns"
            )

        if macros_detected:
            parts.append(
                "Document contains macros - potential malicious code execution risk"
            )

        obfuscated_scripts = [
            s
            for s in scripts
            if any(
                x in s.lower()
                for x in ["eval", "fromcharcode", "atob", "decode", "obfusc"]
            )
        ]
        if obfuscated_scripts:
            parts.append(f"{len(obfuscated_scripts)} obfuscated script(s) detected")

        if entropy >= HIGH_ENTROPY_THRESHOLD:
            parts.append(
                f"High entropy ({entropy:.1f}) suggests packed or encrypted content"
            )

        trusted_count = len(url_analysis.get("trusted_urls", []))
        total_urls = url_analysis.get("total_urls", 0)
        if trusted_count > 0 and trusted_count == total_urls:
            return (
                f"File is safe. All {trusted_count} link(s) are from trusted domains."
            )

        if not parts:
            if risk_level == "Safe":
                return "File appears to be clean with no detected threats."
            else:
                return "No specific threats detected but exercise caution with unknown links."

        return " | ".join(parts)
