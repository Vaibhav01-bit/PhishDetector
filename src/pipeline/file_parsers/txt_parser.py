import re
from typing import List, Dict, Any


class TXTParser:
    SUPPORTED_EXTENSIONS = [
        ".txt",
        ".log",
        ".csv",
        ".json",
        ".xml",
        ".ini",
        ".cfg",
        ".conf",
    ]

    @staticmethod
    def parse(file_bytes: bytes) -> Dict[str, Any]:
        urls = []
        text = ""
        metadata = {}
        scripts = []
        macros_detected = False

        try:
            text = file_bytes.decode("utf-8", errors="ignore")
        except:
            try:
                text = file_bytes.decode("latin-1", errors="ignore")
            except:
                text = ""

        urls = TXTParser._extract_urls_from_text(text)
        scripts = TXTParser._detect_suspicious_content(text)

        return {
            "text": text,
            "urls": urls,
            "metadata": metadata,
            "scripts": scripts,
            "macros_detected": macros_detected,
        }

    @staticmethod
    def _extract_urls_from_text(text: str) -> List[str]:
        url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"{}|\\^`\[\]]*',
            re.IGNORECASE,
        )
        return url_pattern.findall(text)

    @staticmethod
    def _detect_suspicious_content(text: str) -> List[str]:
        scripts = []
        suspicious_patterns = [
            r"powershell\s+-",
            r"cmd\.exe",
            r"certutil",
            r"bitsadmin",
            r"wscript",
            r"cscript",
            r"reg\s+add",
            r"schtasks",
            r"base64",
            r"encodedcommand",
            r"downloadfile",
            r"invoke-webrequest",
            r"curl\s+",
            r"wget\s+",
            r"nc\s+-",
            r"bind\s+shell",
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                scripts.append(pattern)

        return scripts
