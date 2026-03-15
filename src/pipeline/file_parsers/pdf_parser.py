import re
import io
from typing import List, Dict, Any

try:
    import pdfplumber

    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False


class PDFParser:
    SUPPORTED_EXTENSIONS = [".pdf"]

    @staticmethod
    def parse(file_bytes: bytes) -> Dict[str, Any]:
        urls = []
        text = ""
        metadata = {}
        scripts = []
        macros_detected = False

        if not PDFPLUMBER_AVAILABLE:
            text = PDFParser._extract_text_raw(file_bytes)
            urls = PDFParser._extract_urls_from_text(text)
            return {
                "text": text,
                "urls": urls,
                "metadata": metadata,
                "scripts": scripts,
                "macros_detected": macros_detected,
            }

        try:
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                metadata = {
                    "page_count": len(pdf.pages),
                    "metadata": dict(pdf.metadata) if pdf.metadata else {},
                }

                for page in pdf.pages:
                    page_text = page.extract_text() or ""
                    text += page_text + "\n"

                    urls.extend(PDFParser._extract_urls_from_text(page_text))

                    if page.extract_links():
                        for link in page.extract_links():
                            if isinstance(link, dict) and "uri" in link:
                                urls.append(link["uri"])

                urls = list(set(urls))

                scripts = PDFParser._detect_obfuscated_scripts(file_bytes, text)

        except Exception as e:
            text = PDFParser._extract_text_raw(file_bytes)
            urls = PDFParser._extract_urls_from_text(text)

        return {
            "text": text,
            "urls": urls,
            "metadata": metadata,
            "scripts": scripts,
            "macros_detected": macros_detected,
        }

    @staticmethod
    def _extract_text_raw(file_bytes: bytes) -> str:
        try:
            return file_bytes.decode("utf-8", errors="ignore")
        except:
            return ""

    @staticmethod
    def _extract_urls_from_text(text: str) -> List[str]:
        url_pattern = re.compile(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>()\[\]]*", re.IGNORECASE
        )
        return url_pattern.findall(text)

    @staticmethod
    def _detect_obfuscated_scripts(file_bytes: bytes, text: str) -> List[str]:
        scripts = []

        obfuscated_patterns = [
            (r"eval\s*\([^)]+\)", "eval() function - code execution"),
            (r"fromCharCode\s*\(", "fromCharCode() - character obfuscation"),
            (r"atob\s*\(", "atob() - base64 decode"),
            (r"unescape\s*\(", "unescape() - URL encoding"),
            (r"decodeURIComponent\s*\(", "decodeURIComponent() - URL decode"),
            (r"String\.fromCharCode", "String.fromCharCode - obfuscation"),
            (r"\\x[0-9a-fA-F]{2}", "Hex escape sequences"),
            (r"\\u[0-9a-fA-F]{4}", "Unicode escape sequences"),
            (r"setTimeout\s*\(\s*['\"]\s*eval", "setTimeout with eval"),
            (r"exec\s*\(", "exec() function"),
            (r"Function\s*\(", "Function constructor"),
        ]

        file_content = file_bytes.decode("latin-1", errors="ignore")

        for pattern, description in obfuscated_patterns:
            matches = re.findall(pattern, file_content, re.IGNORECASE)
            if matches:
                scripts.append(description)

        suspicious_js_actions = [
            (r"this\.app\.alert", "PDF JavaScript alert"),
            (r"this\.exportXML", "PDF XML export"),
            (r"this\.getField", "PDF form field access"),
            (r"this\.setValue", "PDF form value set"),
            (r"app\.execDialog", "PDF dialog execution"),
            (r"doc\.gelPageNthWord", "PDF page word extraction"),
        ]

        for pattern, description in suspicious_js_actions:
            if re.search(pattern, file_content, re.IGNORECASE):
                scripts.append(description)

        return list(set(scripts))
