import re
from typing import List, Dict, Any

try:
    from bs4 import BeautifulSoup

    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class HTMLParser:
    SUPPORTED_EXTENSIONS = [".html", ".htm", ".html5"]

    @staticmethod
    def parse(file_bytes: bytes) -> Dict[str, Any]:
        urls = []
        text = ""
        metadata = {}
        scripts = []
        macros_detected = False

        try:
            html_content = file_bytes.decode("utf-8", errors="ignore")
        except:
            html_content = file_bytes.decode("latin-1", errors="ignore")

        if BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(html_content, "html.parser")

                text = soup.get_text(separator=" ", strip=True)

                for link in soup.find_all("a", href=True):
                    if link["href"].startswith(("http://", "https://")):
                        urls.append(link["href"])

                for link in soup.find_all("area", href=True):
                    if link["href"].startswith(("http://", "https://")):
                        urls.append(link["href"])

                for link in soup.find_all("link", href=True):
                    if link["href"].startswith(("http://", "https://")):
                        urls.append(link["href"])

                for script in soup.find_all("script"):
                    if script.string:
                        scripts.append(script.string[:200])

                for inline in soup.find_all(attrs={"onclick": True}):
                    scripts.append(f"onclick: {inline.get('onclick', '')}")

                for inline in soup.find_all(attrs={"onerror": True}):
                    scripts.append(f"onerror: {inline.get('onerror', '')}")

                metadata = {
                    "title": soup.title.string if soup.title else "",
                    "meta_description": soup.find("meta", attrs={"name": "description"})
                    or "",
                }

            except Exception as e:
                text = HTMLParser._extract_text_raw(file_bytes)
                urls = HTMLParser._extract_urls_from_text(text)
        else:
            text = HTMLParser._extract_text_raw(file_bytes)
            urls = HTMLParser._extract_urls_from_text(text)

        urls = list(set(urls))

        scripts.extend(HTMLParser._detect_scripts(html_content))

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
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"{}|\\^`\[\]]*',
            re.IGNORECASE,
        )
        return url_pattern.findall(text)

    @staticmethod
    def _detect_scripts(html_content: str) -> List[str]:
        scripts = []
        suspicious_patterns = [
            (r"<script[^>]*>", "inline script tag"),
            (r"javascript:", "javascript protocol"),
            (r"onerror\s*=", "onerror event"),
            (r"onload\s*=", "onload event"),
            (r"onclick\s*=", "onclick event"),
            (r"document\.cookie", "cookie access"),
            (r"eval\s*\(", "eval function"),
            (r"atob\s*\(", "base64 decode"),
            (r"fromCharCode", "character code obfuscation"),
            (r"\\x[0-9a-f]{2}", "hex escape sequence"),
        ]

        for pattern, desc in suspicious_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                scripts.append(desc)

        return list(set(scripts))
