import re
import io
import zipfile
from typing import List, Dict, Any


class ZIPParser:
    SUPPORTED_EXTENSIONS = [".zip"]
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
    ]

    @staticmethod
    def parse(file_bytes: bytes) -> Dict[str, Any]:
        urls = []
        text = ""
        metadata = {}
        scripts = []
        macros_detected = False
        dangerous_files = []

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                file_list = zf.namelist()
                metadata = {
                    "file_count": len(file_list),
                    "files": file_list[:20],
                }

                for filename in file_list:
                    if any(
                        filename.lower().endswith(ext)
                        for ext in ZIPParser.DANGEROUS_EXTENSIONS
                    ):
                        dangerous_files.append(filename)

                    try:
                        with zf.open(filename) as f:
                            content = f.read()

                            if filename.endswith(".txt"):
                                try:
                                    text += (
                                        content.decode("utf-8", errors="ignore") + "\n"
                                    )
                                except:
                                    pass

                                urls.extend(ZIPParser._extract_urls_from_bytes(content))

                            if filename.endswith((".html", ".htm")):
                                try:
                                    html_content = content.decode(
                                        "utf-8", errors="ignore"
                                    )
                                    text += html_content + "\n"
                                    urls.extend(
                                        ZIPParser._extract_urls_from_text(html_content)
                                    )
                                except:
                                    pass

                            if b"<script" in content or b"javascript:" in content:
                                scripts.append(f"script in: {filename}")

                            if b"vbaProject.bin" in content or b"VBA" in content:
                                macros_detected = True

                    except Exception:
                        pass

                urls = list(set(urls))

        except Exception as e:
            urls = ZIPParser._extract_urls_from_bytes(file_bytes)

        return {
            "text": text[:5000],
            "urls": urls,
            "metadata": metadata,
            "scripts": scripts,
            "macros_detected": macros_detected,
            "dangerous_files": dangerous_files,
        }

    @staticmethod
    def _extract_urls_from_bytes(data: bytes) -> List[str]:
        try:
            text = data.decode("utf-8", errors="ignore")
            return ZIPParser._extract_urls_from_text(text)
        except:
            return []

    @staticmethod
    def _extract_urls_from_text(text: str) -> List[str]:
        url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"{}|\\^`\[\]]*',
            re.IGNORECASE,
        )
        return url_pattern.findall(text)
