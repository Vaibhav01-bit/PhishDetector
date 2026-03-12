"""
URL Sandbox Analyzer
Safely opens and analyzes URLs in an isolated headless browser environment.
Captures screenshots (in-memory), extracts metadata, and performs behavioral inspection.
NO DATA IS STORED - All processing is in-memory only.
"""

import os
import time
import json
import base64
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO
from PIL import Image
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
from .sandbox_utils import (
    is_private_ip,
    normalize_url,
    validate_url_format,
    resolve_domain_ip,
    detect_suspicious_keywords,
    generate_scan_id,
    ensure_directory_exists,
    is_localhost_domain,
    extract_domain_from_url,
)


class SandboxAnalyzer:
    """
    Analyzes URLs in a secure sandbox environment.
    Uses Synchronous Playwright API for stability in threaded Flask environments.
    NO DATA IS STORED - All screenshots and results are in-memory only.
    """

    def __init__(self, timeout_ms=30000):
        """
        Initialize the sandbox analyzer.

        Args:
            timeout_ms: Maximum time to wait for page load (milliseconds)
        """
        self.timeout_ms = timeout_ms
        self.max_redirects = 10

    def analyze(self, url, scan_id=None):
        """
        Main analysis entry point.

        Args:
            url (str): URL to analyze
            scan_id (str): Optional scan ID (generated if not provided)

        Returns:
            dict: Analysis results (including Base64 screenshot)
        """
        try:
            if not scan_id:
                scan_id = generate_scan_id()

            result = self._analyze_sync(url, scan_id)
            return result

        except Exception as e:
            return self._error_result(f"Sandbox analysis failed: {str(e)}")

    def _optimize_screenshot_in_memory(self, image_bytes):
        """
        Optimize screenshot in memory (resize if needed).

        Args:
            image_bytes: Raw JPEG image bytes

        Returns:
            bytes: Optimized JPEG image bytes
        """
        try:
            from PIL import Image as PILImage

            img = PILImage.open(BytesIO(image_bytes))

            max_width = 1200
            if img.width > max_width:
                ratio = max_width / img.width
                new_height = int(img.height * ratio)
                # Use Lanczos resampling for high-quality downscaling
                resample_method = getattr(
                    PILImage,
                    "LANCZOS",
                    getattr(PILImage, "RESAMPLE", PILImage.BILINEAR),
                )
                img = img.resize((max_width, new_height), resample_method)

            output = BytesIO()
            img.save(output, format="JPEG", quality=85, optimize=True)
            return output.getvalue()
        except Exception as e:
            print(f"Screenshot optimization failed: {e}")
            # Return original bytes if optimization fails
            return image_bytes

    def _analyze_sync(self, url, scan_id):
        """
        Synchronous analysis implementation.

        Args:
            url (str): URL to analyze
            scan_id (str): Unique scan identifier

        Returns:
            dict: Analysis results
        """
        start_time = time.time()

        url = normalize_url(url)
        is_valid, validation_msg = validate_url_format(url)

        if not is_valid:
            return self._error_result(validation_msg)

        parsed = urlparse(url)
        domain = parsed.netloc

        if is_localhost_domain(domain):
            return self._error_result("Localhost URLs are blocked for security")

        ip_address, ip_error = resolve_domain_ip(domain)

        if ip_error:
            return self._error_result(ip_error)

        with sync_playwright() as p:
            browser = None
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-accelerated-2d-canvas",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=IsolateOrigins,site-per-process",
                    ],
                )

                context = browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ignore_https_errors=True,
                    accept_downloads=False,
                    java_script_enabled=True,
                    bypass_csp=True,
                )

                page = context.new_page()

                load_result = self._load_page(page, url)

                if load_result.get("error"):
                    browser.close()
                    return self._error_result(load_result["error"])

                screenshot_base64 = self._capture_screenshot_in_memory(page)

                metadata = self._extract_metadata(page, url, load_result)

                behavioral = self._inspect_behavior(page, domain)

                browser.close()

                total_time = int((time.time() - start_time) * 1000)

                result = {
                    "success": True,
                    "scan_id": scan_id,
                    "source_url": url,
                    "final_url": load_result.get("final_url", url),
                    "redirect_count": load_result.get("redirect_count", 0),
                    "ip_address": ip_address,
                    "domain": extract_domain_from_url(metadata.get("final_url", url)),
                    "page_title": metadata.get("title", "N/A"),
                    "load_time": load_result.get("load_time", 0),
                    "total_time": total_time,
                    "screenshot_base64": screenshot_base64,
                    "sandbox_message": "Rendered in an isolated sandbox. No user interaction.",
                    "has_login_form": behavioral.get("has_login_form", False),
                    "has_password_field": behavioral.get("has_password_field", False),
                    "has_email_field": behavioral.get("has_email_field", False),
                    "suspicious_keywords": behavioral.get("keywords", []),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }

                return result

            except Exception as e:
                if browser:
                    try:
                        browser.close()
                    except:
                        pass

                return self._error_result(f"Browser error: {str(e)}")

    def _load_page(self, page, url):
        """Load page with redirect tracking and timeout."""
        start_time = time.time()

        try:
            response = page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")

            final_url = page.url

            redirect_count = 0
            if response:
                r = response.request
                while r.redirected_from:
                    redirect_count += 1
                    r = r.redirected_from

            load_time = int((time.time() - start_time) * 1000)

            return {
                "final_url": final_url,
                "redirect_count": redirect_count,
                "load_time": load_time,
                "status_code": response.status if response else None,
            }

        except PlaywrightTimeout:
            return {"error": "Page load timeout (30 seconds exceeded)"}
        except Exception as e:
            return {"error": f"Page load failed: {str(e)}"}

    def _capture_screenshot_in_memory(self, page):
        """
        Capture full-page screenshot to memory (Base64 encoded).

        Returns:
            str: Base64-encoded JPEG image (data URL format)
        """
        try:
            screenshot_bytes = page.screenshot(full_page=True, type="jpeg", quality=85)

            optimized_bytes = self._optimize_screenshot_in_memory(screenshot_bytes)

            base64_encoded = base64.b64encode(optimized_bytes).decode("utf-8")

            return f"data:image/jpeg;base64,{base64_encoded}"

        except Exception as e:
            print(f"Screenshot capture failed: {e}")
            return None

    def _extract_metadata(self, page, original_url, load_result):
        """Extract page metadata."""
        try:
            title = page.title()
            final_url = load_result.get("final_url", original_url)

            return {"title": title if title else "No Title", "final_url": final_url}

        except Exception as e:
            return {"title": "N/A", "final_url": original_url}

    def _inspect_behavior(self, page, domain):
        """Perform behavioral inspection."""
        result = {
            "has_login_form": False,
            "has_password_field": False,
            "has_email_field": False,
            "keywords": [],
        }

        try:
            password_fields = page.query_selector_all('input[type="password"]')
            result["has_password_field"] = len(password_fields) > 0

            email_selectors = [
                'input[type="email"]',
                'input[name*="email"]',
                'input[placeholder*="email"]',
            ]

            for selector in email_selectors:
                elements = page.query_selector_all(selector)
                if len(elements) > 0:
                    result["has_email_field"] = True
                    break

            login_selectors = [
                'form[action*="login"]',
                'form[action*="signin"]',
                'form[id*="login"]',
                'form[class*="login"]',
            ]

            for selector in login_selectors:
                element = page.query_selector(selector)
                if element:
                    result["has_login_form"] = True
                    break

            if result["has_password_field"]:
                result["has_login_form"] = True

            try:
                body_text = page.inner_text("body")
                keywords = detect_suspicious_keywords(body_text)
                result["keywords"] = keywords
            except:
                pass

            return result

        except Exception as e:
            print(f"Behavioral inspection failed: {e}")
            return result

    def _error_result(self, error_message):
        """Generate error result structure."""
        return {
            "success": False,
            "error": error_message,
            "scan_id": None,
            "screenshot_base64": None,
        }
