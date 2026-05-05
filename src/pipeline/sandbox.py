"""
URL Sandbox Analyzer
Safely opens and analyzes URLs in an isolated headless browser environment.
Captures screenshots (in-memory), extracts metadata, and performs behavioral inspection.
NO DATA IS STORED - All processing is in-memory only.
"""

import atexit
import base64
import threading
import time
from io import BytesIO
from urllib.parse import urlparse

from PIL import Image as PILImage

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None  # type: ignore
    PlaywrightTimeout = TimeoutError  # type: ignore
from .sandbox_utils import (
    is_private_ip,
    normalize_url,
    validate_url_format,
    resolve_domain_ip,
    detect_suspicious_keywords,
    generate_scan_id,
    is_localhost_domain,
    extract_domain_from_url,
)


class SandboxAnalyzer:
    """
    Analyzes URLs in a secure sandbox environment.
    Uses Synchronous Playwright API for stability in threaded Flask environments.
    NO DATA IS STORED - All screenshots and results are in-memory only.
    """

    def __init__(
        self,
        timeout_ms=20000,
        settle_timeout_ms=3000,
        screenshot_width=1200,
        screenshot_quality=82,
        capture_full_page=False,
    ):
        """
        Initialize the sandbox analyzer.

        Args:
            timeout_ms: Maximum time to wait for page load (milliseconds)
        """
        self.timeout_ms = timeout_ms
        self.settle_timeout_ms = settle_timeout_ms
        self.screenshot_width = screenshot_width
        self.screenshot_quality = screenshot_quality
        self.capture_full_page = capture_full_page
        self.max_redirects = 10
        self._runtime_lock = threading.Lock()
        self._thread_runtimes = {}
        atexit.register(self.close)

    def analyze(self, url, scan_id=None, preflight=None):
        """
        Main analysis entry point.

        Args:
            url (str): URL to analyze
            scan_id (str): Optional scan ID (generated if not provided)
            preflight (dict): Optional resolved forensic hints from the fast scan

        Returns:
            dict: Analysis results (including Base64 screenshot)
        """
        try:
            if not scan_id:
                scan_id = generate_scan_id()

            return self._analyze_sync(url, scan_id, preflight=preflight or {})

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
            img = PILImage.open(BytesIO(image_bytes))

            if img.width > self.screenshot_width:
                ratio = self.screenshot_width / img.width
                new_height = int(img.height * ratio)
                # Use Lanczos resampling for high-quality downscaling
                resample_method = getattr(
                    PILImage,
                    "LANCZOS",
                    getattr(PILImage, "RESAMPLE", PILImage.BILINEAR),
                )
                img = img.resize((self.screenshot_width, new_height), resample_method)

            output = BytesIO()
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            img.save(
                output,
                format="JPEG",
                quality=self.screenshot_quality,
                optimize=True,
            )
            return output.getvalue()
        except Exception as e:
            print(f"Screenshot optimization failed: {e}")
            # Return original bytes if optimization fails
            return image_bytes

    def _get_runtime(self):
        """Reuse one Playwright/Chromium runtime per worker thread."""
        thread_id = threading.get_ident()
        with self._runtime_lock:
            runtime = self._thread_runtimes.get(thread_id)
            if runtime:
                return runtime

        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-background-timer-throttling",
                "--disable-breakpad",
                "--disable-sync",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-first-run",
            ],
        )
        runtime = {"playwright": playwright, "browser": browser}

        with self._runtime_lock:
            self._thread_runtimes[thread_id] = runtime

        return runtime

    def _reset_runtime(self):
        """Drop the current thread runtime so a later attempt can recreate it."""
        thread_id = threading.get_ident()
        with self._runtime_lock:
            runtime = self._thread_runtimes.pop(thread_id, None)
        if not runtime:
            return
        try:
            runtime["browser"].close()
        except Exception:
            pass
        try:
            runtime["playwright"].stop()
        except Exception:
            pass

    def close(self):
        """Release all persistent browser runtimes."""
        with self._runtime_lock:
            runtimes = list(self._thread_runtimes.values())
            self._thread_runtimes.clear()

        for runtime in runtimes:
            try:
                runtime["browser"].close()
            except Exception:
                pass
            try:
                runtime["playwright"].stop()
            except Exception:
                pass

    def _analyze_sync(self, url, scan_id, preflight):
        """
        Synchronous analysis implementation.

        Args:
            url (str): URL to analyze
            scan_id (str): Unique scan identifier
            preflight (dict): Optional resolved forensic hints

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

        ip_address = preflight.get("ip_address")
        if not ip_address or ip_address == "Unknown":
            ip_address, ip_error = resolve_domain_ip(domain)
        else:
            ip_error = None
            if is_private_ip(ip_address):
                ip_error = f"Domain resolves to private IP: {ip_address}"

        if ip_error:
            return self._error_result(ip_error)

        navigation_url = self._choose_navigation_url(url, preflight)

        for attempt in range(2):
            context = None
            page = None
            try:
                runtime = self._get_runtime()
                context = runtime["browser"].new_context(
                    viewport={"width": 1280, "height": 720},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ignore_https_errors=True,
                    accept_downloads=False,
                    java_script_enabled=True,
                )
                context.set_default_timeout(self.timeout_ms)
                context.set_default_navigation_timeout(self.timeout_ms)
                context.route("**/*", self._route_request)

                page = context.new_page()
                page.on("dialog", lambda dialog: dialog.dismiss())

                load_result = self._load_page(
                    page,
                    url,
                    navigation_url=navigation_url,
                    preflight=preflight,
                )

                if load_result.get("error"):
                    return self._error_result(load_result["error"])

                page.wait_for_timeout(3000)

                screenshot_base64 = self._capture_screenshot_in_memory(page, page_ref=page)
                if screenshot_base64 is None:
                    print(f"[Sandbox] Warning: Screenshot is None for {url}")

                metadata = self._extract_metadata(page, url, load_result)

                behavioral = self._inspect_behavior(page)

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
                self._reset_runtime()
                if attempt == 1:
                    return self._error_result(f"Browser error: {str(e)}")
            finally:
                if page:
                    try:
                        page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass

    def _load_page(self, page, original_url, navigation_url=None, preflight=None):
        """Load page with redirect tracking and timeout."""
        start_time = time.time()
        preferred_url = navigation_url or original_url
        preflight = preflight or {}
        response = None

        try:
            response = page.goto(
                preferred_url,
                timeout=self.timeout_ms,
                wait_until="domcontentloaded",
            )

            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeout:
                pass
            except Exception:
                pass

            final_url = page.url

            redirect_count = 0
            if response:
                r = response.request
                while r.redirected_from:
                    redirect_count += 1
                    r = r.redirected_from

            redirect_count = max(redirect_count, preflight.get("redirect_count", 0) or 0)
            load_time = int((time.time() - start_time) * 1000)

            return {
                "final_url": final_url or preflight.get("final_url") or original_url,
                "redirect_count": redirect_count,
                "load_time": load_time,
                "status_code": response.status if response else None,
            }

        except PlaywrightTimeout:
            return {"error": f"Page load timeout ({self.timeout_ms // 1000} seconds exceeded)"}
        except Exception as e:
            return {"error": f"Page load failed: {str(e)}"}

    def _choose_navigation_url(self, original_url, preflight):
        """Prefer the already-resolved final URL when the fast path found redirects."""
        candidate = (preflight or {}).get("final_url")
        if not candidate or candidate == original_url:
            return original_url

        candidate = normalize_url(candidate)
        is_valid, _ = validate_url_format(candidate)
        if not is_valid:
            return original_url

        if (preflight or {}).get("redirect_count", 0) > 0:
            return candidate

        return original_url

    def _route_request(self, route):
        """Abort background-heavy resource types that do not help the screenshot."""
        if route.request.resource_type in {"media", "websocket", "eventsource"}:
            route.abort()
            return
        route.continue_()

    def _capture_screenshot_in_memory(self, page, page_ref=None):
        """
        Capture full-page screenshot to memory (Base64 encoded).
        Retries up to 2 times if capture fails.

        Returns:
            str: Base64-encoded JPEG image (data URL format)
        """
        for attempt in range(3):
            try:
                screenshot_bytes = page.screenshot(
                    full_page=self.capture_full_page,
                    type="jpeg",
                    quality=self.screenshot_quality,
                )

                if len(screenshot_bytes) <= 250_000:
                    optimized_bytes = screenshot_bytes
                else:
                    optimized_bytes = self._optimize_screenshot_in_memory(screenshot_bytes)

                base64_encoded = base64.b64encode(optimized_bytes).decode("utf-8")
                print(f"[Screenshot] Captured successfully ({len(optimized_bytes)} bytes)")
                return f"data:image/jpeg;base64,{base64_encoded}"

            except Exception as e:
                print(f"[Screenshot] Capture failed (attempt {attempt + 1}/3): {e}")
                if attempt < 2:
                    page.wait_for_timeout(1500)
        print("[Screenshot] All capture attempts failed")
        return None

    def _extract_metadata(self, page, original_url, load_result):
        """Extract page metadata."""
        try:
            title = page.title()
            final_url = load_result.get("final_url", original_url)

            return {"title": title if title else "No Title", "final_url": final_url}

        except Exception:
            return {"title": "N/A", "final_url": original_url}

    def _inspect_behavior(self, page):
        """Perform behavioral inspection."""
        result = {
            "has_login_form": False,
            "has_password_field": False,
            "has_email_field": False,
            "keywords": [],
        }

        try:
            page_data = page.evaluate(
                """() => {
                    const matchesAny = (selectors) => selectors.some((selector) => !!document.querySelector(selector));
                    const bodyText = document.body
                        ? (document.body.innerText || document.body.textContent || "")
                        : "";

                    return {
                        hasPasswordField: !!document.querySelector('input[type="password"]'),
                        hasEmailField: matchesAny([
                            'input[type="email"]',
                            'input[name*="email" i]',
                            'input[placeholder*="email" i]'
                        ]),
                        hasLoginForm: matchesAny([
                            'form[action*="login" i]',
                            'form[action*="signin" i]',
                            'form[id*="login" i]',
                            'form[class*="login" i]'
                        ]),
                        bodyText: bodyText.slice(0, 20000)
                    };
                }"""
            )

            result["has_password_field"] = bool(page_data.get("hasPasswordField"))
            result["has_email_field"] = bool(page_data.get("hasEmailField"))
            result["has_login_form"] = bool(page_data.get("hasLoginForm")) or result["has_password_field"]
            result["keywords"] = detect_suspicious_keywords(page_data.get("bodyText", ""))

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
