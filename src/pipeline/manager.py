import atexit
from .layers import (
    Layer0_Validation,
    Layer1_Blacklist,
    Layer2_Domain,
    Layer3_SSL,
    Layer4_ML_Model,
    Layer5_Behavioral,
    SAFE,
    WARNING,
    PHISHING,
    INVALID,
)
try:
    from .sandbox import SandboxAnalyzer
except ImportError:
    SandboxAnalyzer = None  # type: ignore
from .forensics import ForensicAnalyzer
from .sandbox_utils import generate_scan_id
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional


class InMemoryStatusStore:
    """
    Thread-safe in-memory storage for scan status.
    NO DATA IS STORED - All data exists only during scanning.
    """

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def set(self, scan_id, data):
        with self._lock:
            self._store[scan_id] = data

    def get(self, scan_id):
        with self._lock:
            return self._store.get(scan_id)

    def clear(self, scan_id):
        with self._lock:
            self._store.pop(scan_id, None)

    def get_all(self):
        with self._lock:
            return dict(self._store)


class PhishingDetectionPipeline:
    sandbox: Optional["SandboxAnalyzer"]  # type: ignore

    def __init__(self, enable_sandbox=True):
        self.forensics = ForensicAnalyzer()
        self.l0 = Layer0_Validation()
        self.l1 = Layer1_Blacklist()
        self.l2 = Layer2_Domain()
        self.l3 = Layer3_SSL()
        self.l4 = Layer4_ML_Model()
        self.l5 = Layer5_Behavioral()
        self.sandbox = None
        if enable_sandbox and SandboxAnalyzer is not None:
            self.sandbox = SandboxAnalyzer()

        self._fast_results = InMemoryStatusStore()
        self._sandbox_status = InMemoryStatusStore()

        if enable_sandbox:
            self._sandbox_executor = ThreadPoolExecutor(
                max_workers=max(2, min(4, os.cpu_count() or 2)),
                thread_name_prefix="sandbox-worker",
            )
            atexit.register(self._shutdown_sandbox_resources)
            self._prewarm_sandbox_workers()
        else:
            self._sandbox_executor = None

    def analyze_fast(self, url):
        """
        FAST PATH: Runs forensics + layers 1-5 only (no sandbox).
        Returns preliminary verdict immediately with a scan_id so the
        caller can launch the sandbox asynchronously and poll for results.
        """
        scan_id = generate_scan_id()
        results = {}

        url = self.l0.sanitize(url)

        status, message = self.l0.check(url)
        if status == INVALID:
            return self._finalize_fast(
                INVALID,
                {"validation": {"status": status, "message": message}},
                {},
                scan_id,
            )

        forensics_data = self.forensics.analyze(url)
        target_url = forensics_data["final_url"]

        redirect_count = forensics_data.get("redirect_count", 0)
        is_shortener = forensics_data.get("is_shortener", False)

        if redirect_count > 3:
            results["forensics_check"] = {
                "status": WARNING,
                "message": f"Excessive redirects ({redirect_count}). Risk of obfuscation.",
            }
        elif is_shortener:
            results["forensics_check"] = {
                "status": SAFE,
                "message": "Shortened URL detected. Final destination analyzed.",
            }
        elif redirect_count > 0:
            results["forensics_check"] = {
                "status": SAFE,
                "message": f"Redirects followed ({redirect_count}). Final destination analyzed.",
            }
        else:
            results["forensics_check"] = {
                "status": SAFE,
                "message": "Direct link. No redirects.",
            }

        status, message = self.l1.check(target_url)
        results["layer1"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l2.check(target_url)
        results["layer2"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l3.check(target_url)
        results["layer3"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l4.check(target_url)
        results["layer4"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize_fast(PHISHING, results, forensics_data, scan_id)

        status, message = self.l5.check(target_url)
        results["layer5"] = {"status": status, "message": message}

        warnings = [r for r in results.values() if r.get("status") == WARNING]
        final_status = WARNING if warnings else SAFE

        return self._finalize_fast(final_status, results, forensics_data, scan_id)

    def _finalize_fast(self, final_status, results, forensics_data, scan_id):
        """Package the fast result in memory for polling."""
        data = {
            "status": final_status,
            "layers": results,
            "forensics": forensics_data,
            "scan_id": scan_id,
            "preliminary": True,
        }

        self._fast_results.set(scan_id, data)

        return data

    def run_sandbox_background(self, url, scan_id):
        """
        Launch sandbox analysis on the shared background worker pool.
        ALL work happens off the request thread — never blocks the HTTP response.
        NO DATA IS STORED - all data is in-memory only.
        """
        if not self.sandbox or not self._sandbox_executor:
            return  # Silently skip in serverless environments

        fast_data = self._fast_results.get(scan_id)
        if fast_data:
            layers_snapshot = fast_data.get("layers", {})
            final_status = fast_data.get("status", SAFE)
            forensics_snap = fast_data.get("forensics", {})
        else:
            layers_snapshot = {}
            final_status = SAFE
            forensics_snap = {}

        def _run():
            status_data = {"done": True, "success": False, "scan_id": scan_id}
            try:
                sandbox_result = {"success": False, "error": "Sandbox uninitialized"}
                if self.sandbox:
                    try:
                        sandbox_result = self.sandbox.analyze(
                            url,
                            scan_id=scan_id,
                            preflight=self._build_sandbox_preflight(forensics_snap),
                        )
                    except Exception as sandbox_e:
                        sandbox_result = {
                            "success": False,
                            "error": str(sandbox_e),
                            "source_url": url,
                        }

                status_data = {
                    "done": True,
                    "success": sandbox_result.get("success", False),
                    "screenshot_base64": sandbox_result.get("screenshot_base64"),
                    "scan_id": scan_id,
                    "source_url": sandbox_result.get("source_url", url),
                    "final_url": sandbox_result.get("final_url"),
                    "ip_address": sandbox_result.get("ip_address"),
                    "domain": sandbox_result.get("domain"),
                    "page_title": sandbox_result.get("page_title"),
                    "redirect_count": sandbox_result.get("redirect_count", 0),
                    "load_time": sandbox_result.get("load_time", 0),
                    "timestamp": sandbox_result.get("timestamp"),
                    "has_login_form": sandbox_result.get("has_login_form", False),
                    "has_password_field": sandbox_result.get(
                        "has_password_field", False
                    ),
                    "has_email_field": sandbox_result.get("has_email_field", False),
                    "suspicious_keywords": sandbox_result.get(
                        "suspicious_keywords", []
                    ),
                    "sandbox_message": sandbox_result.get("sandbox_message"),
                    "error": sandbox_result.get("error"),
                    "layers": layers_snapshot,
                    "forensics": forensics_snap,
                    "final_status": final_status,
                }
            except Exception as e:
                import traceback

                print(f"[Sandbox BG error] {traceback.format_exc()}")
                status_data = {
                    "done": True,
                    "success": False,
                    "error": str(e),
                    "scan_id": scan_id,
                    "source_url": url,
                    "layers": layers_snapshot,
                    "forensics": forensics_snap,
                    "final_status": final_status,
                }

            self._sandbox_status.set(scan_id, status_data)
            print(
                f"[Sandbox] status stored in memory: success={status_data['success']}"
            )

        self._sandbox_executor.submit(_run)

    def get_sandbox_status(self, scan_id):
        """
        Read the status from in-memory store.
        Returns None if not yet done.
        """
        return self._sandbox_status.get(scan_id)

    def analyze(self, url):
        results = {}

        url = self.l0.sanitize(url)

        status, message = self.l0.check(url)
        if status == INVALID:
            return self._finalize(
                INVALID, {"validation": {"status": status, "message": message}}, {}
            )

        forensics_data = self.forensics.analyze(url)
        target_url = forensics_data["final_url"]

        redirect_count = forensics_data.get("redirect_count", 0)
        is_shortener = forensics_data.get("is_shortener", False)

        if redirect_count > 3:
            results["forensics_check"] = {
                "status": WARNING,
                "message": f"Excessive redirects detected ({redirect_count}). Risk of obfuscation.",
            }
        elif is_shortener:
            results["forensics_check"] = {
                "status": SAFE,
                "message": "Shortened URL detected. Final destination analyzed.",
            }
        elif redirect_count > 0:
            results["forensics_check"] = {
                "status": SAFE,
                "message": f"Redirects followed ({redirect_count}). Final destination analyzed.",
            }
        else:
            results["forensics_check"] = {
                "status": SAFE,
                "message": "Direct link. No redirects.",
            }

        status, message = self.l1.check(target_url)
        results["layer1"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)

        status, message = self.l2.check(target_url)
        results["layer2"] = {"status": status, "message": message}
        if status == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)

        status, message = self.l3.check(target_url)
        results["layer3"] = {"status": status, "message": message}

        status, message = self.l4.check(target_url)
        results["layer4"] = {"status": status, "message": message}

        status, message = self.l5.check(target_url)
        results["layer5"] = {"status": status, "message": message}

        final_status = SAFE

        if results["layer4"]["status"] == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)

        if results["layer3"]["status"] == PHISHING:
            return self._finalize(PHISHING, results, forensics_data)

        warnings = [r for r in results.values() if r["status"] == WARNING]
        if len(warnings) > 0:
            final_status = WARNING
        else:
            final_status = SAFE

        if self.sandbox:
            try:
                sandbox_result = self.sandbox.analyze(
                    url,
                    preflight=self._build_sandbox_preflight(forensics_data),
                )
                results["sandbox"] = sandbox_result
            except Exception as e:
                import traceback

                error_msg = f"Sandbox error: {str(e)}\n{traceback.format_exc()}"
                print(error_msg)
                results["sandbox"] = {
                    "success": False,
                    "error": str(e),
                    "scan_id": None,
                }

        return self._finalize(final_status, results, forensics_data)

    def _finalize(self, final_status, results, forensics_data):
        return {"status": final_status, "layers": results, "forensics": forensics_data}

    def _build_sandbox_preflight(self, forensics_data):
        """Pass already-resolved forensic hints into the sandbox step."""
        if not forensics_data:
            return {}
        return {
            "ip_address": forensics_data.get("ip_address"),
            "final_url": forensics_data.get("final_url"),
            "domain": forensics_data.get("domain"),
            "redirect_count": forensics_data.get("redirect_count", 0),
        }

    def _shutdown_sandbox_resources(self):
        """Allow the process to exit cleanly while reusing browser workers during runtime."""
        if self._sandbox_executor:
            try:
                self._sandbox_executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        if self.sandbox:
            try:
                self.sandbox.close()
            except Exception:
                pass

    def _prewarm_sandbox_workers(self):
        """Warm Playwright runtimes in the background so the first scan returns sooner."""
        if not self._sandbox_executor:
            return
        for _ in range(getattr(self._sandbox_executor, "_max_workers", 0)):
            future = self._sandbox_executor.submit(self._warm_single_sandbox_worker)
            future.add_done_callback(self._consume_background_exception)

    def _warm_single_sandbox_worker(self):
        if not self.sandbox:
            return
        try:
            self.sandbox._get_runtime()
        except Exception:
            pass

    @staticmethod
    def _consume_background_exception(future):
        try:
            future.exception()
        except Exception:
            pass
