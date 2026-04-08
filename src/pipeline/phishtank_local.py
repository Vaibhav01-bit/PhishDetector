"""
PhishTank Local Database Service
================================
Fast, offline phishing detection using locally stored PhishTank database.
No API dependency - works completely offline.

Features:
- O(1) URL lookup using Python set
- Domain + path pattern matching
- Auto-update every N hours (configurable)
- Thread-safe operations
"""

import json
import threading
import time
import requests
import os
from typing import Set, Dict, Optional, Tuple
from urllib.parse import urlparse

PHISHING = "Phishing"
UNKNOWN = "Unknown"


class PhishTankLocalDB:
    """
    Local PhishTank database for instant phishing detection.
    """

    DATABASE_URL = "http://data.phishtank.com/data/online-valid.json"
    DEFAULT_DB_PATH = "data/phishtank.json"
    DEFAULT_UPDATE_INTERVAL = 12 * 60 * 60  # 12 hours in seconds

    def __init__(self, db_path: str = None, update_interval: int = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.update_interval = update_interval or self.DEFAULT_UPDATE_INTERVAL

        self._exact_urls: Set[str] = set()
        self._domain_paths: Dict[str, Set[str]] = {}
        self._all_domains: Set[str] = set()

        self._lock = threading.RLock()
        self._update_thread = None
        self._running = False
        self._last_updated = None
        self._total_entries = 0

        self._load_database()
        self._start_auto_update()

    def _normalize_url(self, url: str) -> Tuple[str, str, str]:
        """
        Normalize URL for consistent lookup.
        Returns: (full_normalized, domain_only, path_only)
        """
        url = url.lower().strip()
        url = url.replace("https://", "").replace("http://", "")

        if url.startswith("www."):
            url = url[4:]

        url = url.rstrip("/")

        if "/" in url:
            domain, path = url.split("/", 1)
            path = "/" + path
        else:
            domain = url
            path = "/"

        return url, domain, path

    def _load_database(self) -> bool:
        """Load PhishTank JSON into memory structures."""
        try:
            if not os.path.exists(self.db_path):
                print(f"[PhishTank] Database not found at {self.db_path}")
                print("[PhishTank] Will attempt to download on first check")
                return False

            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            exact_urls = set()
            domain_paths = {}
            all_domains = set()

            for entry in data:
                url = entry.get("url", "")
                if not url:
                    continue

                normalized, domain, path = self._normalize_url(url)
                exact_urls.add(normalized)
                all_domains.add(domain)

                if domain not in domain_paths:
                    domain_paths[domain] = set()
                domain_paths[domain].add(path)

            with self._lock:
                self._exact_urls = exact_urls
                self._domain_paths = domain_paths
                self._all_domains = all_domains
                self._last_updated = time.time()
                self._total_entries = len(exact_urls)

            print(
                f"[PhishTank] Loaded {len(exact_urls)} URLs, {len(all_domains)} domains"
            )
            return True

        except json.JSONDecodeError as e:
            print(f"[PhishTank] Invalid JSON in database: {e}")
            return False
        except Exception as e:
            print(f"[PhishTank] Error loading database: {e}")
            return False

    def is_phishing(self, url: str) -> Tuple[str, str]:
        """
        Check if URL is in PhishTank database.

        Returns: (status, message)
        - (PHISHING, reason) if found
        - (UNKNOWN, "Not in database") if not found
        """
        if not self._exact_urls:
            if not self._load_database():
                return (UNKNOWN, "Database unavailable")

        normalized, domain, path = self._normalize_url(url)

        if normalized in self._exact_urls:
            return (PHISHING, "Exact URL match in phishing database")

        with self._lock:
            if domain in self._domain_paths:
                for known_path in self._domain_paths[domain]:
                    if path.startswith(known_path) or known_path == "/":
                        return (PHISHING, f"Phishing pattern on known malicious domain")

        return (UNKNOWN, "URL not found in database")

    def is_known_malicious_domain(self, domain: str) -> bool:
        """Check if domain is in the phishing database (any path)."""
        if not self._all_domains:
            return False

        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        return domain in self._all_domains

    def _download_database(self) -> bool:
        """Download fresh database from PhishTank."""
        temp_path = self.db_path + ".tmp"
        db_dir = os.path.dirname(self.db_path)

        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        try:
            print("[PhishTank] Downloading fresh database...")
            print("[PhishTank] This may take a moment (database is ~5-10MB)...")

            response = requests.get(self.DATABASE_URL, timeout=120)
            response.raise_for_status()

            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(response.json(), f)

            os.replace(temp_path, self.db_path)

            print("[PhishTank] Database updated successfully")
            return self._load_database()

        except requests.exceptions.Timeout:
            print(f"[PhishTank] Download timeout - will retry later")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False
        except requests.exceptions.ConnectionError:
            print(f"[PhishTank] Connection error - will retry later")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False
        except Exception as e:
            print(f"[PhishTank] Download failed: {e}")
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return False

    def _start_auto_update(self):
        """Start background thread for periodic updates."""
        self._running = True
        self._update_thread = threading.Thread(
            target=self._update_loop, daemon=True, name="PhishTank-Updater"
        )
        self._update_thread.start()

    def _update_loop(self):
        """Background update loop."""
        while self._running:
            time.sleep(self.update_interval)
            if self._running:
                self._download_database()

    def update_now(self) -> bool:
        """Manually trigger database update."""
        return self._download_database()

    def get_stats(self) -> Dict:
        """Get database statistics."""
        return {
            "total_urls": self._total_entries,
            "total_domains": len(self._all_domains),
            "last_updated": self._last_updated,
            "database_path": self.db_path,
            "database_exists": os.path.exists(self.db_path),
        }

    def close(self):
        """Stop background updater."""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)


_db_instance: Optional[PhishTankLocalDB] = None


def get_phishtank_db() -> PhishTankLocalDB:
    """Get or create the singleton database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = PhishTankLocalDB()
    return _db_instance


def is_phishing_url(url: str) -> Tuple[str, str]:
    """Convenience function to check URL."""
    return get_phishtank_db().is_phishing(url)
