"""
URL Sandbox Analyzer
Safely opens and analyzes URLs in an isolated headless browser environment.
Captures screenshots, extracts metadata, and performs behavioral inspection.
"""

import asyncio
import os
import time
import json
from datetime import datetime
from urllib.parse import urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from .sandbox_utils import (
    is_private_ip,
    normalize_url,
    validate_url_format,
    resolve_domain_ip,
    optimize_screenshot,
    detect_suspicious_keywords,
    generate_scan_id,
    ensure_directory_exists,
    is_localhost_domain,
    extract_domain_from_url
)


class SandboxAnalyzer:
    """
    Analyzes URLs in a secure sandbox environment.
    """
    
    def __init__(self, screenshot_dir="static/sandbox_screenshots", 
                 results_dir="static/sandbox_results",
                 timeout_ms=15000):
        """
        Initialize the sandbox analyzer.
        
        Args:
            screenshot_dir: Directory to store screenshots
            results_dir: Directory to store analysis results (JSON)
            timeout_ms: Maximum time to wait for page load (milliseconds)
        """
        self.screenshot_dir = screenshot_dir
        self.results_dir = results_dir
        self.timeout_ms = timeout_ms
        self.max_redirects = 10
        
        # Ensure directories exist
        ensure_directory_exists(self.screenshot_dir)
        ensure_directory_exists(self.results_dir)
    
    def analyze(self, url, scan_id=None):
        """
        Main analysis entry point (synchronous wrapper).
        
        Args:
            url (str): URL to analyze
            scan_id (str): Optional scan ID (generated if not provided)
            
        Returns:
            dict: Analysis results
        """
        try:
            # Generate scan ID if not provided
            if not scan_id:
                scan_id = generate_scan_id()
            
            # Run async analysis
            result = asyncio.run(self._analyze_async(url, scan_id))
            
            # Save result to JSON file for later retrieval
            if result.get('success'):
                self._save_result(scan_id, result)
            
            return result
            
        except Exception as e:
            return self._error_result(f"Sandbox analysis failed: {str(e)}")
    
    def _save_result(self, scan_id, result):
        """Save analysis result to JSON file."""
        try:
            result_path = os.path.join(self.results_dir, f"{scan_id}.json")
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save result: {e}")
    
    def get_result(self, scan_id):
        """
        Retrieve a saved sandbox result.
        
        Args:
            scan_id: The scan ID to retrieve
            
        Returns:
            dict: Sandbox result or None if not found
        """
        try:
            result_path = os.path.join(self.results_dir, f"{scan_id}.json")
            if os.path.exists(result_path):
                with open(result_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error retrieving result: {e}")
        return None
    
    def save_full_results(self, scan_id, full_data):
        """
        Save complete pipeline results (5 layers + sandbox).
        
        Args:
            scan_id: The scan ID
            full_data: Complete pipeline analysis data
        """
        try:
            result_path = os.path.join(self.results_dir, f"{scan_id}_full.json")
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(full_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Failed to save full results: {e}")
    
    async def _analyze_async(self, url, scan_id):
        """
        Async analysis implementation.
        
        Args:
            url (str): URL to analyze
            scan_id (str): Unique scan identifier
            
        Returns:
            dict: Analysis results
        """
        start_time = time.time()
        
        # Step 1: Validate URL
        url = normalize_url(url)
        is_valid, validation_msg = validate_url_format(url)
        
        if not is_valid:
            return self._error_result(validation_msg)
        
        # Step 2: Check for localhost
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if is_localhost_domain(domain):
            return self._error_result("Localhost URLs are blocked for security")
        
        # Step 3: Resolve IP and check for private ranges
        ip_address, ip_error = resolve_domain_ip(domain)
        
        if ip_error:
            return self._error_result(ip_error)
        
        # Step 4: Initialize browser and analyze
        browser = None
        try:
            async with async_playwright() as p:
                # Launch browser
                browser = await self._init_browser(p)
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    ignore_https_errors=False,
                    accept_downloads=False,
                    java_script_enabled=True,
                    bypass_csp=False
                )
                
                # Create page
                page = await context.new_page()
                
                # Load page and track redirects
                load_result = await self._load_page(page, url)
                
                if load_result.get('error'):
                    await browser.close()
                    return self._error_result(load_result['error'])
                
                # Capture screenshot
                screenshot_path = await self._capture_screenshot(page, scan_id)
                
                # Extract metadata
                metadata = await self._extract_metadata(page, url, load_result)
                
                # Behavioral inspection
                behavioral = await self._inspect_behavior(page, domain)
                
                # Close browser
                await browser.close()
                
                # Calculate total time
                total_time = int((time.time() - start_time) * 1000)
                
                # Compile results
                result = {
                    'success': True,
                    'scan_id': scan_id,
                    'source_url': url,
                    'final_url': load_result.get('final_url', url),
                    'redirect_count': load_result.get('redirect_count', 0),
                    'ip_address': ip_address,
                    'domain': extract_domain_from_url(metadata.get('final_url', url)),
                    'page_title': metadata.get('title', 'N/A'),
                    'load_time': load_result.get('load_time', 0),
                    'total_time': total_time,
                    'screenshot_path': screenshot_path,
                    'has_login_form': behavioral.get('has_login_form', False),
                    'has_password_field': behavioral.get('has_password_field', False),
                    'has_email_field': behavioral.get('has_email_field', False),
                    'suspicious_keywords': behavioral.get('keywords', []),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                return result
                
        except Exception as e:
            if browser:
                try:
                    await browser.close()
                except:
                    pass
            
            return self._error_result(f"Browser error: {str(e)}")
    
    async def _init_browser(self, playwright):
        """
        Initialize headless browser with security settings.
        
        Args:
            playwright: Playwright instance
            
        Returns:
            Browser instance
        """
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--disable-web-security',  # For CORS issues
                '--disable-features=IsolateOrigins,site-per-process'
            ]
        )
        
        return browser
    
    async def _load_page(self, page, url):
        """
        Load page with redirect tracking and timeout.
        
        Args:
            page: Playwright page instance
            url (str): URL to load
            
        Returns:
            dict: Load result with final URL, redirects, and timing
        """
        start_time = time.time()
        redirect_chain = []
        
        # Track redirects
        page.on('response', lambda response: redirect_chain.append(response.url))
        
        try:
            # Navigate to URL
            response = await page.goto(
                url,
                timeout=self.timeout_ms,
                wait_until='networkidle'
            )
            
            # Get final URL
            final_url = page.url
            
            # Count unique redirects
            unique_redirects = list(dict.fromkeys(redirect_chain))
            redirect_count = len(unique_redirects) - 1  # Subtract original
            
            # Calculate load time
            load_time = int((time.time() - start_time) * 1000)
            
            return {
                'final_url': final_url,
                'redirect_count': max(0, redirect_count),
                'load_time': load_time,
                'status_code': response.status if response else None
            }
            
        except PlaywrightTimeout:
            return {'error': 'Page load timeout (15 seconds exceeded)'}
        except Exception as e:
            return {'error': f'Page load failed: {str(e)}'}
    
    async def _capture_screenshot(self, page, scan_id):
        """
        Capture full-page screenshot.
        
        Args:
            page: Playwright page instance
            scan_id (str): Unique scan identifier
            
        Returns:
            str: Screenshot filename
        """
        try:
            filename = f"{scan_id}.jpg"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            # Capture screenshot
            await page.screenshot(
                path=filepath,
                full_page=True,
                type='jpeg',
                quality=85
            )
            
            # Optimize screenshot
            optimize_screenshot(filepath, max_width=1200, quality=85)
            
            return filename
            
        except Exception as e:
            print(f"Screenshot capture failed: {e}")
            return None
    
    async def _extract_metadata(self, page, original_url, load_result):
        """
        Extract page metadata.
        
        Args:
            page: Playwright page instance
            original_url (str): Original URL
            load_result (dict): Load result data
            
        Returns:
            dict: Metadata
        """
        try:
            # Get page title
            title = await page.title()
            
            # Get final URL
            final_url = load_result.get('final_url', original_url)
            
            return {
                'title': title if title else 'No Title',
                'final_url': final_url
            }
            
        except Exception as e:
            return {
                'title': 'N/A',
                'final_url': original_url
            }
    
    async def _inspect_behavior(self, page, domain):
        """
        Perform behavioral inspection without executing actions.
        
        Args:
            page: Playwright page instance
            domain (str): Domain name
            
        Returns:
            dict: Behavioral flags
        """
        result = {
            'has_login_form': False,
            'has_password_field': False,
            'has_email_field': False,
            'keywords': []
        }
        
        try:
            # Check for password fields
            password_fields = await page.query_selector_all('input[type="password"]')
            result['has_password_field'] = len(password_fields) > 0
            
            # Check for email fields
            email_selectors = [
                'input[type="email"]',
                'input[name*="email"]',
                'input[placeholder*="email"]'
            ]
            
            for selector in email_selectors:
                elements = await page.query_selector_all(selector)
                if len(elements) > 0:
                    result['has_email_field'] = True
                    break
            
            # Check for login forms
            login_selectors = [
                'form[action*="login"]',
                'form[action*="signin"]',
                'form[id*="login"]',
                'form[class*="login"]'
            ]
            
            for selector in login_selectors:
                element = await page.query_selector(selector)
                if element:
                    result['has_login_form'] = True
                    break
            
            # If password field exists, likely a login form
            if result['has_password_field']:
                result['has_login_form'] = True
            
            # Scan for suspicious keywords
            try:
                body_text = await page.inner_text('body')
                keywords = detect_suspicious_keywords(body_text)
                result['keywords'] = keywords
            except:
                pass
            
            return result
            
        except Exception as e:
            print(f"Behavioral inspection failed: {e}")
            return result
    
    def _error_result(self, error_message):
        """
        Generate error result structure.
        
        Args:
            error_message (str): Error description
            
        Returns:
            dict: Error result
        """
        return {
            'success': False,
            'error': error_message,
            'scan_id': None,
            'screenshot_path': None
        }
