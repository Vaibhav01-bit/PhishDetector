import os
import re
import socket
import ssl
import whois
import requests
import pickle
import numpy as np
from urllib.parse import urlparse
from datetime import datetime
from feature import FeatureExtraction
from .brand_impersonation import BrandImpersonationDetector

# Define risk levels
SAFE = "Safe"
WARNING = "Warning"
PHISHING = "Phishing"

class Layer1_Blacklist:
    def __init__(self, blacklist_path="blacklist.txt"):
        self.blacklist_path = blacklist_path
        self.blacklist = self._load_blacklist()

    def _load_blacklist(self):
        try:
            with open(self.blacklist_path, "r") as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def check(self, url):
        # Normalize the input URL to match the blacklist format
        # 1. Parse URL
        try:
             # Ensure scheme exists for urlparse
            if not url.startswith(('http://', 'https://')):
                temp_url = 'http://' + url
            else:
                temp_url = url
            
            parsed = urlparse(temp_url)
            domain = parsed.netloc or temp_url
            
            # 2. Normalize
            domain = domain.lower()
            if domain.startswith("www."):
                domain = domain[4:]
            
            domain = domain.strip()
            
            if domain in self.blacklist:
                return PHISHING, "Domain found in blacklist."
            return SAFE, "Domain not in blacklist."
        except Exception:
             # If parsing fails, fall back to simple check or safe
             return SAFE, "Domain analysis skipped (invalid format)."

class Layer2_Domain:
    # Static whitelist for brand impersonation checks (kept for backward compatibility)
    BRAND_DOMAINS = {
        'paypal': ['paypal.com', 'paypal-objects.com'],
        'google': ['google.com', 'gmail.com', 'accounts.google.com'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'live.com', 'office.com'],
        'amazon': ['amazon.com', 'ssl-images-amazon.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'instagram': ['instagram.com'],
        'netflix': ['netflix.com'],
        'chase': ['chase.com'],
        'wellsfargo': ['wellsfargo.com']
    }

    # Static list of known decentralized content gateways
    DECENTRALIZED_GATEWAYS = [
        'ipfs.io',
        'cloudflare-ipfs.com',
        'gateway.pinata.cloud',
        'dweb.link'
    ]

    def __init__(self):
        """Initialize Layer 2 with brand impersonation detector."""
        self.brand_detector = BrandImpersonationDetector()

    def check(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or url
        domain = domain.lower() # Normalize for analysis
        
        # 0. Check for Decentralized Gateway
        # If matched, treat as neutral infrastructure (WARNING/Suspicious mainly for opacity)
        if any(domain == gateway or domain.endswith('.' + gateway) for gateway in self.DECENTRALIZED_GATEWAYS):
            return WARNING, "Hosted on a Decentralized Platform – Proceed with Caution"
            
        score = 0
        reasons = []

        # Feature 1: Brand Impersonation Detection (NEW - Enhanced)
        # Use the advanced brand impersonation detector
        brand_result = self.brand_detector.check(url, domain)
        
        if brand_result['is_impersonation']:
            # Strong indicator of phishing attempt
            score += 2
            reasons.append(brand_result['message'])
            # Add specific reasons from the detector
            if brand_result['details'].get('typosquatting_detected'):
                reasons.append("Typosquatting pattern detected")
            if brand_result['details'].get('intent_keywords'):
                keywords = ', '.join(brand_result['details']['intent_keywords'][:3])  # Limit to 3
                reasons.append(f"Phishing keywords: {keywords}")
            if brand_result['details'].get('homoglyphs_detected'):
                reasons.append("Character substitution detected")

        # Feature 2: Long Domain
        if len(domain) > 50:
            score += 1
            reasons.append("Domain is unusually long.")

        # Feature 3: High Subdomain Count
        subdomains = domain.split('.')
        # Filter out empty strings from split (e.g., trailing dot)
        subdomains = [s for s in subdomains if s]
        if len(subdomains) > 4:
            score += 1
            reasons.append("High number of subdomains.")
            
        # Feature 4: Suspicious TLD Weighting
        high_risk_tlds = ['.xyz', '.top', '.club', '.info', '.cn', '.help', '.work', '.gq']
        low_risk_tlds = ['.gov', '.edu', '.mil']
        
        if any(domain.endswith(tld) for tld in high_risk_tlds):
            score += 1
            reasons.append("Suspicious or high-risk Top Level Domain (TLD).")
            
        elif any(domain.endswith(tld) for tld in low_risk_tlds):
            score -= 1 # Reduce risk for trusted TLDs

        # Ensure score floor is 0
        score = max(0, score)
            
        if score >= 2:
             return WARNING, f"Suspicious domain features: {', '.join(reasons)}"
        return SAFE, "Domain analysis passed."

class Layer3_SSL:
    def check(self, url):
        # Simplified check: Rely on scheme.
        # This avoids SSRF risks and performance overhead of connection checks.
        if url.startswith("https://"):
             return SAFE, "Valid HTTPS Scheme."
        
        return WARNING, "Insecure (HTTP) or Unknown Scheme."

class Layer4_ML_Model:
    def __init__(self, model_path="newmodel.pkl"):
        self.model_path = model_path
        try:
           self.model = pickle.load(open(model_path, "rb"))
        except:
           self.model = None

    def check(self, url):
        if not self.model:
            return WARNING, "ML Model not loaded."

        try:
            # Use the existing FeatureExtraction class from feature.py
            obj = FeatureExtraction(url)
            # Reshape as expected by the model (1, 30)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            
            y_pred = self.model.predict(x)[0]
            
            # Existing model convention: 1 is safe, -1 is unsafe (phishing)
            if y_pred == 1:
                return SAFE, "ML Model predicts Safe."
            else:
                return PHISHING, "ML Model predicts Phishing."
        except Exception as e:
            return WARNING, f"ML Extraction failed: {str(e)}"

class Layer5_Behavioral:
    def check(self, url):
        reasons = []
        parsed = urlparse(url)
        
        # Check for '@' symbol in URL
        if "@" in url:
            return PHISHING, "URL contains '@' symbol (often used to obscure destination)."
            
        # Check for IP address as domain
        domain = parsed.netloc
        try:
            socket.inet_aton(domain)
            return PHISHING, "URL uses IP address instead of domain name."
        except:
            pass # Not an IP
            
        # Check for multiple redirects (Basic check)
        if "//" in parsed.path:
             return WARNING, "URL path contains '//' which may indicate redirection."
             
        return SAFE, "Behavioral analysis passed."

