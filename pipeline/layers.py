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
        parsed = urlparse(url)
        domain = parsed.netloc or url # Handle cases without scheme
        if domain in self.blacklist:
            return PHISHING, "Domain found in blacklist."
        return SAFE, "Domain not in blacklist."

class Layer2_Domain:
    def check(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or url
        
        score = 0
        reasons = []

        # Feature 1: Long Domain
        if len(domain) > 50:
            score += 1
            reasons.append("Domain is unusually long.")

        # Feature 2: High Subdomain Count
        subdomains = domain.split('.')
        if len(subdomains) > 4:
            score += 1
            reasons.append("High number of subdomains.")
            
        # Feature 3: Suspicious TLD
        suspicious_tlds = ['.xyz', '.top', '.club', '.info', '.cn']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 1
            reasons.append("Suspicious Top Level Domain (TLD).")
            
        if score >= 2:
             return WARNING, f"Suspicious domain features: {', '.join(reasons)}"
        return SAFE, "Domain analysis passed."

class Layer3_SSL:
    def check(self, url):
        if not url.startswith("https://"):
             return WARNING, "URL does not use HTTPS."
        
        # Simple certificate validation (timeout to prevent hanging)
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # If no domain (e.g. just a path), skip
            if not domain:
                 return WARNING, "Invalid URL format for SSL check."
                 
            # Attempt a quick valid connection
            requests.get(url, timeout=3, verify=True)
            return SAFE, "Valid HTTPS certificate."
        except requests.exceptions.SSLError:
            return PHISHING, "Invalid or Untrusted SSL Certificate."
        except Exception:
            # Other connection errors (timeout, DNS) - treat as warning for availability but not necessarily phishing
            return WARNING, "Could not verify SSL certificate (Connection failed)."

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

