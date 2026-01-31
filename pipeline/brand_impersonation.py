"""
Brand Impersonation Detection Module
Detects phishing URLs that impersonate well-known brands using:
- Typosquatting (spelling variations)
- Homoglyphs (character substitutions)
- Intent keywords (login, verify, etc.)
- Domain structure analysis
"""

import json
import os
import re
from urllib.parse import urlparse


class BrandImpersonationDetector:
    """
    Detects brand impersonation attempts in URLs without using external APIs.
    Uses a local brand registry and multiple detection algorithms.
    """
    
    # Intent keywords commonly used in phishing URLs
    INTENT_KEYWORDS = [
        'login', 'signin', 'sign-in', 'authenticate', 'auth',
        'verify', 'verification', 'validate', 'validation',
        'update', 'reset', 'recover', 'recovery',
        'confirm', 'confirmation', 'secure', 'security',
        'account', 'billing', 'payment', 'wallet',
        'suspended', 'locked', 'expire', 'expired',
        'urgent', 'action', 'required', 'alert'
    ]
    
    # Homoglyph substitution patterns (number -> letter)
    HOMOGLYPH_PATTERNS = {
        '0': 'o',
        '1': 'il',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b'
    }
    
    def __init__(self, registry_path=None):
        """
        Initialize the brand impersonation detector.
        
        Args:
            registry_path: Path to brand_registry.json (optional)
        """
        if registry_path is None:
            # Default to same directory as this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            registry_path = os.path.join(current_dir, 'brand_registry.json')
        
        self.registry_path = registry_path
        self.brands = self._load_brand_registry()
    
    def _load_brand_registry(self):
        """Load brand registry from JSON file."""
        try:
            with open(self.registry_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('brands', {})
        except FileNotFoundError:
            print(f"Warning: Brand registry not found at {self.registry_path}")
            return {}
        except json.JSONDecodeError:
            print(f"Warning: Invalid JSON in brand registry at {self.registry_path}")
            return {}
    
    def check(self, url, domain=None):
        """
        Main entry point for brand impersonation detection.
        
        Args:
            url: Full URL to check
            domain: Pre-parsed domain (optional, will be extracted if not provided)
        
        Returns:
            dict: Detection result with structure:
            {
                'is_impersonation': bool,
                'risk_score': int,
                'matched_brand': str or None,
                'message': str,
                'reasons': list,
                'details': dict
            }
        """
        # Parse URL if domain not provided
        if domain is None:
            parsed = urlparse(url)
            domain = parsed.netloc or url
        
        # Normalize domain
        domain = domain.lower().strip()
        
        # Remove www. prefix for analysis
        domain_without_www = domain[4:] if domain.startswith('www.') else domain
        
        # Step 1: Check if this is an exact match with official domain (SAFE)
        if self._is_official_domain(domain_without_www):
            return {
                'is_impersonation': False,
                'risk_score': 0,
                'matched_brand': None,
                'message': 'Official brand domain',
                'reasons': [],
                'details': {}
            }
        
        # Step 2: Extract domain components for analysis
        parsed_url = urlparse(url)
        domain_tokens = self._extract_domain_tokens(domain_without_www)
        path_tokens = self._extract_path_tokens(parsed_url.path)
        subdomain = self._extract_subdomain(domain_without_www)
        
        # Step 3: Check for brand keyword presence
        brand_match = self._check_brand_presence(domain_tokens, path_tokens, subdomain)
        
        if not brand_match:
            # No brand detected, not an impersonation attempt
            return {
                'is_impersonation': False,
                'risk_score': 0,
                'matched_brand': None,
                'message': 'No brand impersonation detected',
                'reasons': [],
                'details': {}
            }
        
        # Brand keyword found but domain is not official - potential impersonation
        matched_brand = brand_match['brand']
        brand_location = brand_match['location']
        
        # Initialize scoring
        risk_score = 0
        reasons = []
        details = {
            'brand_in_domain': False,
            'typosquatting_detected': False,
            'intent_keywords': [],
            'homoglyphs_detected': False,
            'suspicious_structure': False
        }
        
        # Step 4: Brand keyword detected (base score)
        risk_score += 30
        reasons.append(f"Brand keyword '{matched_brand}' detected in {brand_location}")
        details['brand_in_domain'] = True
        
        # Step 5: Check for typosquatting (spelling similarity)
        typo_score, typo_details = self._calculate_typosquatting_score(
            domain_without_www, matched_brand
        )
        if typo_score > 0:
            risk_score += typo_score
            reasons.append(f"Typosquatting detected: {typo_details}")
            details['typosquatting_detected'] = True
        
        # Step 6: Check for homoglyphs and numeric substitutions
        homoglyph_detected = self._detect_homoglyphs(domain_without_www, matched_brand)
        if homoglyph_detected:
            risk_score += 15
            reasons.append("Homoglyph or numeric substitution detected")
            details['homoglyphs_detected'] = True
        
        # Step 7: Check for intent keywords
        intent_keywords = self._check_intent_keywords(domain_tokens, path_tokens)
        if intent_keywords:
            risk_score += 20
            reasons.append(f"Phishing intent keywords detected: {', '.join(intent_keywords)}")
            details['intent_keywords'] = intent_keywords
        
        # Step 8: Check for suspicious domain structure
        if self._has_suspicious_structure(domain_without_www, matched_brand):
            risk_score += 10
            reasons.append("Suspicious domain structure (excessive hyphens or subdomains)")
            details['suspicious_structure'] = True
        
        # Step 9: Determine if this is impersonation based on threshold
        is_impersonation = risk_score >= 50
        
        # Generate user-friendly message
        if is_impersonation:
            brand_name = self.brands[matched_brand]['name']
            message = f"Possible {brand_name} impersonation detected (Risk Score: {risk_score})"
        else:
            message = f"Low risk brand reference detected (Score: {risk_score})"
        
        return {
            'is_impersonation': is_impersonation,
            'risk_score': risk_score,
            'matched_brand': matched_brand,
            'message': message,
            'reasons': reasons,
            'details': details
        }
    
    def _is_official_domain(self, domain):
        """
        Check if domain exactly matches an official brand domain.
        This includes subdomain checks (e.g., accounts.google.com is valid).
        """
        for brand_key, brand_data in self.brands.items():
            for official_domain in brand_data['official_domains']:
                # Exact match
                if domain == official_domain:
                    return True
                # Subdomain match (e.g., auth.paypal.com)
                if domain.endswith('.' + official_domain):
                    return True
        return False
    
    def _extract_domain_tokens(self, domain):
        """
        Extract tokens from domain by splitting on dots and hyphens.
        Example: paypal-login.com -> ['paypal', 'login', 'com']
        """
        # Split by dots and hyphens
        tokens = re.split(r'[.\-]', domain)
        # Filter out empty strings and common TLDs
        common_tlds = {'com', 'net', 'org', 'co', 'uk', 'io', 'app', 'dev'}
        tokens = [t.lower() for t in tokens if t and t.lower() not in common_tlds]
        return tokens
    
    def _extract_path_tokens(self, path):
        """Extract meaningful tokens from URL path."""
        if not path or path == '/':
            return []
        # Split by slashes and hyphens
        tokens = re.split(r'[/\-_]', path)
        # Filter out empty strings and common extensions
        tokens = [t.lower() for t in tokens if t and not t.startswith('.')]
        return tokens
    
    def _extract_subdomain(self, domain):
        """Extract subdomain portion (everything before the root domain)."""
        parts = domain.split('.')
        if len(parts) > 2:
            # Return everything except the last two parts (root domain + TLD)
            return '.'.join(parts[:-2])
        return ''
    
    def _check_brand_presence(self, domain_tokens, path_tokens, subdomain):
        """
        Check if any brand keyword appears in domain tokens, subdomain, or path.
        Returns dict with brand key and location if found, None otherwise.
        """
        all_tokens = domain_tokens + path_tokens
        
        for brand_key in self.brands.keys():
            # Check in domain tokens
            if brand_key in domain_tokens:
                return {'brand': brand_key, 'location': 'domain'}
            
            # Check in subdomain
            if brand_key in subdomain:
                return {'brand': brand_key, 'location': 'subdomain'}
            
            # Check in path tokens
            if brand_key in path_tokens:
                return {'brand': brand_key, 'location': 'path'}
            
            # Check for brand keyword as substring in any token
            for token in all_tokens:
                if brand_key in token and len(token) - len(brand_key) <= 2:
                    # Allow small variations (e.g., 'paypal' in 'paypals')
                    return {'brand': brand_key, 'location': 'domain (substring)'}
        
        return None
    
    def _calculate_typosquatting_score(self, domain, brand_key):
        """
        Calculate typosquatting score using Levenshtein distance.
        Returns (score, details_string).
        """
        # Get official domains for this brand
        official_domains = self.brands[brand_key]['official_domains']
        
        min_distance = float('inf')
        closest_domain = None
        
        for official_domain in official_domains:
            distance = self._levenshtein_distance(domain, official_domain)
            if distance < min_distance:
                min_distance = distance
                closest_domain = official_domain
        
        # Score based on similarity
        # Distance of 1-2 characters is highly suspicious
        if 1 <= min_distance <= 2:
            return 25, f"Very similar to {closest_domain} (distance: {min_distance})"
        elif 3 <= min_distance <= 4:
            return 15, f"Similar to {closest_domain} (distance: {min_distance})"
        
        return 0, ""
    
    def _levenshtein_distance(self, s1, s2):
        """
        Calculate Levenshtein distance between two strings.
        This is a lightweight implementation without external dependencies.
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Cost of insertions, deletions, or substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _detect_homoglyphs(self, domain, brand_key):
        """
        Detect homoglyph and numeric substitution patterns.
        Examples: 0->o, 1->l, paypal->paypa1
        """
        # Check if domain contains numbers
        if not any(char.isdigit() for char in domain):
            return False
        
        # Check for common substitution patterns
        for number, letters in self.HOMOGLYPH_PATTERNS.items():
            if number in domain:
                # Check if replacing the number with possible letters creates brand name
                for letter in letters:
                    test_domain = domain.replace(number, letter)
                    if brand_key in test_domain:
                        return True
        
        # Check for repeated characters (e.g., youtube -> youtubee)
        official_domains = self.brands[brand_key]['official_domains']
        for official_domain in official_domains:
            # Remove TLD for comparison
            official_root = official_domain.split('.')[0]
            domain_root = domain.split('.')[0]
            
            # Check if domain has repeated characters compared to official
            if self._has_repeated_chars(domain_root, official_root):
                return True
        
        return False
    
    def _has_repeated_chars(self, test_str, reference_str):
        """Check if test_str has repeated characters compared to reference."""
        # Simple check: if test_str is longer and contains reference as substring
        if len(test_str) > len(reference_str) and reference_str in test_str:
            # Check if the extra characters are repetitions
            extra_chars = len(test_str) - len(reference_str)
            if extra_chars <= 2:  # Allow up to 2 extra characters
                return True
        return False
    
    def _check_intent_keywords(self, domain_tokens, path_tokens):
        """
        Check for phishing intent keywords in domain or path.
        Returns list of detected keywords.
        """
        all_tokens = domain_tokens + path_tokens
        detected = []
        
        for keyword in self.INTENT_KEYWORDS:
            if keyword in all_tokens:
                detected.append(keyword)
        
        return detected
    
    def _has_suspicious_structure(self, domain, brand_key):
        """
        Check for suspicious domain structure patterns.
        - Excessive hyphens (e.g., pay-pal-login.com)
        - Brand name not in root domain position
        """
        # Count hyphens
        hyphen_count = domain.count('-')
        if hyphen_count >= 2:
            return True
        
        # Check if brand appears with hyphens around it
        if f'-{brand_key}-' in domain or domain.startswith(f'{brand_key}-') or domain.endswith(f'-{brand_key}'):
            return True
        
        return False


# Example usage and testing
if __name__ == "__main__":
    detector = BrandImpersonationDetector()
    
    # Test cases
    test_urls = [
        # Legitimate URLs (should NOT trigger)
        "https://www.youtube.com/watch?v=xyz",
        "https://accounts.google.com/signin",
        "https://www.paypal.com/myaccount",
        
        # Phishing URLs (should trigger)
        "https://youtubee-login.com/verify",
        "https://paypa1-secure.com/reset",
        "https://g00gle-accounts.com/signin",
        "https://paypal-login-secure.com/update",
        "https://youtube-verify.com/account",
        
        # Edge cases
        "https://example.com/youtube/video",  # Brand in path only
        "https://myyoutubechannel.com",  # Contains brand but different context
    ]
    
    print("Brand Impersonation Detection Test Results")
    print("=" * 80)
    
    for url in test_urls:
        result = detector.check(url)
        print(f"\nURL: {url}")
        print(f"Impersonation: {result['is_impersonation']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Message: {result['message']}")
        if result['reasons']:
            print(f"Reasons: {', '.join(result['reasons'])}")
        print("-" * 80)
