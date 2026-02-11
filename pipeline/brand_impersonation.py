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
from functools import lru_cache


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
        # Optimization: Create a set of brand keys for O(1) lookup
        self.brand_keys_set = set(self.brands.keys())
        # Optimization: Create a list of brand keys sorted by length (descending) for robust substring matching
        self.brand_keys_list = sorted(self.brands.keys(), key=len, reverse=True)
    
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
        
        # Convert punycode to unicode if present
        try:
            domain = domain.encode('ascii').decode('idna')
        except:
            pass # Keep original if conversion fails
        
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
        # Optimized: Only run if the domain is not just the brand name (which would be an exact match check)
        if domain_without_www != matched_brand: 
            typo_score, typo_details = self._calculate_typosquatting_score(
                domain_without_www, matched_brand
            )
            if typo_score > 0:
                risk_score += typo_score
                reasons.append(f"Typosquatting detected: {typo_details}")
                details['typosquatting_detected'] = True
        
        # Step 6: Check for homoglyphs and numeric substitutions
        # Optimized: Only check if risk score is already elevated OR if domain contains numbers/suspicious patterns
        # We need to be careful not to skip this if the ONLY sign is the homoglyph itself
        if risk_score >= 15 or any(char.isdigit() for char in domain_without_www) or self._has_repeated_chars_heuristic(domain_without_www):
            homoglyph_detected = self._detect_homoglyphs(domain_without_www, matched_brand)
            if homoglyph_detected:
                risk_score += 30 # Increased score because homoglyphs are strong indicators
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
        # Optimization opportunity: map official domains to brands for O(1) in future
        # For now, iterating is acceptable as official_domains lists are short
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
        # Optimization: Fast check against set for exact token matches
        for token in domain_tokens:
            if token in self.brand_keys_set:
                return {'brand': token, 'location': 'domain'}
        
        if subdomain:
             # Check if subdomain is exactly a brand
             if subdomain in self.brand_keys_set:
                 return {'brand': subdomain, 'location': 'subdomain'}
             
             # Check tokens within subdomain
             sub_tokens = re.split(r'[.\-]', subdomain)
             for token in sub_tokens:
                 if token in self.brand_keys_set:
                     return {'brand': token, 'location': 'subdomain'}

        for token in path_tokens:
            if token in self.brand_keys_set:
                return {'brand': token, 'location': 'path'}
        
        # Optimization: Search for substrings only if no exact match found
        # Use sorted list to match longest brands first (e.g., "facebook" before "face")
        all_tokens = domain_tokens + path_tokens
        if subdomain:
            all_tokens.append(subdomain)
            
        for brand_key in self.brand_keys_list:
            if len(brand_key) < 4: continue # Skip very short brands for substring check to reduce FPs
            
            for token in all_tokens:
                if brand_key in token:
                     # Verify it's a significant match (not just a small part of a larger word)
                     # e.g. "face" in "interface" is filtered out by length check usually, but here we want
                     # to catch "paypal" in "paypalservice"
                     if len(token) - len(brand_key) <= 4:
                        return {'brand': brand_key, 'location': 'domain (substring)'}
                
                # Check for repeated characters (e.g. gooogle)
                if self._has_repeated_chars_heuristic(token):
                    # If token has repeated chars, check if it simplifies to brand_key
                    # This is expensive so we only do it if heuristic passes
                    if self._has_repeated_chars(token, brand_key):
                        return {'brand': brand_key, 'location': 'domain (repeated chars)'}
                
                # Check for homoglyphs in token (e.g. g00gle)
                # Only if token length is similar to brand length
                if abs(len(token) - len(brand_key)) <= 1 and any(c.isdigit() for c in token):
                     # Quick check: replace numbers with likely chars
                     # This is a mini-version of _detect_homoglyphs just for detection
                     for number, letters in self.HOMOGLYPH_PATTERNS.items():
                        if number in token:
                            for letter in letters:
                                if token.replace(number, letter) == brand_key:
                                    return {'brand': brand_key, 'location': 'domain (homoglyph)'}
        
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
            # Optimization: Skip if length difference is already too large
            if abs(len(domain) - len(official_domain)) > 3:
                continue
                
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
    
    @lru_cache(maxsize=1024)
    def _levenshtein_distance(self, s1, s2):
        """
        Calculate Levenshtein distance between two strings.
        This is a lightweight implementation without external dependencies.
        Cached for performance.
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
            
        # Optimization: Limit patterns check
        # Check for common substitution patterns
        if len(domain) > 50: return False # Skip long domains for expensive checks
        
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
    
    def _has_repeated_chars_heuristic(self, domain):
        """Quick check if domain has repeated characters (3+ same chars in a row)."""
        for i in range(len(domain) - 2):
            if domain[i] == domain[i+1] == domain[i+2]:
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
        
        # Enhanced greedy check for interleaved repetitions (e.g. gooogle vs google)
        # This handles cases where the substring check fails (like gooogle vs google where google is NOT a substring of gooogle exactly if we just look for "google")
        # Actually "google" IS a substring of "gooogle" -> NO it is not. "goo" + "ogle".
        
        if len(test_str) <= len(reference_str): return False
        
        i = 0 # test_str index
        j = 0 # reference_str index
        repeats = 0
        
        while i < len(test_str) and j < len(reference_str):
            if test_str[i] == reference_str[j]:
                i += 1
                j += 1
            elif j > 0 and test_str[i] == reference_str[j-1]:
                # Repeated character detected
                i += 1
                repeats += 1
            else:
                return False # Mismatch that isn't a repetition
        
        # Check remaining characters in test_str
        while i < len(test_str):
            if j > 0 and test_str[i] == reference_str[j-1]:
                 i += 1
                 repeats += 1
            else:
                return False
                
        return repeats <= 2 and repeats > 0
    
    def _check_intent_keywords(self, domain_tokens, path_tokens):
        """
        Check for phishing intent keywords in domain or path.
        Returns list of detected keywords.
        """
        all_tokens = domain_tokens + path_tokens
        detected = []
        
        # Optimization: Set lookup intersection would be faster but keywords list is small
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
