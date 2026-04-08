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
        'receive',
        'suspended', 'locked', 'expire', 'expired',
        'urgent', 'action', 'required', 'alert'
    ]

    SUSPICIOUS_PATH_KEYWORDS = {
        'login', 'verify', 'secure', 'receive', 'payment', 'billing',
        'account', 'reset', 'wallet', 'confirm'
    }

    FREE_HOSTING_DOMAINS = {
        'wixstudio.com',
        'wixsite.com',
        'netlify.app',
        'vercel.app',
        'github.io',
        'pages.dev',
    }

    COMMON_SECOND_LEVEL_SUFFIXES = {
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
        'co.in', 'firm.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
        'com.au', 'net.au', 'org.au',
        'co.nz', 'org.nz',
        'co.jp', 'ne.jp', 'or.jp',
        'co.kr', 'or.kr',
        'com.br', 'com.mx', 'com.tr', 'com.cn', 'com.hk', 'com.sg',
        'com.my', 'com.tw', 'com.vn', 'com.sa', 'com.ar', 'com.ph',
        'co.za', 'co.il',
    }
    
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
        self.brand_keys_set = set(self.brands.keys())
        self.brand_identifier_map = self._build_brand_identifier_map()
        self.brand_keys_list = sorted(self.brand_identifier_map.keys(), key=len, reverse=True)
    
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

    def _build_brand_identifier_map(self):
        """Map brand aliases and abbreviations back to their canonical brand key."""
        identifiers = {}
        for brand_key, brand_data in self.brands.items():
            identifiers[brand_key] = brand_key
            for alias in brand_data.get('aliases', []):
                alias_norm = str(alias).lower().strip()
                if alias_norm:
                    identifiers[alias_norm] = brand_key
        return identifiers

    def _normalize_domain(self, domain):
        domain = str(domain or '').lower().strip()
        if ':' in domain:
            domain = domain.split(':', 1)[0]
        domain = domain.strip('.')
        try:
            domain = domain.encode('ascii').decode('idna')
        except Exception:
            pass
        return domain

    def _extract_registrable_domain(self, domain):
        """Extract the registrable/root domain and ignore untrusted subdomains."""
        domain = self._normalize_domain(domain)
        parts = [part for part in domain.split('.') if part]
        if len(parts) <= 2:
            return '.'.join(parts)

        public_suffix = '.'.join(parts[-2:])
        if public_suffix in self.COMMON_SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def _extract_root_label(self, registrable_domain):
        if not registrable_domain:
            return ''
        return registrable_domain.split('.')[0]

    def _get_official_root_domains(self, brand_key):
        official_domains = self.brands.get(brand_key, {}).get('official_domains', [])
        return {
            self._extract_registrable_domain(domain)
            for domain in official_domains
            if domain
        }
    
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
        parsed_url = urlparse(url)

        if domain is None:
            domain = parsed_url.netloc or url

        domain = self._normalize_domain(domain)
        domain_without_www = domain[4:] if domain.startswith('www.') else domain

        if self._is_official_domain(domain_without_www):
            return {
                'is_impersonation': False,
                'risk_score': 0,
                'matched_brand': None,
                'message': 'Official brand domain',
                'reasons': [],
                'details': {}
            }

        registrable_domain = self._extract_registrable_domain(domain_without_www)
        subdomain = self._extract_subdomain(domain_without_www)
        root_label = self._extract_root_label(registrable_domain)
        subdomain_tokens = self._tokenize_component(subdomain)
        root_domain_tokens = self._tokenize_component(root_label)
        path_tokens = self._extract_path_tokens(parsed_url.path)
        domain_tokens = self._extract_domain_tokens(domain_without_www)

        brand_match = self._check_brand_presence(
            root_domain_tokens,
            path_tokens,
            subdomain,
            registrable_domain,
        )

        if not brand_match:
            return {
                'is_impersonation': False,
                'risk_score': 0,
                'matched_brand': None,
                'message': 'No brand impersonation detected',
                'reasons': [],
                'details': {}
            }

        matched_brand = brand_match['brand']
        brand_location = brand_match['location']
        match_type = brand_match.get('match_type', 'exact')
        matched_identifier = brand_match.get('identifier', matched_brand)
        official_root_domains = self._get_official_root_domains(matched_brand)
        main_domain_matches = registrable_domain in official_root_domains
        free_hosting = registrable_domain in self.FREE_HOSTING_DOMAINS
        suspicious_path_keywords = [
            token for token in path_tokens if token in self.SUSPICIOUS_PATH_KEYWORDS
        ]

        risk_score = 0
        reasons = []
        details = {
            'brand_in_domain': brand_location != 'path',
            'typosquatting_detected': False,
            'intent_keywords': [],
            'homoglyphs_detected': False,
            'suspicious_structure': False,
            'free_hosting': free_hosting,
            'official_domain_mismatch': not main_domain_matches,
            'subdomain_trick': False,
            'lookalike_detected': False,
            'suspicious_path': False,
            'force_phishing': False,
            'brand_location': brand_location,
            'matched_identifier': matched_identifier,
            'main_domain': registrable_domain,
            'subdomain': subdomain,
            'score_breakdown': {},
        }

        def add_score(key, points, reason):
            nonlocal risk_score
            if points <= 0:
                return
            risk_score += points
            details['score_breakdown'][key] = details['score_breakdown'].get(key, 0) + points
            reasons.append(reason)

        if brand_location.startswith('subdomain'):
            details['subdomain_trick'] = True
            add_score(
                'brand_in_subdomain',
                40,
                f"Brand '{matched_brand}' detected in untrusted subdomain '{subdomain}'",
            )
        elif brand_location == 'path':
            add_score(
                'brand_in_path',
                5,
                f"Brand keyword '{matched_brand}' referenced in URL path",
            )
        elif match_type in {'exact', 'alias'}:
            add_score(
                'brand_in_domain',
                30,
                f"Brand keyword '{matched_identifier}' detected in domain",
            )
        else:
            add_score(
                'brand_reference',
                15,
                f"Brand-like token '{matched_identifier}' detected in domain",
            )

        if not main_domain_matches and brand_location != 'path':
            add_score(
                'official_domain_mismatch',
                15,
                f"Main domain '{registrable_domain}' is not an official domain for {matched_brand}",
            )

        typo_score, typo_details = self._calculate_typosquatting_score(
            registrable_domain, matched_brand
        )
        if typo_score > 0:
            add_score('typosquatting', typo_score, f"Lookalike domain detected: {typo_details}")
            details['typosquatting_detected'] = True
            details['lookalike_detected'] = True

        homoglyph_targets = [registrable_domain] + subdomain_tokens
        for candidate in homoglyph_targets:
            if self._detect_homoglyphs(candidate, matched_brand):
                add_score('homoglyph', 30, "Homoglyph or numeric substitution detected")
                details['homoglyphs_detected'] = True
                details['lookalike_detected'] = True
                break

        if match_type in {'alias', 'alias_substring', 'homoglyph', 'repeated_chars'}:
            add_score(
                'lookalike_identifier',
                30,
                f"Lookalike brand pattern '{matched_identifier}' detected",
            )
            details['lookalike_detected'] = True

        intent_keywords = self._check_intent_keywords(domain_tokens, path_tokens)
        if intent_keywords:
            add_score(
                'intent_keywords',
                20,
                f"Phishing intent keywords detected: {', '.join(intent_keywords)}",
            )
            details['intent_keywords'] = intent_keywords

        if suspicious_path_keywords:
            add_score(
                'suspicious_path',
                20,
                f"Suspicious path detected: {', '.join(suspicious_path_keywords[:3])}",
            )
            details['suspicious_path'] = True

        if free_hosting and brand_location != 'path':
            add_score(
                'free_hosting',
                30,
                f"Hosted on free/shared platform '{registrable_domain}' with brand-like subdomain",
            )

        if self._has_suspicious_structure(domain_without_www, matched_brand):
            add_score(
                'suspicious_structure',
                10,
                "Suspicious domain structure (excessive hyphens or misleading placement)",
            )
            details['suspicious_structure'] = True

        force_phishing = False
        if details['subdomain_trick'] and not main_domain_matches:
            force_phishing = True
        elif details['lookalike_detected'] and not main_domain_matches:
            force_phishing = True
        elif (
            not main_domain_matches
            and brand_location != 'path'
            and (
                details['suspicious_path']
                or details['suspicious_structure']
                or free_hosting
                or match_type in {'exact', 'alias'}
            )
        ):
            force_phishing = True

        details['force_phishing'] = force_phishing
        is_impersonation = force_phishing or risk_score >= 60

        brand_name = self.brands[matched_brand].get('name', matched_brand.title())
        if is_impersonation:
            message = f"{brand_name} impersonation detected (Risk Score: {risk_score})"
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
                if domain == official_domain:
                    return True
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
        """Extract the untrusted subdomain portion before the registrable domain."""
        registrable_domain = self._extract_registrable_domain(domain)
        if not registrable_domain or domain == registrable_domain:
            return ''
        suffix = '.' + registrable_domain
        if domain.endswith(suffix):
            return domain[: -len(suffix)]
        return ''

    def _tokenize_component(self, value):
        if not value:
            return []
        return [token.lower() for token in re.split(r'[.\-_]', value) if token]

    def _resolve_brand_identifier(self, token):
        token = token.lower().strip()
        return self.brand_identifier_map.get(token)

    def _check_brand_presence(self, root_domain_tokens, path_tokens, subdomain, registrable_domain):
        """
        Check if any brand keyword appears in domain tokens, subdomain, or path.
        Returns dict with brand key and location if found, None otherwise.
        """
        sub_tokens = self._tokenize_component(subdomain)
        root_label = self._extract_root_label(registrable_domain)

        for token in sub_tokens:
            brand_key = self._resolve_brand_identifier(token)
            if brand_key:
                return {'brand': brand_key, 'location': 'subdomain', 'match_type': 'exact', 'identifier': token}

        for token in root_domain_tokens:
            brand_key = self._resolve_brand_identifier(token)
            if brand_key:
                return {'brand': brand_key, 'location': 'domain', 'match_type': 'exact', 'identifier': token}

        for token in path_tokens:
            brand_key = self._resolve_brand_identifier(token)
            if brand_key:
                return {'brand': brand_key, 'location': 'path', 'match_type': 'exact', 'identifier': token}

        for token in sub_tokens + [subdomain] + root_domain_tokens + [root_label]:
            token = token.lower().strip()
            if not token:
                continue

            for identifier in self.brand_keys_list:
                if len(identifier) < 4:
                    continue
                brand_key = self.brand_identifier_map[identifier]

                if identifier in token:
                    location = 'subdomain (substring)' if token in sub_tokens or token == subdomain else 'domain (substring)'
                    match_type = 'alias_substring' if identifier != brand_key else 'substring'
                    length_gap = len(token) - len(identifier)
                    if identifier == brand_key and length_gap > 4:
                        continue
                    if identifier != brand_key and length_gap > 12:
                        continue
                    return {
                        'brand': brand_key,
                        'location': location,
                        'match_type': match_type,
                        'identifier': identifier,
                    }

                if self._has_repeated_chars_heuristic(token) and self._has_repeated_chars(token, identifier):
                    location = 'subdomain' if token in sub_tokens or token == subdomain else 'domain'
                    return {
                        'brand': brand_key,
                        'location': location,
                        'match_type': 'repeated_chars',
                        'identifier': identifier,
                    }

                if abs(len(token) - len(identifier)) <= 1 and any(c.isdigit() for c in token):
                    for number, letters in self.HOMOGLYPH_PATTERNS.items():
                        if number not in token:
                            continue
                        for letter in letters:
                            if token.replace(number, letter) == identifier:
                                location = 'subdomain' if token in sub_tokens or token == subdomain else 'domain'
                                return {
                                    'brand': brand_key,
                                    'location': location,
                                    'match_type': 'homoglyph',
                                    'identifier': identifier,
                                }

        return None
    
    def _calculate_typosquatting_score(self, domain, brand_key):
        """
        Calculate typosquatting score using Levenshtein distance.
        Returns (score, details_string).
        """
        # Get official domains for this brand
        official_domains = list(self._get_official_root_domains(brand_key))
        
        min_distance = float('inf')
        closest_domain = None
        
        for official_domain in official_domains:
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
