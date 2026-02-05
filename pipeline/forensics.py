import requests
import socket
import whois
import datetime
from urllib.parse import urlparse

class ForensicAnalyzer:
    def __init__(self):
        self.headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.SHORTENER_DOMAINS = {
            'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'shorte.st',
            'go.gl', 'tr.im', 'ow.ly', 'youtu.be', 'mcaf.ee', 'shorturl.at',
            'bl.ink', 'cutt.ly', 'clck.ru', 'rb.gy'
        }

    def analyze(self, url):
        """
        Perform a deep forensic analysis of the URL.
        """
        normalized_url = self._normalize_url(url)
        redirect_chain, final_url = self._resolve_redirects(normalized_url)
        
        domain = self._extract_domain(final_url)
        ip_address = self._get_ip(domain)
        whois_data = self._get_whois(domain)
        
        return {
            'input_url': url,
            'normalized_url': normalized_url,
            'final_url': final_url,
            'redirect_chain': redirect_chain,
            'redirect_count': len(redirect_chain) - 1 if redirect_chain else 0,
            'is_shortener': domain in self.SHORTENER_DOMAINS,
            'domain': domain,
            'root_domain': self._get_root_domain(domain),
            'ip_address': ip_address,
            'geo_location': "server-dependent", # Placeholder for GeoIP
            'asn': "Unknown", # Placeholder for ASN
            'whois': whois_data,
            'scan_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    def _normalize_url(self, url):
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    def _resolve_redirects(self, url):
        chain = []
        try:
            response = requests.head(url, headers=self.headers, allow_redirects=True, timeout=5)
            # requests.head history contains the redirects
            if response.history:
                for resp in response.history:
                    chain.append({
                        'url': resp.url,
                        'status': resp.status_code
                    })
            # Add final destination
            chain.append({
                'url': response.url,
                'status': response.status_code
            })
            return chain, response.url
        except requests.RequestException:
            # Fallback if request fails
            return [{'url': url, 'status': 'Error'}], url

    def _extract_domain(self, url):
        try:
            return urlparse(url).netloc
        except:
            return url

    def _get_root_domain(self, domain):
        try:
            parts = domain.split('.')
            if len(parts) > 2:
                return '.'.join(parts[-2:])
            return domain
        except:
            return domain

    def _get_ip(self, domain):
        try:
            # Strip port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            return socket.gethostbyname(domain)
        except:
            return "Unknown"

    def _get_whois(self, domain):
        try:
            w = whois.whois(domain)
            
            # Helper to handle list or string dates
            def format_date(date_obj):
                if isinstance(date_obj, list):
                    return date_obj[0].strftime("%Y-%m-%d") if date_obj else "Unknown"
                if isinstance(date_obj, datetime.datetime):
                    return date_obj.strftime("%Y-%m-%d")
                return str(date_obj)

            creation_date = format_date(w.creation_date)
            
            # Calculate Days Active
            days_active = "Unknown"
            if w.creation_date:
                c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(c_date, datetime.datetime):
                    # Make offset-naive for comparison
                    if c_date.tzinfo:
                        c_date = c_date.replace(tzinfo=None)
                    days_active = (datetime.datetime.now() - c_date).days

            return {
                'registrar': w.registrar or "Unknown",
                'creation_date': creation_date,
                'expiration_date': format_date(w.expiration_date),
                'domain_age_days': days_active
            }
        except Exception as e:
            return {
                'registrar': "Unknown",
                'creation_date': "Unknown",
                'expiration_date': "Unknown",
                'domain_age_days': "Unknown",
                'error': str(e)
            }
