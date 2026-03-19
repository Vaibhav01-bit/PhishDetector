"""
Enhanced Email Utilities
Functions for email parsing, URL extraction, and header analysis.
"""

import re
import base64
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, unquote


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extracts all URLs from a text string.
    Returns a list of unique URLs.

    Args:
        text: The text to search for URLs

    Returns:
        List of unique URLs found in the text
    """
    if not text:
        return []

    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

    urls = re.findall(url_pattern, text)

    unique_urls = []
    seen = set()

    for url in urls:
        url = url.strip()

        if url.lower() not in seen:
            seen.add(url.lower())

            clean_url = url
            if not clean_url.startswith(("http://", "https://")):
                clean_url = "https://" + clean_url

            try:
                parsed = urlparse(clean_url)
                if parsed.netloc:
                    unique_urls.append(clean_url)
            except:
                continue

    return unique_urls


def extract_email_headers(raw_email: str) -> Dict[str, str]:
    """
    Extract email headers from raw email text.

    Args:
        raw_email: Raw email text including headers

    Returns:
        Dictionary of header name -> value pairs
    """
    headers = {}

    if not raw_email:
        return headers

    lines = raw_email.split("\n")

    for line in lines:
        line = line.strip()

        if not line:
            break

        if ":" not in line:
            continue

        try:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if key and value:
                if key in headers:
                    if isinstance(headers[key], list):
                        headers[key].append(value)
                    else:
                        headers[key] = [headers[key], value]
                else:
                    headers[key] = value

        except ValueError:
            continue

    return headers


def extract_sender_info(from_field: str) -> Dict[str, str]:
    """
    Parse sender information from From header.

    Args:
        from_field: The From header value

    Returns:
        Dictionary with 'email', 'domain', and 'display_name'
    """
    result = {"email": "", "domain": "", "display_name": ""}

    if not from_field:
        return result

    email_match = re.search(r"<([^>]+)>", from_field)
    if email_match:
        result["email"] = email_match.group(1).strip()
        result["display_name"] = from_field[: email_match.start()].strip().strip('"')
    else:
        from_field = from_field.strip()
        if "@" in from_field:
            result["email"] = from_field

    if "@" in result["email"]:
        result["domain"] = result["email"].split("@")[1].lower()

    return result


def extract_base64_attachments(body: str) -> List[Dict[str, str]]:
    """
    Extract base64-encoded attachments from email body.

    Args:
        body: Email body text

    Returns:
        List of attachment dictionaries with 'name', 'type', 'data'
    """
    attachments = []

    b64_pattern = r'Content-Type:\s*[^;]+;\s*name="([^"]+)"[^>]*Content-Transfer-Encoding:\s*base64[^>]*\n\n([A-Za-z0-9+\/\s=]+)'
    matches = re.findall(b64_pattern, body, re.IGNORECASE | re.DOTALL)

    for name, data in matches:
        attachments.append(
            {
                "name": name.strip(),
                "type": "inline_base64",
                "data": data.replace(" ", "").replace("\n", ""),
            }
        )

    return attachments


def decode_base64_attachment(encoded_data: str) -> bytes:
    """
    Decode base64-encoded attachment data.

    Args:
        encoded_data: Base64-encoded string

    Returns:
        Decoded bytes
    """
    try:
        clean_data = encoded_data.replace(" ", "").replace("\n", "").replace("\r", "")
        return base64.b64decode(clean_data)
    except Exception:
        return b""


def extract_visible_links(html_content: str) -> List[Tuple[str, str]]:
    """
    Extract visible link text and URLs from HTML content.

    Args:
        html_content: HTML content to parse

    Returns:
        List of (url, visible_text) tuples
    """
    links = []

    html_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(html_pattern, html_content, re.IGNORECASE | re.DOTALL)

    for url, text in matches:
        links.append((url.strip(), text.strip()))

    return links


def parse_authentication_results(header_value: str) -> Dict[str, Dict[str, str]]:
    """
    Parse authentication-results header value.

    Args:
        header_value: The authentication-results header value

    Returns:
        Dictionary with SPF, DKIM, DMARC status
    """
    result = {
        "spf": {"status": "unknown", "detail": ""},
        "dkim": {"status": "unknown", "detail": ""},
        "dmarc": {"status": "unknown", "detail": ""},
    }

    if not header_value:
        return result

    header_lower = header_value.lower()

    for check in ["spf", "dkim", "dmarc"]:
        pattern = rf"{check}=(\w+)"
        match = re.search(pattern, header_lower)
        if match:
            status = match.group(1)
            if status == "pass":
                result[check] = {
                    "status": "pass",
                    "detail": f"{check.upper()} check passed",
                }
            elif status == "fail":
                result[check] = {
                    "status": "fail",
                    "detail": f"{check.upper()} check failed",
                }
            else:
                result[check] = {
                    "status": status,
                    "detail": f"{check.upper()} check: {status}",
                }

    return result


def expand_shortened_url(url: str, timeout: int = 5) -> Optional[str]:
    """
    Expand shortened URLs by following redirects.

    Args:
        url: The potentially shortened URL
        timeout: Request timeout in seconds

    Returns:
        Expanded URL or original if not shortened
    """
    import requests

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "tiny.cc",
        "shorturl.at",
        "cutt.ly",
        "rb.gy",
        "short.link",
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")

        if domain in shorteners or "redirect" in url:
            response = requests.head(url, allow_redirects=True, timeout=timeout)
            if response.url and response.url != url:
                return response.url
    except:
        pass

    return url


def sanitize_url(url: str) -> str:
    """
    Sanitize and normalize a URL.

    Args:
        url: The URL to sanitize

    Returns:
        Sanitized URL
    """
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path

        if "://" not in netloc:
            netloc = "://" + netloc

        normalized = f"{scheme}{netloc}"
        if parsed.path:
            normalized += parsed.path
        if parsed.params:
            normalized += ";" + parsed.params
        if parsed.query:
            normalized += "?" + parsed.query
        if parsed.fragment:
            normalized += "#" + parsed.fragment

        return normalized
    except:
        return url


def extract_domain(url: str) -> str:
    """
    Extract domain from URL.

    Args:
        url: The URL to parse

    Returns:
        Domain name
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return ""


def is_trusted_domain(domain: str, trusted_domains: set = None) -> bool:
    """
    Check if a domain is in the trusted list.

    Args:
        domain: Domain to check
        trusted_domains: Set of trusted domains (optional)

    Returns:
        True if domain is trusted
    """
    if trusted_domains is None:
        trusted_domains = {
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "facebook.com",
            "github.com",
            "linkedin.com",
            "twitter.com",
            "youtube.com",
            "instagram.com",
            "paypal.com",
            "netflix.com",
        }

    domain = domain.lower().strip()

    if domain in trusted_domains:
        return True

    for trusted in trusted_domains:
        if domain.endswith("." + trusted):
            return True

    return False


def clean_email_body(body: str) -> str:
    """
    Clean email body by removing HTML tags and normalizing whitespace.

    Args:
        body: Raw email body

    Returns:
        Cleaned body text
    """
    if not body:
        return ""

    clean = re.sub(r"<[^>]+>", " ", body)
    clean = re.sub(r"http[s]?://\S+", " [URL] ", clean)
    clean = re.sub(r"\s+", " ", clean)
    clean = clean.strip()

    return clean


def detect_email_type(body: str) -> str:
    """
    Detect if email is HTML or plain text.

    Args:
        body: Email body

    Returns:
        'html', 'text', or 'mixed'
    """
    if not body:
        return "text"

    html_tags = re.findall(r"<[a-z]+[^>]*>", body, re.IGNORECASE)

    if len(html_tags) > 5:
        if "<html" in body.lower() or "<body" in body.lower():
            return "html"
        if len(html_tags) > len(body) / 100:
            return "html"

    return "text"


def extract_subject(raw_email: str) -> str:
    """
    Extract subject line from raw email.

    Args:
        raw_email: Raw email text

    Returns:
        Subject line or empty string
    """
    for line in raw_email.split("\n"):
        line = line.strip()
        if line.lower().startswith("subject:"):
            return line[8:].strip()
    return ""
