"""
Sandbox Utility Functions
Provides helper functions for URL validation, IP checking, and behavioral analysis.
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from PIL import Image
import os


def is_private_ip(ip_str):
    """
    Check if an IP address is private/internal.
    Blocks: localhost, private ranges, link-local, multicast
    
    Args:
        ip_str (str): IP address string
        
    Returns:
        bool: True if IP is private/internal
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check for private ranges
        if ip.is_private:
            return True
            
        # Check for localhost
        if ip.is_loopback:
            return True
            
        # Check for link-local (169.254.x.x)
        if ip.is_link_local:
            return True
            
        # Check for multicast
        if ip.is_multicast:
            return True
            
        return False
        
    except ValueError:
        # Invalid IP format
        return True  # Treat invalid IPs as unsafe


def normalize_url(url):
    """
    Normalize URL for consistent processing.
    - Convert to lowercase
    - Strip trailing slashes
    - Ensure scheme exists
    
    Args:
        url (str): Raw URL
        
    Returns:
        str: Normalized URL
    """
    url = url.strip().lower()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Remove trailing slash
    if url.endswith('/'):
        url = url[:-1]
    
    return url


def validate_url_format(url):
    """
    Validate URL format and scheme.
    
    Args:
        url (str): URL to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    # Check scheme
    if not url.startswith(('http://', 'https://')):
        return False, "Invalid scheme. Only http:// and https:// are allowed."
    
    # Parse URL
    try:
        parsed = urlparse(url)
        
        # Check if domain exists
        if not parsed.netloc:
            return False, "No domain found in URL."
        
        # Check for suspicious patterns
        if '@' in parsed.netloc:
            return False, "URL contains '@' symbol in domain (potential obfuscation)."
        
        return True, "URL format valid"
        
    except Exception as e:
        return False, f"URL parsing failed: {str(e)}"


def resolve_domain_ip(domain):
    """
    Safely resolve domain to IP address.
    
    Args:
        domain (str): Domain name
        
    Returns:
        tuple: (ip_address, error_message)
    """
    try:
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Resolve DNS
        ip = socket.gethostbyname(domain)
        
        # Check if IP is private
        if is_private_ip(ip):
            return None, f"Domain resolves to private IP: {ip}"
        
        return ip, None
        
    except socket.gaierror:
        return None, "Domain resolution failed (DNS error)"
    except Exception as e:
        return None, f"IP resolution error: {str(e)}"


def is_localhost_domain(domain):
    """
    Check if domain is localhost or local reference.
    
    Args:
        domain (str): Domain name
        
    Returns:
        bool: True if localhost
    """
    localhost_patterns = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
        'local',
        '.local'
    ]
    
    domain_lower = domain.lower()
    
    for pattern in localhost_patterns:
        if domain_lower == pattern or domain_lower.endswith(pattern):
            return True
    
    return False


def optimize_screenshot(image_path, max_width=1200, quality=85):
    """
    Optimize screenshot for web display.
    Resize if too large and compress.
    
    Args:
        image_path (str): Path to screenshot
        max_width (int): Maximum width in pixels
        quality (int): JPEG quality (1-100)
        
    Returns:
        bool: True if successful
    """
    try:
        with Image.open(image_path) as img:
            # Get original dimensions
            width, height = img.size
            
            # Resize if too wide
            if width > max_width:
                ratio = max_width / width
                new_height = int(height * ratio)
                img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
            
            # Convert to RGB if needed (for JPEG)
            if img.mode in ('RGBA', 'P'):
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                img = rgb_img
            
            # Save optimized
            img.save(image_path, 'JPEG', quality=quality, optimize=True)
            
        return True
        
    except Exception as e:
        print(f"Screenshot optimization failed: {e}")
        return False


def detect_suspicious_keywords(text):
    """
    Scan text for suspicious phishing keywords.
    
    Args:
        text (str): Page text content
        
    Returns:
        list: Found suspicious keywords
    """
    keywords = [
        'verify your account',
        'account suspended',
        'urgent action required',
        'confirm your identity',
        'security alert',
        'update your information',
        'billing problem',
        'payment failed',
        'expire',
        'click here immediately',
        'act now',
        'limited time',
        'verify now',
        'unusual activity',
        'locked account',
        'reset password',
        'confirm payment'
    ]
    
    text_lower = text.lower()
    found = []
    
    for keyword in keywords:
        if keyword in text_lower:
            found.append(keyword)
    
    return found[:5]  # Limit to top 5


def extract_domain_from_url(url):
    """
    Extract clean domain from URL.
    
    Args:
        url (str): Full URL
        
    Returns:
        str: Domain name
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain.lower()
        
    except:
        return url


def generate_scan_id():
    """
    Generate unique scan ID for screenshot storage.
    
    Returns:
        str: Unique scan ID
    """
    import uuid
    import time
    
    timestamp = int(time.time())
    unique_id = str(uuid.uuid4())[:8]
    
    return f"scan_{timestamp}_{unique_id}"


def ensure_directory_exists(directory_path):
    """
    Create directory if it doesn't exist.
    
    Args:
        directory_path (str): Directory path
        
    Returns:
        bool: True if directory exists or was created
    """
    try:
        os.makedirs(directory_path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Failed to create directory {directory_path}: {e}")
        return False


def cleanup_old_screenshots(directory_path, max_age_days=7):
    """
    Remove screenshots older than specified days.
    
    Args:
        directory_path (str): Screenshot directory
        max_age_days (int): Maximum age in days
        
    Returns:
        int: Number of files deleted
    """
    import time
    
    if not os.path.exists(directory_path):
        return 0
    
    deleted_count = 0
    current_time = time.time()
    max_age_seconds = max_age_days * 24 * 60 * 60
    
    try:
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            
            # Check if file
            if os.path.isfile(filepath):
                # Get file age
                file_age = current_time - os.path.getmtime(filepath)
                
                # Delete if too old
                if file_age > max_age_seconds:
                    os.remove(filepath)
                    deleted_count += 1
        
        return deleted_count
        
    except Exception as e:
        print(f"Cleanup failed: {e}")
        return deleted_count
