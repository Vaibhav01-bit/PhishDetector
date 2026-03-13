import re

def extract_urls_from_text(text):
    """
    Extracts all URLs from a text string.
    Returns a list of unique URLs.
    """
    # Regex pattern for finding URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    
    urls = re.findall(url_pattern, text)
    
    # Clean and deduplicate
    unique_urls = list(set([url.strip() for url in urls]))
    
    return unique_urls
