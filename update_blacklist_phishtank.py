import os
import json
import logging
import requests
import shutil
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("blacklist_update.log"),
        logging.StreamHandler()
    ]
)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json"
BLACKLIST_FILE = "blacklist.txt"
BACKUP_FILE = "blacklist.txt.bak"
TEMP_FILE = "blacklist.txt.tmp"
USER_AGENT = "phishtank/phishdetector-student-project"

def normalize_domain(url):
    """
    Extracts and normalizes the domain from a URL.
    - Lowercase
    - Strip protocol
    - Remove 'www.'
    - Strip trailing slashes
    """
    try:
        # parsed = urlparse(url) # urlparse can be tricky with partials, but PhishTank gives full URLs
        
        # Simple manual strip for safety if urlparse misses 'http' without scheme
        if not url.startswith(('http://', 'https://')):
             url = 'http://' + url
             
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path # netloc is empty if no scheme provided originally
        
        # Normalize
        domain = domain.lower()
        if domain.startswith("www."):
            domain = domain[4:]
            
        return domain.strip()
    except Exception as e:
        # logging.debug(f"Failed to normalize URL {url}: {e}")
        return None

def update_blacklist():
    logging.info("Starting PhishTank blacklist update...")
    
    try:
        # 1. Download Feed
        headers = {'User-Agent': USER_AGENT}
        logging.info(f"Downloading feed from {PHISHTANK_URL}...")
        response = requests.get(PHISHTANK_URL, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        logging.info(f"Downloaded {len(data)} entries.")
        
        # 2. Extract & Normalize
        unique_domains = set()
        for entry in data:
            url = entry.get('url')
            if url:
                domain = normalize_domain(url)
                if domain:
                    unique_domains.add(domain)
        
        logging.info(f"Extracted {len(unique_domains)} unique domains.")
        
        # 3. Write to Temp File
        with open(TEMP_FILE, 'w') as f:
            for domain in sorted(unique_domains):
                f.write(domain + '\n')
                
        # 4. Backup Existing
        if os.path.exists(BLACKLIST_FILE):
            shutil.copy2(BLACKLIST_FILE, BACKUP_FILE)
            logging.info(f"Backed up existing blacklist to {BACKUP_FILE}.")
            
        # 5. Atomic Update
        os.replace(TEMP_FILE, BLACKLIST_FILE)
        logging.info(f"Successfully updated {BLACKLIST_FILE}.")
        
    except Exception as e:
        logging.error(f"Update failed: {e}")
        # Clean up temp file if exists
        if os.path.exists(TEMP_FILE):
            os.remove(TEMP_FILE)

if __name__ == "__main__":
    update_blacklist()
