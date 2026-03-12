import ipaddress
import re
import urllib.request
from urllib import response

from bs4 import BeautifulSoup
import socket
import requests
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse, ParseResult
from typing import Optional

from urllib3.util import url


def sanitize_url(input_url):
    """
    Sanitize URL by removing common prefixes and cleaning malformed strings.
    This fixes issues like "Scanning:https://www.youtube.com/"
    """
    if not input_url:
        return ""

    url = str(input_url).strip()

    prefixes = ["scanning:", "checking:", "url:", "link:", "visit:", "open:"]

    changed = True
    while changed:
        changed = False
        url_lower = url.lower()
        for prefix in prefixes:
            if url_lower.startswith(prefix):
                url = url[len(prefix) :].strip()
                changed = True
                break

    url = re.sub(r"^\s*https?://+", "https://", url, flags=re.IGNORECASE)
    url = re.sub(r"^\s*www\.", "https://www.", url)

    return url


class FeatureExtraction:
    url: str
    domain: str
    whois_response: Optional[whois.whois]
    urlparse: ParseResult
    response: Optional[requests.Response]
    soup: BeautifulSoup
    features: list[int]

    def __init__(self, url, fetch_content=True):
        self.features = []

        self.url = sanitize_url(url)

        if not self.url:
            self._fill_default_features()
            return

        self.domain = ""
        self.whois_response = None
        self.urlparse = urlparse(
            self.url if self.url.startswith("http") else "http://" + self.url
        )
        self.soup = BeautifulSoup("", "html.parser")
        self.response = None

        if fetch_content:
            try:
                resp = requests.get(self.url, timeout=5, verify=False)
                self.response = resp
                if resp:
                    self.soup = BeautifulSoup(resp.text, "html.parser")
            except:
                pass

        try:
            parsed = urlparse(self.url)
            self.domain = str(parsed.netloc)
        except:
            pass

        try:
            if self.domain:
                self.whois_response = whois.whois(self.domain)
        except:
            pass

        self._extract_all_features()

    def _fill_default_features(self):
        """Fill with default safe features when URL is invalid."""
        self.features = [1] * 30

    def _extract_all_features(self):
        """Extract all 30 features with error handling."""
        try:
            self.features.append(int(self.UsingIp()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.longUrl()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.shortUrl()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.symbol()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.redirecting()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.prefixSuffix()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.SubDomains()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.Hppts()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.DomainRegLen()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.Favicon()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.NonStdPort()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.HTTPSDomainURL()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.RequestURL()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.AnchorURL()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.LinksInScriptTags()))
        except:
            self.features.append(0)

        try:
            self.features.append(int(self.ServerFormHandler()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.InfoEmail()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.AbnormalURL()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.WebsiteForwarding()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.StatusBarCust()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.DisableRightClick()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.UsingPopupWindow()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.IframeRedirection()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.AgeofDomain()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.DNSRecording()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.WebsiteTraffic()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.PageRank()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.GoogleIndex()))
        except:
            self.features.append(1)

        try:
            self.features.append(int(self.LinksPointingToPage()))
        except:
            self.features.append(-1)

        try:
            self.features.append(int(self.StatsReport()))
        except:
            self.features.append(1)

        while len(self.features) < 30:
            self.features.append(1)

        self.features = self.features[:30]

    # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search(
            "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
            "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
            "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net",
            self.url,
        )
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@", self.url):
            return -1
        return 1

    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind("//") > 6:
            return -1
        return 1

    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall("\-", self.domain)
            if match:
                return -1
            return 1
        except:
            return -1

    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Hppts(self) -> int:
        try:
            parsed = self.urlparse
            if parsed and "https" in str(parsed.scheme):
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self) -> int:
        try:
            whois_res = self.whois_response
            if not whois_res:
                return -1
            expiration_date = whois_res.expiration_date
            creation_date = whois_res.creation_date
            try:
                if isinstance(expiration_date, list) and len(expiration_date):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if isinstance(creation_date, list) and len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            if not expiration_date or not creation_date:
                return -1

            age = (int(expiration_date.year) - int(creation_date.year)) * 12 + (
                int(expiration_date.month) - int(creation_date.month)
            )
            if age >= 12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all("head"):
                for head.link in self.soup.find_all("link", href=True):
                    dots = [x.start(0) for x in re.finditer("\.", head.link["href"])]
                    if (
                        self.url in head.link["href"]
                        or len(dots) == 1
                        or self.domain in head.link["href"]
                    ):
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port) > 1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if "https" in self.domain:
                return -1
            return 1
        except:
            return -1

    # 13. RequestURL
    def RequestURL(self) -> int:
        i: int = 0
        success: int = 0
        try:
            soup = self.soup
            if not soup:
                return -1
            for img in soup.find_all("img", src=True):
                src = str(img["src"])
                dots = [x.start(0) for x in re.finditer("\.", src)]
                if self.url in src or self.domain in src or len(dots) == 1:
                    success = success + 1  # type: ignore
                i = i + 1  # type: ignore

            for audio in soup.find_all("audio", src=True):
                src = str(audio["src"])
                dots = [x.start(0) for x in re.finditer("\.", src)]
                if self.url in src or self.domain in src or len(dots) == 1:
                    success = success + 1  # type: ignore
                i = i + 1  # type: ignore

            for embed in soup.find_all("embed", src=True):
                src = str(embed["src"])
                dots = [x.start(0) for x in re.finditer("\.", src)]
                if self.url in src or self.domain in src or len(dots) == 1:
                    success = success + 1  # type: ignore
                i = i + 1  # type: ignore

            for iframe in soup.find_all("iframe", src=True):
                src = str(iframe["src"])
                dots = [x.start(0) for x in re.finditer("\.", src)]
                if self.url in src or self.domain in src or len(dots) == 1:
                    success = success + 1  # type: ignore
                i = i + 1  # type: ignore

            try:
                if i != 0:
                    percentage = float(success) / float(i) * 100
                    if percentage < 22.0:
                        return 1
                    elif (percentage >= 22.0) and (percentage < 61.0):
                        return 0
                    else:
                        return -1
                return 0
            except:
                return 0
        except:
            return -1

    # 14. AnchorURL
    def AnchorURL(self) -> int:
        i: int = 0
        unsafe: int = 0
        try:
            soup = self.soup
            if not soup:
                return -1
            for tag in soup.find_all("a", href=True):
                href = str(tag["href"])
                if (
                    "#" in href
                    or "javascript" in href.lower()
                    or "mailto" in href.lower()
                    or not (self.url in href or self.domain in href)
                ):
                    unsafe = unsafe + 1
                i = i + 1

            if i != 0:
                percentage = float(unsafe) / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif (percentage >= 31.0) and (percentage < 67.0):
                    return 0
                else:
                    return -1
            return -1
        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self) -> int:
        i: int = 0
        success: int = 0
        try:
            soup = self.soup
            if not soup:
                return -1

            for link in soup.find_all("link", href=True):
                href = str(link["href"])
                if self.url not in href and self.domain not in href:
                    success = success + 1
                i = i + 1

            for script in soup.find_all("script", src=True):
                src = str(script["src"])
                if self.url not in src and self.domain not in src:
                    success = success + 1
                i = i + 1

            if i != 0:
                percentage = float(success) / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif (percentage >= 17.0) and (percentage < 81.0):
                    return 0
                else:
                    return -1
            return 0
        except:
            return 0

    # 16. ServerFormHandler
    def ServerFormHandler(self) -> int:
        try:
            soup = self.soup
            if not soup:
                return -1
            forms = soup.find_all("form", action=True)
            if len(forms) == 0:
                return 1

            for tag in forms:
                if tag["action"] == "" or tag["action"] == "about:blank":
                    return -1
                elif self.url not in tag["action"] and self.domain not in tag["action"]:
                    return 0
                else:
                    return 1
            return 1
        except:
            return 1

    # 17. InfoEmail
    def InfoEmail(self) -> int:
        try:
            resp = self.response
            if resp and (re.findall(r"[mail\(\)|mailto:?]", resp.text)):
                return -1
            else:
                return 1
        except:
            return 1

    # 18. AbnormalURL
    def AbnormalURL(self) -> int:
        try:
            resp = self.response
            whois_resp = self.whois_response
            if resp and whois_resp and resp.text == str(whois_resp):
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self) -> int:
        try:
            resp = self.response
            if not resp or not resp.history:
                return -1
            history = resp.history
            if len(history) <= 1:
                return 1
            elif len(history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self) -> int:
        try:
            resp = self.response
            if resp and re.findall("<script>.+onmouseover.+</script>", resp.text):
                return 1
            return -1
        except:
            return -1

    # 21. DisableRightClick
    def DisableRightClick(self) -> int:
        try:
            resp = self.response
            if resp and re.findall(r"event.button ?== ?2", resp.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self) -> int:
        try:
            resp = self.response
            if resp and re.findall(r"alert\(", resp.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 23. IframeRedirection
    def IframeRedirection(self) -> int:
        try:
            resp = self.response
            if resp and re.findall(r"[<iframe>|<frameBorder>]", resp.text):
                return 1
            else:
                return -1
        except:
            return -1

    # 24. AgeofDomain
    def AgeofDomain(self) -> int:
        try:
            if not self.whois_response:
                return -1
            whois_res = self.whois_response
            creation_date = whois_res.creation_date  # type: ignore
            try:
                if isinstance(creation_date, list) and len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (
                today.month - creation_date.month
            )  # type: ignore
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording
    def DNSRecording(self) -> int:
        try:
            if not self.whois_response:
                return -1
            whois_res = self.whois_response
            creation_date = whois_res.creation_date  # type: ignore
            try:
                if isinstance(creation_date, list) and len(creation_date):
                    creation_date = creation_date[0]
            except:
                pass

            today = date.today()
            age = (today.year - creation_date.year) * 12 + (
                today.month - creation_date.month
            )  # type: ignore
            if age >= 6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(
                urllib.request.urlopen(
                    "http://data.alexa.com/data?cli=10&dat=s&url=" + self.url
                ).read(),
                "xml",
            ).find("REACH")["RANK"]
            if int(rank) < 100000:
                return 1
            return 0
        except:
            return -1

    # 27. PageRank
    def PageRank(self, rank_checker_response=None):
        try:
            prank_checker_response = requests.post(
                "https://www.checkpagerank.net/index.php", {"name": self.domain}
            )

            global_rank = int(
                re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0]
            )
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
                "at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
                url,
            )
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                "146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
                "107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
                "118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
                "216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
                "34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|"
                "216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42",
                ip_address,
            )
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1

    def getFeaturesList(self):
        return self.features
