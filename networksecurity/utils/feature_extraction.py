import urllib.parse
import whois
import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import ssl
import tldextract
from urllib.parse import urlparse, urljoin
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class WebsiteFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        
        try:
            self.response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            
            self.final_url = self.response.url
        except (requests.exceptions.RequestException, socket.error) as e:
            
            self.response = None
            self.soup = None
            self.final_url = url

    
    def has_ip_address(self):
        """Check if URL's domain is an IP address."""
        try:
            socket.inet_aton(self.domain.split(':')[0])
            return 1
        except socket.error:
            return 0

    def get_url_length(self):
        """Return the length of the URL."""
        return len(self.url)

    def uses_shortening_service(self):
        """Check if the URL uses a known shortening service."""
        shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'tiny.cc',
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'shorte.st'
        ]
        domain = tldextract.extract(self.url).registered_domain
        return 1 if domain in shorteners else 0

    def has_at_symbol(self):
        """Check if the URL contains the '@' symbol."""
        return 1 if '@' in self.url else 0

    def has_double_slash(self):
        """Check if the URL contains a double slash '//' in the path."""
        path = self.parsed_url.path
        return 1 if '//' in path else 0

    def has_prefix_suffix(self):
        """Check if the domain name contains a hyphen '-'."""
        return 1 if '-' in self.domain else 0

    def count_subdomains(self):
        """Count the number of subdomains."""
        subdomain = tldextract.extract(self.url).subdomain
        if subdomain:
            
            count = len(subdomain.split('.'))
            if count == 1:
                return 0
            elif count == 2:
                return 1
            else:
                return 1
        return 0
        
    def check_https_token(self):
        """Check if 'https' is part of the domain name."""
        return 1 if 'https' in self.domain.lower() else 0

  
    def check_ssl_trustworthiness(self):
        """Checks the SSL certificate issuer for trustworthiness."""
        try:
            hostname = self.parsed_url.netloc.split(':')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    trusted_issuers = ["cPanel, Inc.", "Cloudflare, Inc.", "DigiCert Inc", "GoDaddy.com, Inc.", "GlobalSign nv-sa", "Let's Encrypt", "Sectigo Limited", "Amazon"]
                    
                    org_name = issuer.get('organizationName', '')
                    return 1 if any(trusted in org_name for trusted in trusted_issuers) else 0
        except:
            return 0

    def get_domain_time_to_expiry(self):
        """Gets the time until the domain expires in days."""
        try:
            whois_info = whois.whois(self.domain)
            expiration_date = whois_info.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            if expiration_date:
                time_to_expiry = (expiration_date - datetime.now()).days
                return time_to_expiry
            return 0
        except:
            return 0

    def get_domain_age(self):
        """Get the age of the domain in days."""
        try:
            whois_info = whois.whois(self.domain)
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age = (datetime.now() - creation_date).days
                return age
            return 0
        except:
            return 0

    def check_dns_records(self):
        """Check if DNS records exist for the domain."""
        try:
            socket.gethostbyname(self.domain)
            return 1
        except socket.gaierror:
            return 0

    
    def check_favicon(self):
        """Check if the favicon is loaded from an external domain."""
        if not self.soup: return 0
        
        favicon = self.soup.find('link', rel=re.compile(r'icon', re.I))
        if favicon and favicon.get('href'):
            favicon_url = urljoin(self.url, favicon['href'])
            favicon_domain = urlparse(favicon_url).netloc
            return 1 if favicon_domain and favicon_domain != self.domain else 0
        return 0

    def get_port(self):
        """Check if a non-standard port is used."""
        port = self.parsed_url.port
        if port:
            return 1 if port not in [80, 443] else 0
        return 0

    def check_request_url_ratio(self):
        """Calculate the percentage of external resources (img, video, audio, etc.)."""
        if not self.soup: return 0
        
        external_count = 0
        total_count = 0
        tags = ['img', 'video', 'audio', 'script', 'link', 'source']
        attrs = ['src', 'href']

        for tag in tags:
            for element in self.soup.find_all(tag):
                for attr in attrs:
                    url = element.get(attr)
                    if url:
                        total_count += 1
                        if urlparse(urljoin(self.url, url)).netloc != self.domain:
                            external_count += 1
                        break
        
        return (external_count / total_count * 100) if total_count > 0 else 0

    def check_anchor_url_ratio(self):
        """Calculate the percentage of anchor tags pointing to external domains."""
        if not self.soup: return 0
        
        external_count = 0
        total_count = 0
        for a in self.soup.find_all('a', href=True):
            total_count += 1
            href = a['href']
            if urlparse(urljoin(self.url, href)).netloc != self.domain:
                external_count += 1
        
        return (external_count / total_count * 100) if total_count > 0 else 0

    def check_sfh(self):
        """Check for suspicious Server Form Handler (SFH) actions."""
        if not self.soup: return 0
        
        for form in self.soup.find_all('form', action=True):
            action = form['action']
            if not action or action.strip().lower() == 'about:blank':
                return 1
            if urlparse(urljoin(self.url, action)).netloc != self.domain:
                return 1
        return 0

    def check_email_submission(self):
        """Check if a form submits information to an email address."""
        if not self.soup: return 0
        
        for form in self.soup.find_all('form', action=True):
            if 'mailto:' in form['action'].lower():
                return 1
        return 0

    def count_redirects(self):
        """Counts the number of redirects."""
        if self.response and self.response.history:
            return 1 if len(self.response.history) >= 2 else 0
        return 0

    def check_right_click_disabled(self):
        """Check if the right-click context menu is disabled."""
        if not self.response: return 0
        return 1 if 'event.button==2' in self.response.text or 'oncontextmenu' in self.response.text else 0

    def check_popup_windows(self):
        """Check for scripts that create pop-up windows with text fields."""
        if not self.response: return 0
        return 1 if 'prompt(' in self.response.text else 0

    def check_iframes(self):
        """Check if the page uses iframes."""
        if not self.soup: return 0
        return 1 if self.soup.find_all('iframe') else 0
        
   

    def check_ssl_final_state(self):
        """Alias for SSL check. A value > 1 yr is good (1), else (-1)."""
        days_left = self.get_domain_time_to_expiry()
        if days_left == 0: 
             return 0
        return 1 if days_left >= 365 else -1

    def get_domain_registration_length(self):
        """Alias for domain expiry check."""
        return self.get_domain_time_to_expiry()

    def check_request_url(self):
        """Alias for request URL ratio. A high ratio is suspicious."""
        ratio = self.check_request_url_ratio()
        if ratio < 22:
            return 0
        elif 22 <= ratio < 61:
            return 1
        else:
            return 1 

    def check_anchor_urls(self):
        """Alias for anchor URL ratio. A high ratio is suspicious."""
        ratio = self.check_anchor_url_ratio()
        if ratio < 31:
            return 0
        elif 31 <= ratio < 67:
            return 1
        else:
            return 1 

    def count_links_in_tags(self):
        
        return 0

    def check_abnormal_url(self):
        """Checks if the hostname is present in the URL string itself."""
        return 1 if self.domain in self.url else 0

    def check_mouseover(self):
       
        if not self.response: return 0
        return 1 if "onmouseover" in self.response.text.lower() else 0
        
    def estimate_web_traffic(self):
        
        return 0

    def get_page_rank(self):
       
        return 0

    def check_google_index(self):
     
        return 1

    def count_external_links(self):
        return 0

    def check_statistical_report(self):
        return 0

    def extract_features(self):
        """
        Runs all feature extraction methods and returns a dictionary with keys
        aligned to the model's expected input columns.
        """
        features = {
            "having_IP_Address": self.has_ip_address(),
            "URL_Length": self.get_url_length(),
            "Shortining_Service": self.uses_shortening_service(),
            "having_At_Symbol": self.has_at_symbol(),
            "double_slash_redirecting": self.has_double_slash(),
            "Prefix_Suffix": self.has_prefix_suffix(),
            "having_Sub_Domain": self.count_subdomains(),
            "SSLfinal_State": self.check_ssl_final_state(),
            "Domain_registeration_length": self.get_domain_registration_length(),
            "Favicon": self.check_favicon(),
            "port": self.get_port(),
            "HTTPS_token": self.check_https_token(),
            "Request_URL": self.check_request_url(),
            "URL_of_Anchor": self.check_anchor_urls(),
            "Links_in_tags": self.count_links_in_tags(),
            "SFH": self.check_sfh(),
            "Submitting_to_email": self.check_email_submission(),
            "Abnormal_URL": self.check_abnormal_url(),
            "Redirect": self.count_redirects(),
            "on_mouseover": self.check_mouseover(),
            "RightClick": self.check_right_click_disabled(),
            "popUpWidnow": self.check_popup_windows(),
            "Iframe": self.check_iframes(),
            "age_of_domain": self.get_domain_age(),
            "DNSRecord": self.check_dns_records(),
            "web_traffic": self.estimate_web_traffic(),
            "Page_Rank": self.get_page_rank(),
            "Google_Index": self.check_google_index(),
            "Links_pointing_to_page": self.count_external_links(),
            "Statistical_report": self.check_statistical_report()
        }
        return features