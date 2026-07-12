import whois
from urllib.parse import urlparse
from datetime import datetime


def get_domain_info(url):

    try:

        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        info = whois.whois(domain)

        return info

    except Exception:
        return None