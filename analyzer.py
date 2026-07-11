from urllib.parse import urlparse
import re


def analyze_url(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "secure",
        "update",
        "account",
        "password",
        "signin"
    ]

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "is.gd",
        "ow.ly"
    ]

    result = {}

    # HTTPS
    result["https"] = url.startswith("https://")

    # Length
    result["length"] = len(url)

    # IP Address
    result["ip_address"] = bool(
        re.match(r"^\d+\.\d+\.\d+\.\d+$", domain)
    )

    # Suspicious Words
    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    result["suspicious_words"] = found_words

    # Hyphen
    result["hyphen"] = "-" in domain

    # Multiple Subdomains
    result["subdomains"] = domain.count(".")

    # URL Shortener
    result["shortened"] = domain in shorteners

    return result