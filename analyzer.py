import re
from urllib.parse import urlparse

# Common phishing keywords
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "bank",
    "secure",
    "update",
    "account",
    "password"
]

# Common URL shorteners
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co"
]


def analyze_url(url):

    results = {}

    # -----------------------------
    # URL Length
    # -----------------------------
    results["length"] = len(url)

    # -----------------------------
    # HTTPS
    # -----------------------------
    results["https"] = url.startswith("https://")

    # -----------------------------
    # IP Address Detection
    # -----------------------------
    ip_pattern = r"^(http://|https://)?(\d{1,3}\.){3}\d{1,3}"

    results["ip_address"] = bool(
        re.match(ip_pattern, url)
    )

    # -----------------------------
    # Suspicious Words
    # -----------------------------
    found_words = []

    lower_url = url.lower()

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:
            found_words.append(word)

    results["suspicious_words"] = found_words

    # -----------------------------
    # Hyphen
    # -----------------------------
    domain = urlparse(url).netloc

    results["hyphen"] = "-" in domain

    # -----------------------------
    # Subdomains
    # -----------------------------
    dot_count = domain.count(".")

    results["subdomains"] = dot_count

    # -----------------------------
    # Shortened URL
    # -----------------------------
    results["shortened"] = any(
        short in domain
        for short in SHORTENERS
    )

    return results