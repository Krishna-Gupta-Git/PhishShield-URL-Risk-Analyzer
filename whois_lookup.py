import whois
from urllib.parse import urlparse
from datetime import datetime


def get_domain_info(url):
    """
    Fetch WHOIS information for a given URL.

    Returns:
        dict: Domain information if successful.
        None: If WHOIS lookup fails.
    """

    try:
        # Extract the domain from the URL
        domain = urlparse(url).netloc

        # Remove 'www.' if present
        if domain.startswith("www."):
            domain = domain[4:]

        # Perform WHOIS lookup
        data = whois.whois(domain)

        # Get creation date
        creation = data.creation_date

        # Some WHOIS servers return a list of dates
        if isinstance(creation, list):
            creation = creation[0]

        # Get expiration date
        expiry = data.expiration_date

        if isinstance(expiry, list):
            expiry = expiry[0]

        # Calculate domain age
        age = None

        if creation:
            age = datetime.now().year - creation.year

        # Determine domain status
        if age is None:
            age_status = "Unknown"

        elif age < 1:
            age_status = "⚠️ Very New Domain"

        elif age < 3:
            age_status = "🟡 New Domain"

        else:
            age_status = "🟢 Established Domain"

        # Return cleaned information
        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": creation,
            "expiration_date": expiry,
            "domain_age": age,
            "age_status": age_status
        }

    except Exception as e:
        print("WHOIS Error:", e)
        return None