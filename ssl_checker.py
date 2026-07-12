import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime


def get_ssl_info(url):
    """
    Retrieves SSL certificate information for a given website.

    Returns:
        dict: SSL information if successful.
        dict: Default values if SSL information cannot be retrieved.
    """

    try:
        # Extract hostname from the URL
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Remove 'www.' if present
        if hostname.startswith("www."):
            hostname = hostname[4:]

        # Create default SSL context
        context = ssl.create_default_context()

        # Connect to the server on port 443 (HTTPS)
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:

                # Get SSL certificate
                certificate = secure_socket.getpeercert()

        # Get certificate issuer
        issuer = dict(item[0] for item in certificate["issuer"])

        issued_by = issuer.get("organizationName", "Unknown")

        # Certificate expiry date
        expiry_string = certificate["notAfter"]

        expiry_date = datetime.strptime(
            expiry_string,
            "%b %d %H:%M:%S %Y %Z"
        )

        # Calculate remaining days
        days_remaining = (expiry_date - datetime.now()).days

        # Determine certificate health
        if days_remaining < 0:
            certificate_status = "❌ Expired"

        elif days_remaining < 30:
            certificate_status = "⚠️ Expiring Soon"

        elif days_remaining < 90:
            certificate_status = "🟡 Valid (Near Expiry)"

        else:
            certificate_status = "🟢 Healthy"

        return {
            "valid": True,
            "issuer": issued_by,
            "expiry_date": expiry_date.strftime("%d %B %Y"),
            "days_remaining": days_remaining,
            "certificate_status": certificate_status
        }

    except Exception as e:
        print("SSL Error:", e)

        return {
            "valid": False,
            "issuer": "Unknown",
            "expiry_date": "Unavailable",
            "days_remaining": 0,
            "certificate_status": "❌ Invalid or Unavailable"
        }