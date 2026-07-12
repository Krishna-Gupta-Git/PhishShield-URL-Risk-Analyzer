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
        # Add https:// if the user didn't include a scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            raise ValueError("Invalid hostname")

        # Create SSL context
        context = ssl.create_default_context()

        # Connect to server
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_socket:
                certificate = secure_socket.getpeercert()

        # Certificate issuer
        issuer = dict(x[0] for x in certificate.get("issuer", []))
        issued_by = issuer.get("organizationName", "Unknown")

        # Expiry date
        expiry_string = certificate["notAfter"]
        expiry_date = datetime.strptime(
            expiry_string,
            "%b %d %H:%M:%S %Y %Z"
        )

        days_remaining = (expiry_date - datetime.utcnow()).days

        # Certificate health
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
            "issuer": "Unavailable",
            "expiry_date": "Unavailable",
            "days_remaining": 0,
            "certificate_status": "❌ Invalid or Unavailable"
        }