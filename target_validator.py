
from urllib.parse import urlsplit
import ipaddress

# Explicitly approved targets for the current lab
ALLOWED_TARGETS = {
    ("192.168.56.1", 3000),
}

def validate_target(url):
    parsed = urlsplit(url.strip())

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname or IP address is required.")

    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Credentials and URL fragments are not allowed.")

    host = parsed.hostname

    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(
            "For now, use an approved IP address rather than a domain name."
        )

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise ValueError("Invalid port number.")

    if (host, port) not in ALLOWED_TARGETS:
        raise ValueError("Target is not in the authorised allowlist.")

    return host, port
