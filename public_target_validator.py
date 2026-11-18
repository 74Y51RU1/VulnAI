
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


MAX_URL_LENGTH = 2048

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


def is_public_ip(address):
    """Only accept globally routable IP addresses."""
    ip = ipaddress.ip_address(address)
    return ip.is_global


def validate_public_target(url):
    """
    Validate a public HTTP/HTTPS website URL.

    This does not authorise active vulnerability testing.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url or len(url) > MAX_URL_LENGTH:
        raise ValueError("Invalid URL length.")

    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            "Only HTTP and HTTPS websites are supported."
        )

    if not parsed.hostname:
        raise ValueError("A hostname is required.")

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing credentials are not allowed."
        )

    if parsed.fragment:
        raise ValueError(
            "URL fragments are not supported."
        )

    hostname = parsed.hostname.rstrip(".").lower()

    if (
        hostname in BLOCKED_HOSTNAMES
        or hostname.endswith(".localhost")
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise ValueError(
            "Local and internal hostnames are not allowed."
        )

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    # Restrict the public mode to standard web ports.
    if port is not None and port not in (80, 443):
        raise ValueError(
            "Public website mode supports only ports 80 and 443."
        )

    if parsed.scheme == "http" and port not in (None, 80):
        raise ValueError(
            "HTTP websites must use port 80."
        )

    if parsed.scheme == "https" and port not in (None, 443):
        raise ValueError(
            "HTTPS websites must use port 443."
        )

    try:
        ip = ipaddress.ip_address(hostname)
        addresses = [str(ip)]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                443 if parsed.scheme == "https" else 80,
                type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            raise ValueError(
                "Could not resolve the website hostname."
            )

        addresses = list({
            record[4][0]
            for record in records
        })

    if not addresses:
        raise ValueError(
            "No IP addresses were found for this website."
        )

    for address in addresses:
        if not is_public_ip(address):
            raise ValueError(
                "Website resolves to a non-public IP address. "
                "Public assessment blocked."
            )

    # Remove fragments and normalise the hostname.
    # Keep the path and query for the requested page.
    netloc = hostname

    if ":" in hostname:
        netloc = f"[{hostname}]"

    if port is not None:
        netloc += f":{port}"

    normalised_url = urlunsplit((
        parsed.scheme,
        netloc,
        parsed.path or "/",
        parsed.query,
        ""
    ))

    return {
        "url": normalised_url,
        "hostname": hostname,
        "port": port or (
            443 if parsed.scheme == "https" else 80
        ),
        "resolved_ips": sorted(addresses)
    }


if __name__ == "__main__":
    print("Public website validator ready.")
