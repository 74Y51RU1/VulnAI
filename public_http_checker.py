
import json
import re
import ipaddress
from html.parser import HTMLParser
from urllib.parse import urlsplit

import urllib3

from public_target_validator import validate_public_target


MAX_RESPONSE_BYTES = 100_000


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


def check_public_http(target_url):
    """
    Collect read-only HTTP evidence from a public website.

    No automatic redirects.
    No proxy configuration.
    No active vulnerability payloads.
    """

    target = validate_public_target(target_url)

    hostname = target["hostname"]
    port = target["port"]
    parsed = urlsplit(target["url"])

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    # Use a public IP returned by the validator.
    # The connection is pinned to this address.
    public_ip = target["resolved_ips"][0]

    if not ipaddress.ip_address(public_ip).is_global:
        raise ValueError("Non-public destination blocked.")

    if parsed.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            host=public_ip,
            port=port,
            server_hostname=hostname,
            assert_hostname=hostname,
            cert_reqs="CERT_REQUIRED",
            timeout=urllib3.Timeout(
                connect=5,
                read=10
            ),
            maxsize=1,
            block=True
        )
    else:
        pool = urllib3.HTTPConnectionPool(
            host=public_ip,
            port=port,
            timeout=urllib3.Timeout(
                connect=5,
                read=10
            ),
            maxsize=1,
            block=True
        )

    host_header = hostname

    if ":" in hostname:
        host_header = f"[{hostname}]"

    if (
        parsed.scheme == "http" and port != 80
    ) or (
        parsed.scheme == "https" and port != 443
    ):
        host_header += f":{port}"

    try:
        response = pool.urlopen(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "VulnAI/2.0 ReadOnlyAssessment",
                "Accept": "text/html,application/xhtml+xml",
                "Connection": "close"
            },
            redirect=False,
            retries=False,
            preload_content=False
        )

        try:
            body = response.read(
                MAX_RESPONSE_BYTES + 1
            )

            truncated = len(body) > MAX_RESPONSE_BYTES
            body = body[:MAX_RESPONSE_BYTES]

            parser = TitleParser()

            content_type = response.headers.get(
                "Content-Type", ""
            )

            if "html" in content_type.lower():
                parser.feed(
                    body.decode("utf-8", errors="replace")
                )

            evidence = {
                "url": target["url"],
                "hostname": hostname,
                "connected_ip": public_ip,
                "status_code": response.status,
                "headers": dict(response.headers),
                "set_cookie_headers": response.headers.getlist(
                    "Set-Cookie"
                ),
                "page_title": (
                    parser.title.strip()
                    or "Not identified"
                ),
                "response_truncated": truncated,
                "redirect_location": response.headers.get(
                    "Location"
                ),
                "assessment_type": "public_web"
            }

            return evidence

        finally:
            response.release_conn()

    finally:
        pool.close()


if __name__ == "__main__":
    result = check_public_http("https://example.com")
    print(json.dumps(result, indent=2))
