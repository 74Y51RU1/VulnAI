
import requests

# Our authorised Juice Shop lab target
TARGET_URL = "http://192.168.56.1:3000/"


def check_http(target_url=TARGET_URL):
    """Collect read-only HTTP evidence from Juice Shop."""

    response = requests.get(
        target_url,
        timeout=10,
        allow_redirects=False
    )

    evidence = {
        "url": target_url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "page_title": "Not identified"
    }

    # Extract the HTML title without additional dependencies
    from html.parser import HTMLParser

    class TitleParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.in_title = False
            self.title = ""

        def handle_starttag(self, tag, attrs):
            if tag == "title":
                self.in_title = True

        def handle_endtag(self, tag):
            if tag == "title":
                self.in_title = False

        def handle_data(self, data):
            if self.in_title:
                self.title += data

    parser = TitleParser()
    parser.feed(response.text[:50000])
    evidence["page_title"] = parser.title.strip() or "Not identified"

    return evidence


if __name__ == "__main__":
    import json
    print(json.dumps(check_http(), indent=2))
