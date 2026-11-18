
def check_cookie_security(http_evidence):
    """
    Perform read-only checks on HTTP response cookies.
    Findings are observations, not confirmed vulnerabilities.
    """

    headers = {
        key.lower(): value
        for key, value in http_evidence.get("headers", {}).items()
    }

    url = http_evidence.get("url", "")
    is_https = url.lower().startswith("https://")

    findings = []

    # This checks the captured response headers only.
    # Some HTTP clients combine or separately store Set-Cookie headers.
    set_cookie = headers.get("set-cookie")

    if not set_cookie:
        findings.append({
            "name": "Cookie Security",
            "status": "Not Observed",
            "severity": "Informational",
            "evidence": "No Set-Cookie header found in the captured response.",
            "recommendation": (
                "No cookie attributes can be evaluated from this response. "
                "Other application endpoints may set cookies."
            )
        })
        return findings

    # A single Set-Cookie value is evaluated here.
    # Multiple cookies require separate Set-Cookie header collection.
    cookie_name = set_cookie.split("=", 1)[0].strip()
    attributes = [
        part.strip().lower()
        for part in set_cookie.split(";")[1:]
    ]

    checks = {
        "HttpOnly": any(attr == "httponly" for attr in attributes),
        "Secure": any(attr == "secure" for attr in attributes),
        "SameSite": any(
            attr.startswith("samesite=")
            for attr in attributes
        )
    }

    for attribute, present in checks.items():
        status = "Observed" if present else "Needs Verification"

        if attribute == "Secure" and not is_https:
            status = "Needs Verification"

        findings.append({
            "name": f"Cookie {attribute}",
            "status": status,
            "severity": "Informational",
            "evidence": (
                f"Cookie '{cookie_name}': "
                f"{attribute} {'present' if present else 'not present'} "
                "in the captured Set-Cookie header"
            ),
            "recommendation": (
                "Review this cookie's purpose and whether the "
                f"{attribute} attribute is appropriate. "
                "Missing attributes alone do not confirm a vulnerability."
            )
        })

    return findings
