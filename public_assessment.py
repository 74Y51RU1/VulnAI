
from public_http_checker import check_public_http
from security_checks import check_security_headers


def check_public_cookies(http_evidence):
    """
    Evaluate cookie attributes observed in a public HTTP response.
    Observations are not confirmed vulnerabilities.
    """

    cookies = http_evidence.get("set_cookie_headers", [])
    findings = []

    if not cookies:
        return [{
            "name": "Cookie Security",
            "status": "Not Observed",
            "severity": "Informational",
            "evidence": "No Set-Cookie headers observed.",
            "recommendation": (
                "No cookie attributes can be assessed from this "
                "response. Other endpoints may set cookies."
            )
        }]

    is_https = http_evidence.get(
        "url", ""
    ).startswith("https://")

    for cookie in cookies:
        parts = cookie.split(";")
        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = [
            part.strip().lower()
            for part in parts[1:]
        ]

        checks = {
            "HttpOnly": "httponly" in attributes,
            "Secure": "secure" in attributes,
            "SameSite": any(
                attr.startswith("samesite=")
                for attr in attributes
            )
        }

        for attribute, present in checks.items():
            findings.append({
                "name": f"Cookie {attribute}: {cookie_name}",
                "status": (
                    "Observed"
                    if present else "Needs Verification"
                ),
                "severity": "Informational",
                "evidence": (
                    f"Cookie '{cookie_name}': "
                    f"{attribute} "
                    f"{'present' if present else 'absent'}"
                ),
                "recommendation": (
                    f"Review whether the {attribute} attribute "
                    "is appropriate for this cookie's purpose. "
                    "An absent attribute alone does not "
                    "confirm a vulnerability."
                )
            })

        if not is_https:
            findings.append({
                "name": f"Cookie Transport: {cookie_name}",
                "status": "Needs Verification",
                "severity": "Informational",
                "evidence": (
                    "Cookie observed in an HTTP response."
                ),
                "recommendation": (
                    "Review whether this cookie contains "
                    "sensitive data and requires HTTPS."
                )
            })

    return findings


def assess_public_website(target_url):
    """
    Perform a read-only public website assessment.
    """

    http_evidence = check_public_http(target_url)

    findings = []

    findings.extend(
        check_security_headers(http_evidence)
    )

    findings.extend(
        check_public_cookies(http_evidence)
    )

    # CORS requires an additional request and is not
    # included until public request safeguards are ready.

    return {
        "assessment_type": "public_web",
        "target_url": http_evidence["url"],
        "http_evidence": http_evidence,
        "findings": findings,
        "finding_count": len(findings),
        "confirmed_vulnerabilities": 0,
        "limitations": [
            "Only the requested page was assessed.",
            "No authentication or application crawling.",
            "No active vulnerability exploitation.",
            "No CORS probe was performed.",
            "Missing headers or cookie attributes alone "
            "do not establish exploitable vulnerabilities."
        ]
    }


if __name__ == "__main__":
    import json

    result = assess_public_website(
        "https://example.com"
    )

    print(json.dumps(result, indent=2))
