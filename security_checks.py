
def check_security_headers(http_evidence):
    headers = {
        key.lower(): value
        for key, value in http_evidence.get("headers", {}).items()
    }

    url = http_evidence.get("url", "")
    is_https = url.lower().startswith("https://")

    findings = []

    checks = {
        "content-security-policy": "Content Security Policy (CSP)",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options"
    }

    for header, name in checks.items():
        if header in headers:
            findings.append({
                "name": name,
                "status": "Observed",
                "severity": "Informational",
                "evidence": f"{header}: {headers[header]}",
                "recommendation": (
                    "Review whether the configured value meets "
                    "the application's security requirements."
                )
            })
        else:
            findings.append({
                "name": name,
                "status": "Needs Verification",
                "severity": "Informational",
                "evidence": f"{header} header not present in response",
                "recommendation": (
                    "Review whether this security header is "
                    "appropriate for the application. "
                    "Its absence alone does not confirm a vulnerability."
                )
            })

    # HSTS is evaluated only on HTTPS responses.
    if is_https:
        if "strict-transport-security" in headers:
            findings.append({
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "Observed",
                "severity": "Informational",
                "evidence": (
                    "strict-transport-security: "
                    + headers["strict-transport-security"]
                ),
                "recommendation": (
                    "Verify the HSTS policy is appropriate "
                    "for the HTTPS deployment."
                )
            })
        else:
            findings.append({
                "name": "HTTP Strict Transport Security (HSTS)",
                "status": "Needs Verification",
                "severity": "Informational",
                "evidence": "HSTS header absent from HTTPS response",
                "recommendation": (
                    "Review whether an HSTS policy should "
                    "be configured for this HTTPS deployment."
                )
            })
    else:
        findings.append({
            "name": "HTTP Strict Transport Security (HSTS)",
            "status": "Not Applicable",
            "severity": "Not Rated",
            "evidence": "Assessment response was served over HTTP",
            "recommendation": (
                "HSTS cannot be established through an HTTP response. "
                "Review HTTPS availability separately."
            )
        })

    return findings
