
import requests

from target_validator import validate_target


def check_cors(target_url):
    # Only assess targets permitted by VulnAI.
    validate_target(target_url)

    test_origin = "https://vulnai-test.invalid"

    response = requests.get(
        target_url,
        headers={"Origin": test_origin},
        timeout=10,
        allow_redirects=False
    )

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials", ""
    )

    if allow_origin is None:
        status = "Not Observed"
        evidence = "No Access-Control-Allow-Origin header returned."

    elif allow_origin == "*":
        status = "Needs Verification"
        evidence = (
            "Access-Control-Allow-Origin: *; "
            f"Access-Control-Allow-Credentials: "
            f"{allow_credentials or 'not present'}"
        )

    elif allow_origin == test_origin:
        status = "Needs Verification"
        evidence = (
            "Server returned the supplied test Origin: "
            + allow_origin
        )

    else:
        status = "Observed"
        evidence = (
            "Access-Control-Allow-Origin: " + allow_origin
        )

    return [{
        "name": "CORS Configuration",
        "status": status,
        "severity": "Informational",
        "evidence": evidence,
        "recommendation": (
            "Review whether cross-origin access is appropriate. "
            "A wildcard or reflected Origin alone does not "
            "confirm a CORS vulnerability. Further checks "
            "would be needed to establish security impact."
        )
    }]
