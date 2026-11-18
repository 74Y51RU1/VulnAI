
from scan_history import get_assessment


def compare_web_assessments(old_id, new_id):
    """
    Compare two saved website assessments.

    Uses previously recorded evidence only.
    No new HTTP requests are performed.
    """

    old = get_assessment(old_id)
    new = get_assessment(new_id)

    if old is None or new is None:
        raise ValueError("One or both assessments do not exist.")

    if old["target_url"] != new["target_url"]:
        raise ValueError(
            "Cannot compare assessments of different targets."
        )

    old_http = old.get("http_evidence") or {}
    new_http = new.get("http_evidence") or {}

    if (
        old_http.get("assessment_type") == "infrastructure"
        or new_http.get("assessment_type") == "infrastructure"
    ):
        raise ValueError(
            "Both assessments must be website assessments."
        )

    if not old_http or not new_http:
        raise ValueError(
            "Both assessments require saved HTTP evidence."
        )

    def findings_by_name(assessment):
        result = {}

        for finding in assessment.get("all_findings", []):
            name = finding.get("name", "").strip()

            if name:
                result[name] = finding

        return result

    old_findings = findings_by_name(old)
    new_findings = findings_by_name(new)

    old_names = set(old_findings)
    new_names = set(new_findings)

    added = sorted(new_names - old_names)
    removed = sorted(old_names - new_names)

    changed = []
    unchanged = []

    for name in sorted(old_names & new_names):
        previous = old_findings[name]
        current = new_findings[name]

        fields = ("status", "severity", "evidence")

        if any(
            previous.get(field) != current.get(field)
            for field in fields
        ):
            changed.append({
                "name": name,
                "previous_status": previous.get("status", ""),
                "current_status": current.get("status", ""),
                "previous_evidence": previous.get("evidence", ""),
                "current_evidence": current.get("evidence", "")
            })
        else:
            unchanged.append(name)

    return {
        "target": old["target_url"],
        "previous_id": old["id"],
        "current_id": new["id"],
        "previous_timestamp": old["timestamp"],
        "current_timestamp": new["timestamp"],
        "previous_http_status": old_http.get("status_code"),
        "current_http_status": new_http.get("status_code"),
        "added_findings": added,
        "removed_findings": removed,
        "changed_findings": changed,
        "unchanged_findings": unchanged,
        "note": (
            "Results compare saved observations only. "
            "A changed or missing finding does not independently "
            "confirm that a vulnerability was introduced or fixed. "
            "Changes may reflect different HTTP responses, "
            "assessment coverage, or application configuration."
        )
    }


if __name__ == "__main__":
    print("VulnAI Website Comparison module ready.")
