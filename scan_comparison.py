
from scan_history import get_assessment


def compare_assessments(old_id, new_id):
    """
    Compare two saved infrastructure assessments.

    Only compare TCP ports assessed in both scans.
    No new network scans are performed.
    """

    old = get_assessment(old_id)
    new = get_assessment(new_id)

    if old is None or new is None:
        raise ValueError("One or both assessments do not exist.")

    if old["target_url"] != new["target_url"]:
        raise ValueError(
            "Cannot compare assessments of different targets."
        )

    old_http = old.get("http_evidence", {})
    new_http = new.get("http_evidence", {})

    if (
        old_http.get("assessment_type") != "infrastructure"
        or new_http.get("assessment_type") != "infrastructure"
    ):
        raise ValueError(
            "Both assessments must be infrastructure assessments."
        )

    old_scan = old_http.get("infrastructure", {})
    new_scan = new_http.get("infrastructure", {})

    old_checked = set(old_scan.get("ports_checked", []))
    new_checked = set(new_scan.get("ports_checked", []))

    common_ports = old_checked & new_checked

    if not common_ports:
        raise ValueError(
            "The assessments have no commonly scanned ports."
        )

    def open_services(scan):
        return {
            int(service["port"]): service
            for service in scan.get("services", [])
            if service.get("state") == "open"
        }

    old_services = open_services(old_scan)
    new_services = open_services(new_scan)

    old_open = set(old_services) & common_ports
    new_open = set(new_services) & common_ports

    newly_opened = sorted(new_open - old_open)
    no_longer_open = sorted(old_open - new_open)
    unchanged_open = sorted(old_open & new_open)

    service_changes = []

    for port in unchanged_open:
        old_service = old_services[port]
        new_service = new_services[port]

        fields = ("service", "product", "version")

        if any(
            old_service.get(field) != new_service.get(field)
            for field in fields
        ):
            service_changes.append({
                "port": port,
                "previous": {
                    field: old_service.get(field, "")
                    for field in fields
                },
                "current": {
                    field: new_service.get(field, "")
                    for field in fields
                }
            })

    return {
        "target": old["target_url"],
        "previous_id": old["id"],
        "current_id": new["id"],
        "previous_timestamp": old["timestamp"],
        "current_timestamp": new["timestamp"],
        "common_ports_checked": sorted(common_ports),
        "newly_opened": newly_opened,
        "no_longer_open": no_longer_open,
        "unchanged_open": unchanged_open,
        "service_changes": service_changes,
        "note": (
            "Results compare recorded observations only. "
            "A port no longer observed open may be closed, "
            "filtered, or otherwise unreachable. "
            "Service identification changes require verification."
        )
    }


if __name__ == "__main__":
    print(
        "VulnAI Scan Comparison module ready."
    )
