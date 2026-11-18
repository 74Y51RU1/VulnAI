
# Infrastructure exposure analysis.
# Open ports are observations, not confirmed vulnerabilities.

REVIEW_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "Windows RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch"
}


def check_infrastructure_exposure(scan_results):
    """Convert observed open ports into investigation findings."""

    findings = []

    for service in scan_results.get("services", []):

        port = service["port"]
        detected_name = service.get("service", "unknown")
        product = service.get("product", "")
        version = service.get("version", "")

        if port in REVIEW_PORTS:
            status = "Needs Verification"

            recommendation = (
                f"Confirm whether {REVIEW_PORTS[port]} "
                "should be accessible from this network. "
                "Review access controls, service configuration, "
                "and supported software versions."
            )
        else:
            status = "Observed"

            recommendation = (
                "Confirm that this service is required "
                "and appropriately restricted."
            )

        evidence = (
            f"TCP port {port} is open. "
            f"Nmap service label: {detected_name}. "
            f"Product: {product or 'Not identified'}. "
            f"Version: {version or 'Not identified'}."
        )

        findings.append({
            "name": f"Open TCP Port {port}",
            "status": status,
            "severity": "Informational",
            "evidence": evidence,
            "recommendation": recommendation
        })

    return findings
