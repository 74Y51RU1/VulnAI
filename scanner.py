
import subprocess
import ipaddress
import xml.etree.ElementTree as ET


# Explicitly authorised lab targets.
# Add another IP only after confirming that you own
# the target or have permission to assess it.
ALLOWED_TARGETS = {
    ipaddress.ip_address("192.168.56.1")
}

# Common infrastructure service ports.
INFRASTRUCTURE_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135,
    139, 143, 443, 445, 587, 993, 995,
    1433, 3000, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200
]


def validate_scan_ip(ip):
    """Allow scanning only explicitly authorised IPs."""
    address = ipaddress.ip_address(str(ip))

    if address not in ALLOWED_TARGETS:
        raise ValueError(
            "Target is not on the authorised IP allowlist."
        )

    return str(address)


def validate_ports(ports):
    """Validate the requested TCP ports."""
    if isinstance(ports, int):
        ports = [ports]

    if not isinstance(ports, (list, tuple)):
        raise ValueError("Ports must be a list or tuple.")

    if not ports:
        raise ValueError("At least one port is required.")

    validated = []

    for port in ports:
        if isinstance(port, bool):
            raise ValueError("Invalid port.")

        port = int(port)

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        validated.append(port)

    return sorted(set(validated))


def run_nmap(ip, ports):
    """Run an authorised TCP service scan."""
    ip = validate_scan_ip(ip)
    ports = validate_ports(ports)

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-p",
        ",".join(map(str, ports)),
        "-oX",
        "-",
        ip
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=180
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Nmap scan failed."
        )

    return result.stdout


def scan_target(ip, port=3000):
    """
    Existing dashboard-compatible function.

    Returns human-readable Nmap output for one port.
    """
    ip = validate_scan_ip(ip)
    ports = validate_ports([port])

    result = subprocess.run(
        [
            "nmap",
            "-sT",
            "-sV",
            "--version-light",
            "-Pn",
            "-p",
            str(ports[0]),
            ip
        ],
        capture_output=True,
        text=True,
        timeout=120
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Nmap scan failed."
        )

    return result.stdout


def scan_infrastructure(ip):
    """Scan common infrastructure ports and parse XML."""
    xml_output = run_nmap(
        ip,
        INFRASTRUCTURE_PORTS
    )

    root = ET.fromstring(xml_output)

    services = []

    for port_element in root.findall(".//port"):
        state_element = port_element.find("state")

        if state_element is None:
            continue

        if state_element.get("state") != "open":
            continue

        service_element = port_element.find("service")

        service = {
            "port": int(port_element.get("portid")),
            "protocol": port_element.get("protocol", "tcp"),
            "state": "open",
            "service": "unknown",
            "product": "",
            "version": ""
        }

        if service_element is not None:
            service["service"] = service_element.get(
                "name", "unknown"
            )
            service["product"] = service_element.get(
                "product", ""
            )
            service["version"] = service_element.get(
                "version", ""
            )

        services.append(service)

    return {
        "target": validate_scan_ip(ip),
        "ports_checked": INFRASTRUCTURE_PORTS,
        "open_ports": len(services),
        "services": services
    }


def clean_scan_output(raw_output):
    """Remove verbose Nmap fingerprints from text output."""
    cleaned_lines = []
    in_fingerprint = False

    for line in raw_output.splitlines():

        if (
            "service unrecognized despite returning data"
            in line
        ):
            in_fingerprint = True
            continue

        if in_fingerprint:
            if (
                line.startswith("Service detection performed")
                or line.startswith("Nmap done:")
            ):
                in_fingerprint = False
            else:
                continue

        if line.startswith("SF-"):
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


if __name__ == "__main__":
    result = scan_infrastructure("192.168.56.1")

    import json
    print(json.dumps(result, indent=2))
