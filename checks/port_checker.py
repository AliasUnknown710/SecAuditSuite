import json
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from checks.exceptions import ConfigurationError, TargetUnreachableError, setup_logger

logger = setup_logger("SecAudit.PortChecker")

DEFAULT_PORTS = (22, 80, 443, 445, 1433, 3389)

def parse_port_spec(port_spec: str) -> list:
    """Parses comma-separated individual ports and ranges (e.g., '22,80,440-445')."""
    if not port_spec or not port_spec.strip():
        raise ConfigurationError("Port specification string cannot be empty.")

    parsed_ports = set()
    tokens = [token.strip() for token in port_spec.split(",") if token.strip()]

    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ConfigurationError(f"Malformed port range '{token}'. Expected 'start-end' (e.g., 8000-8010).")
            start_port, end_port = int(parts[0]), int(parts[1])
            if start_port > end_port:
                raise ConfigurationError(f"Invalid port range '{token}': start ({start_port}) > end ({end_port}).")
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ConfigurationError(f"Port range '{token}' out of valid TCP bounds (1-65535).")
            parsed_ports.update(range(start_port, end_port + 1))
        else:
            if not token.isdigit():
                raise ConfigurationError(f"Invalid port value '{token}': must be an integer (1-65535).")
            port_num = int(token)
            if not (1 <= port_num <= 65535):
                raise ConfigurationError(f"Port '{port_num}' out of valid TCP bounds (1-65535).")
            parsed_ports.add(port_num)

    if not parsed_ports:
        raise ConfigurationError("No valid TCP ports remained after parsing input.")

    return sorted(parsed_ports)

def _probe_single_port(host: str, resolved_ip: str, port: int) -> dict | None:
    """Worker function to probe a single TCP port on a resolved endpoint."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            if sock.connect_ex((resolved_ip, port)) == 0:
                return {
                    "module": "port_checker",
                    "target": host,
                    "severity": "INFO",
                    "category": "Active Listening Service",
                    "detail": f"Port {port} is open and listening on {host} ({resolved_ip}). Verify firewall rules.",
                    "framework": "CIS Control 4.4 / NIST CSF PR.IP-1"
                }
    except PermissionError as exc:
        logger.error(f"Insufficient OS permissions probing {host}:{port}: {exc}")
    except OSError as exc:
        logger.error(f"Network/OS error probing {host}:{port}: {exc}")
    return None

def check_ports_on_host(host: str, target_ports: list, max_workers: int = 20) -> list:
    """Concurrently scans all target ports on a single host."""
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise TargetUnreachableError(f"DNS resolution failed for target host '{host}': {exc}") from exc

    logger.info(f"Scanning {len(target_ports)} TCP port(s) on {host} ({resolved_ip})...")
    findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_probe_single_port, host, resolved_ip, port) for port in target_ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    return sorted(findings, key=lambda x: x["detail"])

def check_multiple_hosts(hosts: list, ports: list = None, max_workers: int = 10) -> list:
    """Concurrently audits multiple endpoints at once."""
    if not hosts:
        raise ConfigurationError("At least one target host must be provided.")

    target_ports = list(ports) if ports is not None else list(DEFAULT_PORTS)
    if not target_ports:
        raise ConfigurationError("No ports configured for scanning.")

    all_findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(check_ports_on_host, host, target_ports): host
            for host in hosts
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                all_findings.extend(future.result())
            except TargetUnreachableError as exc:
                logger.error(f"Endpoint skipped ({host}): {exc}")

    return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python -m checks.port_checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Standalone Concurrent Multi-Endpoint TCP Port Checker\n"
            "-----------------------------------------------------\n"
            "Probes specified TCP ports and port ranges across one or more target hosts\n"
            "concurrently and maps active listening services to CIS Control 4.4 / NIST CSF PR.IP-1."
        ),
        epilog=(
            "Examples:\n"
            "  python -m checks.port_checker --hosts 127.0.0.1 localhost --ports \"22,80,443,1430-1435\"\n"
            "  python -m checks.port_checker --hosts 10.0.0.12 --ports \"3389\""
        )
    )
    parser.add_argument(
        "--hosts",
        nargs="+",
        metavar="HOST",
        default=["127.0.0.1"],
        help="Space-separated target IP addresses or hostnames. Format: HOST [HOST ...] (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--ports",
        metavar="PORTS",
        default=None,
        help="Comma-separated TCP ports (1-65535) and/or ranges. Format: \"22,80,8000-8010\" (default: 22,80,443,445,1433,3389)"
    )
    args = parser.parse_args()

    try:
        custom_ports = parse_port_spec(args.ports) if args.ports else None
        results = check_multiple_hosts(args.hosts, custom_ports)
        print(json.dumps(results, indent=2))
    except ConfigurationError as err:
        logger.error(f"Configuration Error: {err}")
        exit(2)