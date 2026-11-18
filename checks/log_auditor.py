import os
import json
import argparse
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from checks.exceptions import ConfigurationError, setup_logger

logger = setup_logger("SecAudit.LogAuditor")
FAILED_LOGIN_THRESHOLD = 3

def _resolve_log_paths(paths: list) -> list:
    """Expands a list of file or directory paths into concrete .jsonl file paths."""
    resolved_files = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ConfigurationError(f"Log path does not exist: '{raw_path}'")
        if p.is_file():
            resolved_files.append(p)
        elif p.is_dir():
            found = list(p.rglob("*.jsonl"))
            if not found:
                logger.warning(f"No .jsonl files found inside directory '{raw_path}'.")
            resolved_files.extend(found)
    if not resolved_files:
        raise ConfigurationError("No valid .jsonl log files found to audit.")
    return resolved_files

def audit_single_log(log_path: str | Path) -> list:
    """Audits a single JSONL security log file."""
    path_obj = Path(log_path)
    if not path_obj.is_file():
        raise ConfigurationError(f"Log file not found: '{log_path}'")

    findings = []
    failed_ips = Counter()

    try:
        with open(path_obj, "r", encoding="utf-8") as file:
            for line_num, line in enumerate(file, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning(f"Skipping malformed JSON on line {line_num} in '{path_obj.name}'.")
                    continue

                event_id = event.get("event_id")
                src_ip = event.get("source_ip", "Unknown")
                user = event.get("user", "Unknown")

                if event_id == 4625:
                    failed_ips[src_ip] += 1

                if event_id == 4672:
                    findings.append({
                        "module": "log_auditor",
                        "target": str(path_obj),
                        "severity": "MEDIUM",
                        "category": "Privilege Escalation Monitoring",
                        "detail": f"Special privileges assigned to '{user}' from {src_ip} in {path_obj.name} (Line {line_num}).",
                        "framework": "CIS Control 5.4 / NIST CSF PR.AC-4"
                    })
    except PermissionError as exc:
        raise ConfigurationError(f"Permission denied reading '{path_obj}': {exc}") from exc

    for ip, count in failed_ips.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            findings.append({
                "module": "log_auditor",
                "target": str(path_obj),
                "severity": "HIGH",
                "category": "Potential Brute-Force Attack",
                "detail": f"Detected {count} failed logins (Event 4625) from IP {ip} in {path_obj.name}.",
                "framework": "CIS Control 8.2 / NIST CSF DE.CM-1"
            })

    return findings

def audit_multiple_logs(paths: list, max_workers: int = 8) -> list:
    """Concurrently audits multiple log files or directories."""
    files_to_audit = _resolve_log_paths(paths)
    logger.info(f"Auditing {len(files_to_audit)} log file(s) concurrently...")
    all_findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(audit_single_log, f): f for f in files_to_audit}
        for future in as_completed(futures):
            all_findings.extend(future.result())

    return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python -m checks.log_auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Standalone Concurrent Windows/JSONL Security Log Auditor\n"
            "--------------------------------------------------------\n"
            "Parses JSON Lines (.jsonl) security event logs to detect brute-force login bursts\n"
            "(Event ID 4625) and special privilege assignments (Event ID 4672)."
        ),
        epilog=(
            "Expected JSONL Line Format:\n"
            "  {\"timestamp\": \"2026-11-17T08:12:01Z\", \"event_id\": 4625, \"user\": \"admin\", \"source_ip\": \"10.0.0.5\"}\n\n"
            "Examples:\n"
            "  python -m checks.log_auditor --files data/sample_logs.jsonl\n"
            "  python -m checks.log_auditor --files data/ /var/log/security_exports/"
        )
    )
    parser.add_argument(
        "--files",
        nargs="+",
        metavar="PATH",
        default=["data/sample_logs.jsonl"],
        help="Space-separated paths to .jsonl log files or directories (searched recursively). Format: PATH [PATH ...] (default: data/sample_logs.jsonl)"
    )
    args = parser.parse_args()

    try:
        results = audit_multiple_logs(args.files)
        print(json.dumps(results, indent=2))
    except ConfigurationError as err:
        logger.error(f"Configuration Error: {err}")
        exit(2)