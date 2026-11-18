"""
Security Audit Check Modules Package.

Exposes concurrent, standalone-capable threat hunting and posture auditing modules:
- log_auditor: Windows/JSONL brute-force and privilege escalation detection
- secret_scanner: Recursive regex scanner for hardcoded credentials and keys
- port_checker: Multi-host concurrent TCP port and range exposure scanner
"""

from checks.log_auditor import audit_multiple_logs
from checks.secret_scanner import scan_multiple_paths
from checks.port_checker import check_multiple_hosts, parse_port_spec

__all__ = [
    "audit_multiple_logs",
    "scan_multiple_paths",
    "check_multiple_hosts",
    "parse_port_spec",
]