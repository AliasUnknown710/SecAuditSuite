import json
import re
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from checks.exceptions import ConfigurationError, setup_logger

logger = setup_logger("SecAudit.SecretScanner")

PATTERNS = {
    "AWS/Cloud Access Key": r"AKIA[0-9A-Z]{16}",
    "Hardcoded Password/Secret": r"(?i)(password|secret|api_key|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{8,}['\"]?",
    "Private Key Header": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"
}

SCANNABLE_EXTENSIONS = {".ini", ".env", ".conf", ".config", ".json", ".yaml", ".yml", ".txt", ".py"}

def _resolve_target_files(paths: list) -> list:
    """Expands files and recursive directories into scannable configuration files."""
    files = []
    for raw_path in paths:
        p = Path(raw_path)
        if not p.exists():
            raise ConfigurationError(f"Target scan path does not exist: '{raw_path}'")
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for item in p.rglob("*"):
                if item.is_file() and item.suffix.lower() in SCANNABLE_EXTENSIONS:
                    files.append(item)
    if not files:
        raise ConfigurationError("No scannable configuration files found in specified path(s).")
    return files

def scan_single_file(file_path: str | Path) -> list:
    """Scans a single file for hardcoded secrets using regex rules."""
    path_obj = Path(file_path)
    if not path_obj.is_file():
        raise ConfigurationError(f"File not found: '{file_path}'")

    findings = []
    try:
        content = path_obj.read_text(encoding="utf-8", errors="ignore")
    except PermissionError as exc:
        raise ConfigurationError(f"Permission denied reading '{path_obj}': {exc}") from exc

    for label, pattern in PATTERNS.items():
        if re.search(pattern, content):
            findings.append({
                "module": "secret_scanner",
                "target": str(path_obj),
                "severity": "CRITICAL",
                "category": "Exposed Credential in Configuration",
                "detail": f"{label} detected in '{path_obj}'.",
                "framework": "CIS Control 3.11 / NIST CSF PR.DS-5"
            })

    return findings

def scan_multiple_paths(paths: list, max_workers: int = 8) -> list:
    """Concurrently scans multiple files or directory trees for exposed secrets."""
    target_files = _resolve_target_files(paths)
    logger.info(f"Scanning {len(target_files)} file(s) for exposed secrets concurrently...")
    all_findings = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_file, f): f for f in target_files}
        for future in as_completed(futures):
            all_findings.extend(future.result())

    return all_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="python -m checks.secret_scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Standalone Concurrent Configuration Secret & Credential Scanner\n"
            "---------------------------------------------------------------\n"
            "Scans files or recursive directory trees for exposed AWS keys, hardcoded passwords,\n"
            "API tokens, and private key headers, mapping findings to CIS Control 3.11 / NIST PR.DS-5."
        ),
        epilog=(
            "Supported Extensions for Directory Recursion:\n"
            "  .ini, .env, .conf, .config, .json, .yaml, .yml, .txt, .py\n\n"
            "Examples:\n"
            "  python -m checks.secret_scanner --paths data/mock_config.ini\n"
            "  python -m checks.secret_scanner --paths data/ ./configs/ .env"
        )
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        metavar="PATH",
        default=["data/mock_config.ini"],
        help="Space-separated file or directory paths to scan recursively. Format: PATH [PATH ...] (default: data/mock_config.ini)"
    )
    args = parser.parse_args()

    try:
        results = scan_multiple_paths(args.paths)
        print(json.dumps(results, indent=2))
    except ConfigurationError as err:
        logger.error(f"Configuration Error: {err}")
        exit(2)