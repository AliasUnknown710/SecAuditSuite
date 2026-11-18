import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from checks.exceptions import ConfigurationError, TargetUnreachableError, SecurityAuditError, setup_logger
from checks.log_auditor import audit_multiple_logs
from checks.secret_scanner import scan_multiple_paths
from checks.port_checker import check_multiple_hosts, parse_port_spec

logger = setup_logger("SecAudit.Orchestrator")

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="main_auditor.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Modular Security Posture & Threat Hunting Suite\n"
            "-------------------------------------------------\n"
            "Concurrently audits Windows/JSONL security logs, scans configuration files/trees\n"
            "for hardcoded credentials, and probes TCP endpoints for exposed listening ports.\n"
            "If no module flag (--logs, --secrets, --ports) is specified, all modules run by default."
        ),
        epilog=(
            "Command Syntax & Usage Examples:\n"
            "  1. Run full suite across multiple hosts, custom port ranges, and directories:\n"
            "     python main_auditor.py --all --hosts 127.0.0.1 10.0.1.5 --port-list \"22,80,443,1430-1435\" --log-files data/ --config-paths data/\n\n"
            "  2. Run only secret scanning across multiple specific files and folders:\n"
            "     python main_auditor.py --secrets --config-paths data/mock_config.ini /etc/app_configs/\n\n"
            "  3. Run log auditing and port checks together:\n"
            "     python main_auditor.py --logs --ports --log-files data/sample_logs.jsonl --hosts localhost --port-list \"3389,5432\"\n\n"
            "Exit Codes:\n"
            "  0 = Success | 1 = Runtime/Audit Error | 2 = Configuration/Input Error | 3 = Target Unreachable"
        )
    )

    module_group = parser.add_argument_group("Audit Module Selection (Optional - defaults to all)")
    module_group.add_argument("--all", action="store_true", help="Explicitly run all security audit modules concurrently.")
    module_group.add_argument("--logs", action="store_true", help="Enable the Windows/JSONL security log auditor.")
    module_group.add_argument("--secrets", action="store_true", help="Enable the regex hardcoded credential & secret scanner.")
    module_group.add_argument("--ports", action="store_true", help="Enable the concurrent multi-host TCP port checker.")

    target_group = parser.add_argument_group("Target & Input Configuration")
    target_group.add_argument(
        "--log-files",
        nargs="+",
        metavar="PATH",
        default=["data/sample_logs.jsonl"],
        help="Space-separated paths to .jsonl log files or directories (searched recursively). Format: PATH [PATH ...] (default: data/sample_logs.jsonl)"
    )
    target_group.add_argument(
        "--config-paths",
        nargs="+",
        metavar="PATH",
        default=["data/mock_config.ini"],
        help="Space-separated paths to config files or directories to scan recursively (.ini, .env, .json, .yaml, .conf, .py). Format: PATH [PATH ...] (default: data/mock_config.ini)"
    )
    target_group.add_argument(
        "--hosts",
        nargs="+",
        metavar="HOST",
        default=["127.0.0.1"],
        help="Space-separated target IPv4 addresses or hostnames to probe. Format: HOST [HOST ...] (default: 127.0.0.1)"
    )
    target_group.add_argument(
        "--port-list",
        metavar="PORTS",
        default=None,
        help="Comma-separated individual TCP ports (1-65535) and/or hyphenated ranges with no spaces (or quoted). Format: \"22,80,443,1430-1435\" (default: 22,80,443,445,1433,3389)"
    )

    args = parser.parse_args()
    run_all = args.all or not (args.logs or args.secrets or args.ports)

    try:
        target_ports = parse_port_spec(args.port_list) if args.port_list else None
        tasks = {}
        findings = []

        # Execute all selected audit modules concurrently
        with ThreadPoolExecutor(max_workers=3) as executor:
            if run_all or args.logs:
                tasks[executor.submit(audit_multiple_logs, args.log_files)] = "Log Auditor"
            if run_all or args.secrets:
                tasks[executor.submit(scan_multiple_paths, args.config_paths)] = "Secret Scanner"
            if run_all or args.ports:
                tasks[executor.submit(check_multiple_hosts, args.hosts, target_ports)] = "Port Checker"

            for future in as_completed(tasks):
                module_name = tasks[future]
                findings.extend(future.result())
                logger.info(f"Completed module: {module_name}")

        print("\n" + "=" * 70)
        print(f"SECURITY AUDIT SUITE | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        if not findings:
            print("[+] No anomalies detected across selected modules.")
        else:
            for idx, item in enumerate(findings, start=1):
                print(f"\n[{idx}] [{item['severity']}] ({item['module']}) Target: {item['target']}")
                print(f"    Category  : {item['category']}")
                print(f"    Finding   : {item['detail']}")
                print(f"    Compliance: {item['framework']}")

        # Append-only historical audit log
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        report_path = output_dir / "audit_history.jsonl"

        audit_record = {
            "run_timestamp": datetime.now().isoformat(),
            "targets": {
                "hosts": args.hosts,
                "ports": target_ports if target_ports else "DEFAULT_PORTS",
                "log_paths": args.log_files,
                "config_paths": args.config_paths
            },
            "modules_executed": {
                "logs": bool(run_all or args.logs),
                "secrets": bool(run_all or args.secrets),
                "ports": bool(run_all or args.ports)
            },
            "total_findings": len(findings),
            "findings": findings
        }

        file_existed = report_path.exists()
        with open(report_path, "a", encoding="utf-8") as out:
            out.write(json.dumps(audit_record) + "\n")

        action = "Appended run to existing" if file_existed else "Created new"
        print("\n" + "=" * 70)
        print(f"Audit complete. {action} audit log: {report_path}")
        print("=" * 70)
        return 0

    except ConfigurationError as exc:
        logger.error(f"CONFIGURATION ERROR: {exc}")
        return 2
    except TargetUnreachableError as exc:
        logger.error(f"TARGET UNREACHABLE ERROR: {exc}")
        return 3
    except SecurityAuditError as exc:
        logger.error(f"AUDIT FAILURE: {exc}")
        return 1
    except Exception as exc:
        logger.critical(f"UNHANDLED SYSTEM EXCEPTION: {exc}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())