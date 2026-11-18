# Modular Security Posture & Threat Hunting Suite

## Executive Summary
Organizations managing sensitive financial, payroll, and project data require continuous visibility into authentication anomalies, exposed network services, and plaintext credential leaks. Manual log triage and ad-hoc configuration reviews introduce operational delays and compliance gaps.

This Python security automation suite provides **concurrent, multi-endpoint threat hunting and posture auditing**. Every technical finding is automatically mapped to **CIS Controls v8** and the **NIST Cybersecurity Framework (CSF)** and written to an append-only JSONL audit trail—bridging daily security operations with Governance, Risk, and Compliance (GRC) reporting.

---

## Key Architectural Features
* **Two-Tier Concurrency (`ThreadPoolExecutor`):** Executes audit modules in parallel while simultaneously scanning multiple endpoints, log directories, and configuration trees.
* **Dual Execution Modes:** Run the full suite from the central orchestrator (`main_auditor.py`) or invoke individual sub-modules (`checks/*.py`) standalone during targeted incident response.
* **Flexible Port & Target Specification:** Supports scanning multiple hosts (`--hosts`), directory trees (`--log-files`, `--config-paths`), and mixed individual/ranged TCP ports (`--port-list "22,80,443,1430-1435"`).
* **Enterprise Error Handling:** Uses custom exception hierarchies (`ConfigurationError`, `TargetUnreachableError`), structured logging, and standardized exit codes (`0`, `1`, `2`, `3`).
* **Append-Only SIEM-Ready Audit Trail:** Appends structured JSON records to `output/audit_history.jsonl` without overwriting historical test or production runs.

---

## Project Structure
```text
foundation-sec-audit/
├── checks/
│   ├── __init__.py
│   ├── exceptions.py        # Custom exception hierarchy & enterprise logger
│   ├── log_auditor.py       # Windows/JSONL brute-force & privilege escalation hunter
│   ├── secret_scanner.py    # Recursive regex scanner for hardcoded keys/passwords
│   └── port_checker.py      # Concurrent multi-host TCP socket exposure checker
├── data/
│   ├── sample_logs.jsonl    # Sample Windows Security Event logs (4624, 4625, 4672)
│   └── mock_config.ini      # Sample configuration file for credential testing
├── output/
│   └── audit_history.jsonl  # Auto-generated append-only audit log
├── main_auditor.py          # Master CLI orchestrator
├── test_suite.py            # Automated unit test suite
└── README.md
```

---

## Usage Examples

### 1. Run the Full Suite Across Multiple Endpoints & Paths
```bash
python main_auditor.py --all \
  --hosts 127.0.0.1 localhost \
  --port-list "22,80,443,1430-1435,3389" \
  --log-files data/sample_logs.jsonl \
  --config-paths data/
```

### 2. Run Targeted Checks via Master CLI
```bash
# Hunt only for hardcoded secrets across an entire directory
python main_auditor.py --secrets --config-paths data/

# Audit specific log files and check custom port ranges
python main_auditor.py --logs --ports --log-files data/sample_logs.jsonl --port-list "8000-8010,3389"
```

### 3. Run Sub-Modules Standalone
```bash
python -m checks.secret_scanner --paths data/mock_config.ini
python -m checks.log_auditor --files data/sample_logs.jsonl
python -m checks.port_checker --hosts 127.0.0.1 localhost --ports "80,443,1433"
```

### 4. Run Automated Unit Tests
```bash
python -m unittest test_suite.py -v
```

---

## Compliance & Framework Mappings

| Detection Module | Security Check | Framework Reference |
| :--- | :--- | :--- |
| **Log Auditor** | Brute-Force Detection (`Event ID 4625` threshold) | CIS Control 8.2 / NIST CSF DE.CM-1 |
| **Log Auditor** | Special Privilege Assignment (`Event ID 4672`) | CIS Control 5.4 / NIST CSF PR.AC-4 |
| **Secret Scanner** | Plaintext API Keys, Passwords & Private Keys | CIS Control 3.11 / NIST CSF PR.DS-5 |
| **Port Checker** | Unintended Listening Services (RDP, SMB, SQL) | CIS Control 4.4 / NIST CSF PR.IP-1 |

---

## Exit Codes
* `0` — Audit completed successfully.
* `1` — General or unhandled runtime failure.
* `2` — `ConfigurationError` (missing input files, malformed port ranges, empty port configuration).
* `3` — `TargetUnreachableError` (DNS resolution failure for target endpoint).