from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = PROJECT_ROOT / "tests" / "test_authorized_intermediary_limitation.py"
OUTPUT_DIR = PROJECT_ROOT / "results" / "local" / "attacks" / "authorized_intermediary_limitation"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(TEST_FILE),
            "-v",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    report = {
        "test_file": str(TEST_FILE),
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "case": "malicious_authorized_intermediary",
        "intermediary": "hospital-agent",
        "modification": {
            "field": "authorization_details[0].maximum_amount.value",
            "original": "120",
            "modified": "9000",
        },
        "capabilities_used": [
            "shared C2 HMAC secret",
            "hospital-agent Ed25519 private key",
            "authorized append of the Hospital-to-Insurance delegation entry",
        ],
        "checks_asserted_valid": [
            "C3 request authentication",
            "Hospital Secure Passport v1 CallerContext",
            "C2 companion artifact integrity and origin verification",
            "authorization-details binding",
            "delegation-path verification",
            "insurance application validation",
        ],
        "observed_outcome": (
            "approved"
            if completed.returncode == 0
            else "test_failed"
        ),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }

    report_path = OUTPUT_DIR / "authorized_intermediary_report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    print(f"Report: {report_path}")

    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
