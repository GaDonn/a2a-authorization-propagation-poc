from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_FILE = (
    PROJECT_ROOT
    / "tests"
    / "test_step_d_adversarial_matrix.py"
)
OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "attacks"
    / "step_d_updated_matrix"
)


def main() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

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
        "architecture": {
            "c1": (
                "A2A Secure Passport Extension v1"
            ),
            "c2": (
                "Thesis Extended Secure Passport"
            ),
            "c3": (
                "Project-specific per-hop signed "
                "A2A request envelope"
            ),
        },
        "covered_attacks": [
            "sender_impersonation",
            "modified_text",
            "modified_standard_secure_passport",
            "modified_extended_secure_passport",
            "authorization_amount_tampering",
            "authorization_beneficiary_tampering",
            "authorization_coverage_tampering",
            "authorization_treatment_tampering",
            "authorization_action_tampering",
            "unauthorized_hop",
            "destination_substitution",
            "scope_widening_policy_gap",
            "request_replay",
            "authorization_artifact_replay",
            "expired_authorization_artifact",
        ],
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }

    report_path = (
        OUTPUT_DIR
        / "step_d_adversarial_matrix_report.json"
    )

    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(completed.stdout)

    if completed.stderr:
        print(
            completed.stderr,
            file=sys.stderr,
        )

    print(
        f"Report: {report_path}"
    )

    raise SystemExit(
        completed.returncode
    )


if __name__ == "__main__":
    main()
