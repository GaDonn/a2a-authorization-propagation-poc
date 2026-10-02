from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results" / "local" / "normal_workflows"

EXPECTED_APPROVAL = (
    "Insurance approved reimbursement for Claim/claim-001"
)


@dataclass(frozen=True)
class WorkflowConfiguration:
    name: str
    mode: str
    request_authentication: str
    replay_protection: str = "off"

    def environment(self) -> dict[str, str]:
        return {
            "MODE": self.mode,
            "ATTACK": "none",
            "REQUEST_AUTHENTICATION": (
                self.request_authentication
            ),
            "REPLAY_PROTECTION": self.replay_protection,
        }


CONFIGURATIONS: tuple[WorkflowConfiguration, ...] = (
    WorkflowConfiguration(
        name="C0_baseline",
        mode="baseline",
        request_authentication="off",
    ),
    WorkflowConfiguration(
        name="C1_standard_passport",
        mode="passport",
        request_authentication="off",
    ),
    WorkflowConfiguration(
        name="C2_extended",
        mode="extended",
        request_authentication="off",
    ),
    WorkflowConfiguration(
        name="C3_extended_signed",
        mode="extended",
        request_authentication="on",
    ),
)


def wait_for_port(
    host: str,
    port: int,
    *,
    timeout_seconds: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                (host, port),
                timeout=0.5,
            ):
                return
        except OSError:
            time.sleep(0.2)

    raise TimeoutError(
        f"Service did not open {host}:{port} "
        f"within {timeout_seconds} seconds."
    )


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return

    process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def start_agent(
    module_name: str,
    environment: dict[str, str],
    log_path: Path,
) -> tuple[subprocess.Popen[str], Any]:
    log_file = log_path.open(
        "w",
        encoding="utf-8",
    )

    process_environment = os.environ.copy()
    process_environment.update(environment)
    process_environment["PYTHONUNBUFFERED"] = "1"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            module_name,
        ],
        cwd=PROJECT_ROOT,
        env=process_environment,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )

    return process, log_file


def run_client(
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    process_environment = os.environ.copy()
    process_environment.update(environment)
    process_environment["PYTHONUNBUFFERED"] = "1"

    return subprocess.run(
        [
            sys.executable,
            "test_client.py",
        ],
        cwd=PROJECT_ROOT,
        env=process_environment,
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )


def read_log(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )


def run_configuration(
    configuration: WorkflowConfiguration,
) -> dict[str, Any]:
    config_dir = RESULTS_DIR / configuration.name
    config_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = configuration.environment()

    processes: list[subprocess.Popen[str]] = []
    log_files: list[Any] = []

    try:
        insurance, insurance_log = start_agent(
            "insurance_agent",
            environment,
            config_dir / "insurance.log",
        )
        processes.append(insurance)
        log_files.append(insurance_log)
        wait_for_port("127.0.0.1", 12002)

        hospital, hospital_log = start_agent(
            "hospital_agent",
            environment,
            config_dir / "hospital.log",
        )
        processes.append(hospital)
        log_files.append(hospital_log)
        wait_for_port("127.0.0.1", 12001)

        patient, patient_log = start_agent(
            "patient_agent",
            environment,
            config_dir / "patient.log",
        )
        processes.append(patient)
        log_files.append(patient_log)
        wait_for_port("127.0.0.1", 12000)

        client = run_client(environment)

        client_output = (
            client.stdout
            + (
                "\nSTDERR:\n" + client.stderr
                if client.stderr
                else ""
            )
        )

        (config_dir / "client.log").write_text(
            client_output,
            encoding="utf-8",
        )

        success = (
            client.returncode == 0
            and EXPECTED_APPROVAL in client.stdout
        )

        return {
            "name": configuration.name,
            "mode": configuration.mode,
            "request_authentication": (
                configuration.request_authentication
            ),
            "replay_protection": (
                configuration.replay_protection
            ),
            "client_exit_code": client.returncode,
            "approved": success,
            "expected_approval_found": (
                EXPECTED_APPROVAL in client.stdout
            ),
            "client_output": client.stdout.strip(),
        }

    except Exception as error:
        return {
            "name": configuration.name,
            "mode": configuration.mode,
            "request_authentication": (
                configuration.request_authentication
            ),
            "replay_protection": (
                configuration.replay_protection
            ),
            "approved": False,
            "error": str(error),
        }

    finally:
        for process in reversed(processes):
            stop_process(process)

        for log_file in log_files:
            log_file.close()


def validate_configuration_logs(
    result: dict[str, Any],
) -> dict[str, Any]:
    config_dir = RESULTS_DIR / result["name"]

    patient_log = read_log(
        config_dir / "patient.log"
    )
    hospital_log = read_log(
        config_dir / "hospital.log"
    )
    insurance_log = read_log(
        config_dir / "insurance.log"
    )

    mode = result["mode"]
    signed = (
        result["request_authentication"] == "on"
    )

    checks: dict[str, bool] = {
        "patient_started": (
            "[patient-agent]" in patient_log
        ),
        "hospital_started": (
            "[hospital-agent]" in hospital_log
        ),
        "insurance_started": (
            "[insurance-agent]" in insurance_log
        ),
        "deterministic_decision_present": (
            "INSURANCE DETERMINISTIC DECISION"
            in insurance_log
        ),
    }

    if mode == "baseline":
        checks["baseline_hospital_path"] = (
            "Baseline mode" in hospital_log
        )
        checks["baseline_insurance_path"] = (
            "Baseline mode" in insurance_log
        )

    if mode == "passport":
        checks["hospital_passport_verified"] = (
            "STANDARD PASSPORT VERIFICATION AT HOSPITAL"
            in hospital_log
        )
        checks["insurance_passport_verified"] = (
            "STANDARD PASSPORT VERIFICATION AT INSURANCE"
            in insurance_log
        )

    if mode == "extended":
        checks["hospital_binding_verified"] = (
            "AUTHORIZATION-DETAILS BINDING CHECK AT HOSPITAL"
            in hospital_log
        )
        checks["insurance_binding_verified"] = (
            "AUTHORIZATION-DETAILS BINDING CHECK AT INSURANCE"
            in insurance_log
        )
        checks["delegation_verified"] = (
            "DELEGATION CHAIN CHECK AT INSURANCE"
            in insurance_log
        )

    if signed:
        checks["patient_fail_closed_valid"] = (
            "FAIL-CLOSED REQUEST VERIFICATION AT PATIENT"
            in patient_log
            and '"valid": true' in patient_log
        )
        checks["hospital_fail_closed_valid"] = (
            "FAIL-CLOSED REQUEST VERIFICATION AT HOSPITAL"
            in hospital_log
            and '"valid": true' in hospital_log
        )
        checks["insurance_fail_closed_valid"] = (
            "FAIL-CLOSED REQUEST VERIFICATION AT INSURANCE"
            in insurance_log
            and '"valid": true' in insurance_log
        )
    else:
        checks["no_patient_signature_check"] = (
            "FAIL-CLOSED REQUEST VERIFICATION AT PATIENT"
            not in patient_log
        )

    result["log_checks"] = checks
    result["all_log_checks_passed"] = all(
        checks.values()
    )
    result["passed"] = bool(
        result.get("approved")
        and result["all_log_checks_passed"]
    )

    return result


def main() -> None:
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results = []

    for configuration in CONFIGURATIONS:
        print(
            f"Running {configuration.name}..."
        )
        result = run_configuration(
            configuration
        )
        result = validate_configuration_logs(
            result
        )
        results.append(result)

        status = (
            "PASS" if result["passed"] else "FAIL"
        )
        print(
            f"{configuration.name}: {status}"
        )

    report = {
        "workflow": "normal benign reimbursement",
        "configurations": results,
        "all_passed": all(
            result["passed"]
            for result in results
        ),
    }

    report_path = (
        RESULTS_DIR / "normal_workflow_report.json"
    )
    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print()
    print(
        f"Report: {report_path}"
    )
    print(
        "Overall: "
        + (
            "PASS"
            if report["all_passed"]
            else "FAIL"
        )
    )

    raise SystemExit(
        0 if report["all_passed"] else 1
    )


if __name__ == "__main__":
    main()
