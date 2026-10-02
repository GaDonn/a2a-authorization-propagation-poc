from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "benchmark"
)
BENCHMARK_SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "run_step_e_benchmark.py"
)

TRACKED = (
    "common",
    "patient_agent",
    "hospital_agent",
    "insurance_agent",
    "scripts/run_step_e_benchmark.py",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest() -> dict[str, str]:
    files: list[Path] = []

    for relative in TRACKED:
        path = PROJECT_ROOT / relative

        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                candidate
                for candidate in path.rglob(
                    "*.py"
                )
                if "__pycache__"
                not in candidate.parts
            )

    return {
        str(
            path.relative_to(
                PROJECT_ROOT
            )
        ): sha256_file(path)
        for path in sorted(
            set(files)
        )
    }


def run_capture(
    command: list[str],
) -> dict:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runs",
        type=int,
        default=100,
    )
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args()

    runs = args.runs
    if runs <= 0:
        raise ValueError("--runs must be positive")
    output_dir = args.output_dir

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = {
        "captured_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "python_version": platform.python_version(),
        "installed_packages": sorted(
            f"{package.metadata['Name']}=={package.version}"
            for package in importlib.metadata.distributions()
        ),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
        },
        "latency_scope": (
            "local_security_pipeline_only"
        ),
        "size_scope": (
            "serialized_local_benchmark_payload_"
            "not_http_wire_bytes"
        ),
    }

    (
        output_dir
        / "environment.json"
    ).write_text(
        json.dumps(
            environment,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    before = build_manifest()
    (
        output_dir
        / "code_manifest_before.json"
    ).write_text(
        json.dumps(
            before,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    started = datetime.now(
        timezone.utc
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(BENCHMARK_SCRIPT),
            "--runs",
            str(runs),
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        check=False,
    )

    finished = datetime.now(
        timezone.utc
    )

    after = build_manifest()
    (
        output_dir
        / "code_manifest_after.json"
    ).write_text(
        json.dumps(
            after,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Step E final benchmark failed."
        )

    summary = json.loads(
        (
            output_dir
            / "step_e_benchmark_summary.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    code_unchanged = (
        before == after
    )

    report = {
        "benchmark": (
            "step_e_corrected_final_benchmark"
        ),
        "runs_per_condition": runs,
        "condition_count": 9,
        "started_at_utc": (
            started.isoformat()
        ),
        "finished_at_utc": (
            finished.isoformat()
        ),
        "duration_seconds": (
            finished - started
        ).total_seconds(),
        "code_unchanged_during_run": (
            code_unchanged
        ),
        "row_validation": summary[
            "row_validation"
        ],
        "latency_scope": (
            "local_security_pipeline_only"
        ),
        "size_scope": (
            "serialized_local_benchmark_payload_"
            "not_http_wire_bytes"
        ),
        "passed": (
            code_unchanged
            and summary[
                "row_validation"
            ]["valid"]
        ),
    }

    (
        output_dir
        / "step_e_final_benchmark_report.json"
    ).write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        f"Runs per condition: {runs}"
    )
    print(
        "Code unchanged: "
        f"{code_unchanged}"
    )
    print(
        "Row validation: "
        f"{summary['row_validation']['valid']}"
    )
    print(
        "Overall: "
        + (
            "PASS"
            if report["passed"]
            else "FAIL"
        )
    )

    raise SystemExit(
        0 if report["passed"] else 1
    )


if __name__ == "__main__":
    main()
