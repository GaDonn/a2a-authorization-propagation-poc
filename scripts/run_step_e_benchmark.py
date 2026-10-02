from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
    attach_secure_passport_v1,
    create_caller_context,
    verify_secure_passport_v1,
)
from common.agent_keys import load_agent_identity
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
    InMemoryReplayCache,
    add_delegation_entry,
    attach_extended_secure_passport,
    consume_authorization_nonce,
    create_extended_secure_passport,
    verify_authorization_details_binding,
    verify_delegation_chain,
    verify_extended_secure_passport,
)
from common.request_authentication import (
    create_request_authentication,
    verify_request_authentication,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "benchmark"
)
DEFAULT_RUNS = 30

TEXT = "Hospital validated Claim/claim-001."

AUTHORIZATION_DETAILS = [
    {
        "type": "healthcare_reimbursement",
        "identifier": "authz-claim-001",
        "actions": ["request_reimbursement"],
        "beneficiary": {
            "reference": "Patient/patient-001",
        },
        "claim": {
            "reference": "Claim/claim-001",
        },
        "coverage": {
            "reference": "Coverage/coverage-basic-001",
        },
        "treatment": {
            "system": (
                "https://example.org/fhir/"
                "CodeSystem/treatment"
            ),
            "code": "T123",
        },
        "maximum_amount": {
            "value": "120",
            "currency": "EUR",
        },
        "constraints": {
            "permitted_destination": "insurance-agent",
            "permitted_hops": [
                "patient-agent",
                "hospital-agent",
                "insurance-agent",
            ],
            "max_agent_hops": 2,
        },
    }
]

HEALTHCARE_RESOURCES = {
    "modelVersion": "1.0",
    "resources": {
        "claim": {
            "resourceType": "Claim",
            "id": "claim-001",
            "patient": {
                "reference": "Patient/patient-001",
            },
            "insurance": [
                {
                    "coverage": {
                        "reference": (
                            "Coverage/coverage-basic-001"
                        )
                    },
                    "focal": True,
                    "sequence": 1,
                }
            ],
            "total": {
                "value": "120",
                "currency": "EUR",
            },
        }
    },
}

HOSPITAL_VALIDATION = {
    "status": "validated",
    "claim_reference": "Claim/claim-001",
}

HOSPITAL_PROVENANCE = {
    "agent": "hospital-agent",
    "activity": "claim_validation",
}


@dataclass(frozen=True)
class Condition:
    configuration: str
    scenario: str


CONDITIONS = (
    Condition("C0_baseline", "benign"),
    Condition("C1_secure_passport_v1", "benign"),
    Condition("C2_extended_secure_passport", "benign"),
    Condition("C3_extended_plus_per_hop_security", "benign"),
    Condition("C3_extended_plus_per_hop_security", "modified_text"),
    Condition("C3_extended_plus_per_hop_security", "modified_metadata"),
    Condition("C3_extended_plus_per_hop_security", "sender_impersonation"),
    Condition("C3_extended_plus_per_hop_security", "request_replay"),
    Condition("C3_extended_plus_per_hop_security", "authorization_artifact_replay"),
)

CSV_FIELDS = (
    "configuration",
    "scenario",
    "run_id",
    "serialized_benchmark_payload_size_bytes",
    "signing_time_ms",
    "verification_time_ms",
    "local_security_pipeline_latency_ms",
    "accepted",
    "rejection_reason",
    "security_check",
    "detection_layer",
    "request_nonce",
    "authorization_nonce",
    "latency_scope",
    "size_scope",
)


def elapsed_ms(start_ns: int) -> float:
    return (
        time.perf_counter_ns() - start_ns
    ) / 1_000_000


def serialized_size_bytes(
    *,
    text: str,
    metadata: dict[str, Any],
) -> int:
    return len(
        json.dumps(
            {
                "text": text,
                "metadata": metadata,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def build_upstream_extended_artifact(
    *,
    now: int,
) -> tuple[dict[str, Any], str]:
    """
    Build the C2 authorization artifact as it would exist after
    Patient -> Hospital, before Hospital adds its own downstream hop.

    This setup is outside the measured Hospital -> Insurance pipeline.
    """
    origin = create_caller_context(
        client_id="patient-agent",
        session_id="reimbursement-session-001",
        state={
            "patient_reference": "Patient/patient-001",
            "coverage_reference": (
                "Coverage/coverage-basic-001"
            ),
            "claim_reference": "Claim/claim-001",
            "consent": True,
        },
        sign_state=True,
    )

    artifact = create_extended_secure_passport(
        origin_caller_context=origin,
        authorization_details=deepcopy(
            AUTHORIZATION_DETAILS
        ),
        now=now,
        nonce=f"auth-{uuid4()}",
    )

    artifact = add_delegation_entry(
        artifact,
        from_agent="patient-agent",
        to_agent="hospital-agent",
        scope=[
            "request_reimbursement",
            "send_to_hospital",
        ],
        now=now,
    )

    return artifact, artifact["nonce"]


def build_c1_metadata(
    *,
    now: int,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()

    metadata: dict[str, Any] = {
        "healthcare_resources": deepcopy(
            HEALTHCARE_RESOURCES
        ),
        "hospital_validation": deepcopy(
            HOSPITAL_VALIDATION
        ),
        "hospital_provenance": deepcopy(
            HOSPITAL_PROVENANCE
        ),
    }

    hospital_context = create_caller_context(
        client_id="hospital-agent",
        session_id="reimbursement-session-001",
        state={
            "claim_reference": "Claim/claim-001",
            "patient_reference": "Patient/patient-001",
            "coverage_reference": (
                "Coverage/coverage-basic-001"
            ),
            "validation_status": "validated",
            "source_context_client_id": (
                "patient-agent"
            ),
        },
        sign_state=True,
    )

    attach_secure_passport_v1(
        metadata,
        hospital_context,
    )

    return metadata, elapsed_ms(started)


def build_c2_metadata(
    *,
    now: int,
) -> tuple[
    dict[str, Any],
    float,
    str,
]:
    upstream_artifact, authorization_nonce = (
        build_upstream_extended_artifact(
            now=now
        )
    )

    started = time.perf_counter_ns()

    metadata, _ = build_c1_metadata(
        now=now
    )

    updated = add_delegation_entry(
        upstream_artifact,
        from_agent="hospital-agent",
        to_agent="insurance-agent",
        scope=[
            "validate_claim",
            "request_insurance_authorization",
        ],
        now=now,
    )

    metadata["authorization_details"] = (
        deepcopy(AUTHORIZATION_DETAILS)
    )

    attach_extended_secure_passport(
        metadata,
        updated,
    )

    return (
        metadata,
        elapsed_ms(started),
        authorization_nonce,
    )


def verify_c1(
    metadata: dict[str, Any],
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()

    result = verify_secure_passport_v1(
        metadata,
        expected_client_id="hospital-agent",
        require_signature=True,
    )

    return result, elapsed_ms(started)


def verify_c2(
    metadata: dict[str, Any],
    *,
    replay_cache: (
        InMemoryReplayCache | None
    ) = None,
    now: int,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()

    c1 = verify_secure_passport_v1(
        metadata,
        expected_client_id="hospital-agent",
        require_signature=True,
    )
    if not c1["valid"]:
        return c1, elapsed_ms(started)

    artifact = metadata.get(
        EXTENDED_SECURE_PASSPORT_URI
    )

    c2 = verify_extended_secure_passport(
        artifact,
        replay_cache=replay_cache,
        now=now,
    )
    if not c2["valid"]:
        return c2, elapsed_ms(started)

    binding = (
        verify_authorization_details_binding(
            artifact,
            metadata[
                "authorization_details"
            ],
        )
    )
    if not binding["valid"]:
        return binding, elapsed_ms(started)

    delegation = verify_delegation_chain(
        artifact
    )
    if not delegation["valid"]:
        return (
            delegation,
            elapsed_ms(started),
        )

    return {
        "valid": True,
        "reason": (
            "C1 and C2 security checks valid"
        ),
    }, elapsed_ms(started)


def create_c3_envelope(
    *,
    metadata: dict[str, Any],
    message_id: str,
    now: int,
    nonce: str,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()

    envelope = create_request_authentication(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id=message_id,
        text=TEXT,
        metadata=metadata,
        identity=load_agent_identity(
            "hospital-agent"
        ),
        now=now,
        ttl_seconds=60,
        nonce=nonce,
    )

    return envelope, elapsed_ms(started)


def verify_c3(
    *,
    envelope: dict[str, Any],
    metadata: dict[str, Any],
    message_id: str,
    text: str = TEXT,
    replay_cache: set[str] | None = None,
    consume_nonce: bool = False,
    now: int,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()

    result = verify_request_authentication(
        envelope=envelope,
        expected_sender_id="hospital-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id=message_id,
        text=text,
        metadata=metadata,
        replay_cache=replay_cache,
        consume_nonce=consume_nonce,
        now=now,
    )

    return result, elapsed_ms(started)


def row_base(
    *,
    condition: Condition,
    run_id: int,
) -> dict[str, Any]:
    return {
        "configuration": condition.configuration,
        "scenario": condition.scenario,
        "run_id": run_id,
        "serialized_benchmark_payload_size_bytes": 0,
        "signing_time_ms": 0.0,
        "verification_time_ms": 0.0,
        "local_security_pipeline_latency_ms": 0.0,
        "accepted": False,
        "rejection_reason": "",
        "security_check": "",
        "detection_layer": "",
        "request_nonce": "",
        "authorization_nonce": "",
        "latency_scope": (
            "local_security_pipeline_only"
        ),
        "size_scope": (
            "serialized_local_benchmark_payload_"
            "not_http_wire_bytes"
        ),
    }


def run_condition(
    condition: Condition,
    *,
    run_id: int,
) -> dict[str, Any]:
    row = row_base(
        condition=condition,
        run_id=run_id,
    )

    now = 1_700_000_000 + run_id
    pipeline_start = time.perf_counter_ns()

    if condition.configuration == (
        "C0_baseline"
    ):
        metadata = {
            "healthcare_resources": deepcopy(
                HEALTHCARE_RESOURCES
            ),
            "hospital_validation": deepcopy(
                HOSPITAL_VALIDATION
            ),
            "hospital_provenance": deepcopy(
                HOSPITAL_PROVENANCE
            ),
        }

        row["serialized_benchmark_payload_size_bytes"] = (
            serialized_size_bytes(
                text=TEXT,
                metadata=metadata,
            )
        )
        row["accepted"] = True
        row["security_check"] = "none"
        row["detection_layer"] = "baseline"

    elif condition.configuration == (
        "C1_secure_passport_v1"
    ):
        metadata, signing_ms = (
            build_c1_metadata(
                now=now
            )
        )
        verification, verification_ms = (
            verify_c1(metadata)
        )

        row["signing_time_ms"] = signing_ms
        row["verification_time_ms"] = (
            verification_ms
        )
        row["serialized_benchmark_payload_size_bytes"] = (
            serialized_size_bytes(
                text=TEXT,
                metadata=metadata,
            )
        )
        row["accepted"] = bool(
            verification["valid"]
        )
        row["rejection_reason"] = (
            ""
            if verification["valid"]
            else verification["reason"]
        )
        row["security_check"] = (
            "secure_passport_v1"
        )
        row["detection_layer"] = "C1"

    else:
        metadata, c2_signing_ms, auth_nonce = (
            build_c2_metadata(
                now=now
            )
        )
        row["authorization_nonce"] = (
            auth_nonce
        )

        if condition.configuration == (
            "C2_extended_secure_passport"
        ):
            verification, verification_ms = (
                verify_c2(
                    metadata,
                    now=now + 1,
                )
            )

            row["signing_time_ms"] = (
                c2_signing_ms
            )
            row["verification_time_ms"] = (
                verification_ms
            )
            row["serialized_benchmark_payload_size_bytes"] = (
                serialized_size_bytes(
                    text=TEXT,
                    metadata=metadata,
                )
            )
            row["accepted"] = bool(
                verification["valid"]
            )
            row["rejection_reason"] = (
                ""
                if verification["valid"]
                else verification["reason"]
            )
            row["security_check"] = (
                "extended_secure_passport"
            )
            row["detection_layer"] = "C2"

        else:
            message_id = (
                f"step-e-{run_id}-{uuid4()}"
            )
            request_nonce = (
                f"req-{uuid4()}"
            )
            row["request_nonce"] = (
                request_nonce
            )

            envelope, request_signing_ms = (
                create_c3_envelope(
                    metadata=metadata,
                    message_id=message_id,
                    now=now,
                    nonce=request_nonce,
                )
            )

            signed_metadata = deepcopy(
                metadata
            )
            signed_metadata[
                "request_authentication"
            ] = envelope

            row["signing_time_ms"] = (
                c2_signing_ms
                + request_signing_ms
            )
            row[
                "serialized_benchmark_payload_size_bytes"
            ] = serialized_size_bytes(
                text=TEXT,
                metadata=signed_metadata,
            )

            scenario = condition.scenario

            if scenario == "benign":
                request_result, request_verify_ms = (
                    verify_c3(
                        envelope=envelope,
                        metadata=metadata,
                        message_id=message_id,
                        now=now + 1,
                    )
                )

                if request_result["valid"]:
                    c2_result, c2_verify_ms = (
                        verify_c2(
                            metadata,
                            now=now + 1,
                        )
                    )
                    final = c2_result
                    verification_ms = (
                        request_verify_ms
                        + c2_verify_ms
                    )
                else:
                    final = request_result
                    verification_ms = (
                        request_verify_ms
                    )

                row["verification_time_ms"] = (
                    verification_ms
                )
                row["accepted"] = bool(
                    final["valid"]
                )
                row["rejection_reason"] = (
                    ""
                    if final["valid"]
                    else final["reason"]
                )
                row["security_check"] = (
                    "C3_request_plus_C2_authorization"
                )
                row["detection_layer"] = (
                    "C3+C2"
                )

            elif scenario == "modified_text":
                result, verification_ms = (
                    verify_c3(
                        envelope=envelope,
                        metadata=metadata,
                        message_id=message_id,
                        text=(
                            "Tampered hospital message"
                        ),
                        now=now + 1,
                    )
                )
                row["verification_time_ms"] = (
                    verification_ms
                )
                row["accepted"] = bool(
                    result["valid"]
                )
                row["rejection_reason"] = (
                    result["reason"]
                )
                row["security_check"] = (
                    "text_digest"
                )
                row["detection_layer"] = "C3"

            elif scenario == "modified_metadata":
                tampered = deepcopy(metadata)
                tampered[
                    EXTENDED_SECURE_PASSPORT_URI
                ][
                    "authorizationDetailsHash"
                ] = "0" * 64

                result, verification_ms = (
                    verify_c3(
                        envelope=envelope,
                        metadata=tampered,
                        message_id=message_id,
                        now=now + 1,
                    )
                )
                row["verification_time_ms"] = (
                    verification_ms
                )
                row["accepted"] = bool(
                    result["valid"]
                )
                row["rejection_reason"] = (
                    result["reason"]
                )
                row["security_check"] = (
                    "protected_metadata_digest"
                )
                row["detection_layer"] = "C3"

            elif scenario == (
                "sender_impersonation"
            ):
                attacker_envelope = (
                    create_request_authentication(
                        sender_id=(
                            "reimbursement-client"
                        ),
                        receiver_id=(
                            "insurance-agent"
                        ),
                        message_id=message_id,
                        text=TEXT,
                        metadata=metadata,
                        identity=load_agent_identity(
                            "reimbursement-client"
                        ),
                        now=now,
                        ttl_seconds=60,
                        nonce=request_nonce,
                    )
                )

                attacker_envelope[
                    "sender_id"
                ] = "hospital-agent"
                attacker_envelope[
                    "key_id"
                ] = "hospital-agent-ed25519-v1"

                result, verification_ms = (
                    verify_c3(
                        envelope=(
                            attacker_envelope
                        ),
                        metadata=metadata,
                        message_id=message_id,
                        now=now + 1,
                    )
                )
                row["verification_time_ms"] = (
                    verification_ms
                )
                row["accepted"] = bool(
                    result["valid"]
                )
                row["rejection_reason"] = (
                    result["reason"]
                )
                row["security_check"] = (
                    "request_signature"
                )
                row["detection_layer"] = "C3"

            elif scenario == "request_replay":
                request_cache: set[str] = set()

                first, _ = verify_c3(
                    envelope=envelope,
                    metadata=metadata,
                    message_id=message_id,
                    replay_cache=request_cache,
                    consume_nonce=True,
                    now=now + 1,
                )

                started = time.perf_counter_ns()
                second = (
                    verify_request_authentication(
                        envelope=envelope,
                        expected_sender_id=(
                            "hospital-agent"
                        ),
                        expected_receiver_id=(
                            "insurance-agent"
                        ),
                        expected_message_id=(
                            message_id
                        ),
                        text=TEXT,
                        metadata=metadata,
                        replay_cache=request_cache,
                        consume_nonce=True,
                        now=now + 1,
                    )
                )
                second_verify_ms = elapsed_ms(
                    started
                )

                result = second
                row["verification_time_ms"] = (
                    second_verify_ms
                )
                row["accepted"] = bool(
                    result["valid"]
                )
                row["rejection_reason"] = (
                    result["reason"]
                )
                row["security_check"] = (
                    "request_nonce"
                )
                row["detection_layer"] = "C3"

                if not first["valid"]:
                    raise RuntimeError(
                        "request replay control "
                        "first attempt failed"
                    )

            elif scenario == (
                "authorization_artifact_replay"
            ):
                artifact = metadata[
                    EXTENDED_SECURE_PASSPORT_URI
                ]
                auth_cache = (
                    InMemoryReplayCache()
                )

                first = (
                    verify_extended_secure_passport(
                        artifact,
                        replay_cache=auth_cache,
                        now=now + 1,
                    )
                )
                if not first["valid"]:
                    raise RuntimeError(
                        "authorization replay control "
                        "first attempt failed"
                    )

                consumed = (
                    consume_authorization_nonce(
                        artifact,
                        auth_cache,
                    )
                )
                if not consumed["valid"]:
                    raise RuntimeError(
                        "authorization nonce "
                        "consumption failed"
                    )

                started = time.perf_counter_ns()
                result = (
                    verify_extended_secure_passport(
                        artifact,
                        replay_cache=auth_cache,
                        now=now + 1,
                    )
                )
                verification_ms = elapsed_ms(
                    started
                )

                row["verification_time_ms"] = (
                    verification_ms
                )
                row["accepted"] = bool(
                    result["valid"]
                )
                row["rejection_reason"] = (
                    result["reason"]
                )
                row["security_check"] = (
                    "authorization_nonce"
                )
                row["detection_layer"] = "C2"

            else:
                raise ValueError(
                    f"Unknown scenario: {scenario}"
                )

    row[
        "local_security_pipeline_latency_ms"
    ] = elapsed_ms(pipeline_start)

    return row


def run_benchmark(
    *,
    runs: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for condition in CONDITIONS:
        for run_id in range(runs):
            rows.append(
                run_condition(
                    condition,
                    run_id=run_id,
                )
            )

    return rows


def validate_rows(
    rows: list[dict[str, Any]],
    *,
    runs: int,
) -> dict[str, Any]:
    benign_failures = [
        row
        for row in rows
        if row["scenario"] == "benign"
        and not row["accepted"]
    ]

    attack_acceptances = [
        row
        for row in rows
        if row["scenario"] != "benign"
        and row["accepted"]
    ]

    expected = len(CONDITIONS) * runs

    return {
        "expected_rows": expected,
        "observed_rows": len(rows),
        "benign_failure_count": len(
            benign_failures
        ),
        "attack_acceptance_count": len(
            attack_acceptances
        ),
        "valid": (
            len(rows) == expected
            and not benign_failures
            and not attack_acceptances
        ),
    }


def write_outputs(
    *,
    rows: list[dict[str, Any]],
    output_dir: Path,
    runs: int,
) -> None:
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    csv_path = (
        output_dir
        / "step_e_benchmark.csv"
    )

    with csv_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDS,
        )
        writer.writeheader()
        writer.writerows(rows)

    validation = validate_rows(
        rows,
        runs=runs,
    )

    summary = {
        "runs_per_condition": runs,
        "condition_count": len(CONDITIONS),
        "row_validation": validation,
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
        / "step_e_benchmark_summary.json"
    ).write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        f"Rows: {len(rows)}"
    )
    print(
        f"Validation: {validation['valid']}"
    )
    print(
        f"CSV: {csv_path}"
    )

    if not validation["valid"]:
        raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.runs <= 0:
        raise ValueError(
            "--runs must be positive"
        )

    rows = run_benchmark(
        runs=args.runs,
    )

    write_outputs(
        rows=rows,
        output_dir=args.output_dir,
        runs=args.runs,
    )


if __name__ == "__main__":
    main()
