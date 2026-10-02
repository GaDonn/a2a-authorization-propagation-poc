from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
    create_caller_context,
)
from common.agent_keys import load_agent_identity
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
    add_delegation_entry,
    consume_authorization_nonce,
    create_extended_secure_passport,
    verify_extended_secure_passport,
)
from common.request_authentication import (
    create_request_authentication,
    verify_request_authentication,
)
from common.secure_passport import InMemoryReplayCache


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "attacks"
    / "replay_evidence_final"
)

TEXT = (
    "Hospital validated Claim/claim-001. "
    "Please process the reimbursement request."
)

AUTHORIZATION_DETAILS = [
    {
        "type": "healthcare_reimbursement",
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
            "code": "T123",
        },
        "maximum_amount": {
            "value": "120",
            "currency": "EUR",
        },
    }
]


def make_metadata() -> dict:
    origin_context = create_caller_context(
        client_id="patient-agent",
        session_id="reimbursement-session-001",
        state={
            "patient_reference": "Patient/patient-001",
            "claim_reference": "Claim/claim-001",
            "coverage_reference": (
                "Coverage/coverage-basic-001"
            ),
        },
        sign_state=True,
    )

    artifact = create_extended_secure_passport(
        origin_caller_context=origin_context,
        authorization_details=AUTHORIZATION_DETAILS,
        now=1000,
        nonce="authorization-nonce-001",
    )

    artifact = add_delegation_entry(
        artifact,
        from_agent="patient-agent",
        to_agent="hospital-agent",
        scope=[
            "request_reimbursement",
            "send_to_hospital",
        ],
        now=1001,
    )

    artifact = add_delegation_entry(
        artifact,
        from_agent="hospital-agent",
        to_agent="insurance-agent",
        scope=[
            "validate_claim",
            "request_insurance_authorization",
        ],
        now=1002,
    )

    hospital_context = create_caller_context(
        client_id="hospital-agent",
        session_id="reimbursement-session-001",
        state={
            "claim_reference": "Claim/claim-001",
            "validation_status": "validated",
        },
        sign_state=True,
    )

    return {
        "healthcare_resources": {
            "resources": {
                "claim": {
                    "resourceType": "Claim",
                    "id": "claim-001",
                }
            }
        },
        "authorization_details": deepcopy(
            AUTHORIZATION_DETAILS
        ),
        SECURE_PASSPORT_URI: (
            hospital_context.model_dump(
                by_alias=True,
                exclude_none=True,
                mode="json",
            )
        ),
        EXTENDED_SECURE_PASSPORT_URI: artifact,
        "hospital_validation": {
            "status": "validated",
        },
        "hospital_provenance": {
            "agent": "hospital-agent",
        },
    }


def sign_request(
    metadata: dict,
    *,
    message_id: str,
    nonce: str,
) -> dict:
    return create_request_authentication(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id=message_id,
        text=TEXT,
        metadata=metadata,
        identity=load_agent_identity(
            "hospital-agent"
        ),
        now=1000,
        ttl_seconds=60,
        nonce=nonce,
    )


def verify_request(
    envelope: dict,
    metadata: dict,
    *,
    message_id: str,
    replay_cache: set[str],
) -> dict:
    return verify_request_authentication(
        envelope=envelope,
        expected_sender_id="hospital-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id=message_id,
        text=TEXT,
        metadata=metadata,
        replay_cache=replay_cache,
        consume_nonce=True,
        now=1003,
    )


def envelope_summary(envelope: dict) -> dict:
    return {
        "sender_id": envelope["sender_id"],
        "receiver_id": envelope["receiver_id"],
        "message_id": envelope["message_id"],
        "key_id": envelope["key_id"],
        "nonce": envelope["nonce"],
        "created_at": envelope["created_at"],
        "expires_at": envelope["expires_at"],
        "protected_metadata_fields": (
            envelope["protected_metadata_fields"]
        ),
        "text_digest": envelope["text_digest"],
        "protected_metadata_digest": (
            envelope["protected_metadata_digest"]
        ),
        "signature": envelope["signature"],
    }


def main() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    # ---------------------------------------------------------
    # Case 1: replay of the same signed C3 request
    # ---------------------------------------------------------
    replayed_envelope = sign_request(
        metadata,
        message_id="request-replay-message-001",
        nonce="request-replay-nonce-001",
    )

    request_cache: set[str] = set()

    request_first = verify_request(
        replayed_envelope,
        metadata,
        message_id="request-replay-message-001",
        replay_cache=request_cache,
    )

    request_cache_after_first = sorted(
        request_cache
    )

    request_second = verify_request(
        replayed_envelope,
        metadata,
        message_id="request-replay-message-001",
        replay_cache=request_cache,
    )

    # ---------------------------------------------------------
    # Case 2: fresh C3 request carrying an already consumed C2
    # authorization artifact
    # ---------------------------------------------------------
    first_fresh_envelope = sign_request(
        metadata,
        message_id="artifact-replay-message-001",
        nonce="artifact-replay-request-nonce-001",
    )
    second_fresh_envelope = sign_request(
        metadata,
        message_id="artifact-replay-message-002",
        nonce="artifact-replay-request-nonce-002",
    )

    fresh_request_cache: set[str] = set()

    first_fresh_request = verify_request(
        first_fresh_envelope,
        metadata,
        message_id="artifact-replay-message-001",
        replay_cache=fresh_request_cache,
    )
    second_fresh_request = verify_request(
        second_fresh_envelope,
        metadata,
        message_id="artifact-replay-message-002",
        replay_cache=fresh_request_cache,
    )

    artifact_cache = InMemoryReplayCache()

    artifact_first = (
        verify_extended_secure_passport(
            artifact,
            replay_cache=artifact_cache,
            now=1003,
        )
    )

    artifact_consumption = (
        consume_authorization_nonce(
            artifact,
            artifact_cache,
        )
    )

    artifact_second = (
        verify_extended_secure_passport(
            artifact,
            replay_cache=artifact_cache,
            now=1003,
        )
    )

    request_replay_passed = (
        request_first["valid"] is True
        and request_second["valid"] is False
        and request_second["reason"]
        == "request nonce already consumed"
    )

    artifact_replay_passed = (
        first_fresh_request["valid"] is True
        and second_fresh_request["valid"] is True
        and artifact_first["valid"] is True
        and artifact_consumption["valid"] is True
        and artifact_second["valid"] is False
        and artifact_second["reason"]
        == "authorization nonce already consumed"
    )

    report = {
        "experiment": (
            "separate_request_and_authorization_"
            "artifact_replay_domains"
        ),
        "architecture": {
            "c2": (
                "project-specific companion "
                "authorization-evidence artifact"
            ),
            "c3": (
                "project-specific signed A2A "
                "request-authentication envelope"
            ),
        },
        "authorization_details": (
            AUTHORIZATION_DETAILS
        ),
        "artifact_summary": {
            "authorization_nonce": (
                artifact["nonce"]
            ),
            "authorization_details_hash": (
                artifact[
                    "authorizationDetailsHash"
                ]
            ),
            "delegation_chain": (
                artifact["delegationChain"]
            ),
        },
        "request_replay": {
            "description": (
                "The same signed C3 request is "
                "presented twice."
            ),
            "envelope": envelope_summary(
                replayed_envelope
            ),
            "first_verification": request_first,
            "request_cache_after_first": (
                request_cache_after_first
            ),
            "second_verification": (
                request_second
            ),
            "expected_second_outcome": (
                "rejected"
            ),
            "observed_second_outcome": (
                "rejected"
                if not request_second["valid"]
                else "accepted"
            ),
            "passed": request_replay_passed,
        },
        "authorization_artifact_replay": {
            "description": (
                "Two distinct, valid C3 requests "
                "carry the same C2 authorization "
                "artifact. The second request is "
                "fresh at the request layer, but "
                "the authorization nonce has "
                "already been consumed."
            ),
            "first_request_envelope": (
                envelope_summary(
                    first_fresh_envelope
                )
            ),
            "second_request_envelope": (
                envelope_summary(
                    second_fresh_envelope
                )
            ),
            "request_nonces_are_distinct": (
                first_fresh_envelope["nonce"]
                != second_fresh_envelope["nonce"]
            ),
            "message_ids_are_distinct": (
                first_fresh_envelope[
                    "message_id"
                ]
                != second_fresh_envelope[
                    "message_id"
                ]
            ),
            "signatures_are_distinct": (
                first_fresh_envelope[
                    "signature"
                ]
                != second_fresh_envelope[
                    "signature"
                ]
            ),
            "first_request_verification": (
                first_fresh_request
            ),
            "second_request_verification": (
                second_fresh_request
            ),
            "first_artifact_verification": (
                artifact_first
            ),
            "artifact_nonce_consumption": (
                artifact_consumption
            ),
            "second_artifact_verification": (
                artifact_second
            ),
            "expected_artifact_outcome": (
                "rejected"
            ),
            "observed_artifact_outcome": (
                "rejected"
                if not artifact_second["valid"]
                else "accepted"
            ),
            "passed": artifact_replay_passed,
        },
        "summary": {
            "request_replay_rejected": (
                request_replay_passed
            ),
            "authorization_artifact_replay_rejected": (
                artifact_replay_passed
            ),
            "request_and_authorization_nonces_are_distinct": (
                replayed_envelope["nonce"]
                != artifact["nonce"]
            ),
        },
    }

    report["passed"] = all(
        report["summary"].values()
    )

    report_path = (
        OUTPUT_DIR
        / "replay_evidence_report.json"
    )
    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
    )
    print(f"\nReport: {report_path}")

    raise SystemExit(
        0 if report["passed"] else 1
    )


if __name__ == "__main__":
    main()
