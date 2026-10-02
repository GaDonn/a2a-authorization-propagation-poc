from __future__ import annotations

from copy import deepcopy

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
    create_caller_context,
)
from common.agent_keys import (
    load_agent_identity,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
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
from common.secure_passport import (
    InMemoryReplayCache,
)


TEXT = "Hospital validated Claim/claim-001."
MESSAGE_ID = "step-d-message-001"

AUTHORIZATION_DETAILS = [
    {
        "type": "healthcare_reimbursement",
        "actions": [
            "request_reimbursement",
        ],
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
    sender_id: str = "hospital-agent",
    receiver_id: str = "insurance-agent",
    identity_id: str = "hospital-agent",
    message_id: str = MESSAGE_ID,
    nonce: str = "request-nonce-001",
) -> dict:
    return create_request_authentication(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_id=message_id,
        text=TEXT,
        metadata=metadata,
        identity=load_agent_identity(
            identity_id
        ),
        now=1000,
        ttl_seconds=60,
        nonce=nonce,
    )


def verify_request(
    envelope: dict,
    metadata: dict,
    *,
    expected_sender_id: str = "hospital-agent",
    expected_receiver_id: str = "insurance-agent",
    expected_message_id: str = MESSAGE_ID,
    replay_cache: set[str] | None = None,
    consume_nonce: bool = False,
) -> dict:
    return verify_request_authentication(
        envelope=envelope,
        expected_sender_id=expected_sender_id,
        expected_receiver_id=expected_receiver_id,
        expected_message_id=expected_message_id,
        text=TEXT,
        metadata=metadata,
        replay_cache=replay_cache,
        consume_nonce=consume_nonce,
        now=1001,
    )


def test_control_legitimate_c3_request_is_accepted() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    result = verify_request(
        envelope,
        metadata,
    )

    assert result["valid"] is True


def test_sender_impersonation_is_rejected() -> None:
    metadata = make_metadata()

    # First create a legitimately signed request from the
    # reimbursement client.
    envelope = sign_request(
        metadata,
        sender_id="reimbursement-client",
        identity_id="reimbursement-client",
    )

    # Then forge the claimed sender identity and key identifier
    # without recomputing the signature.
    #
    # The signature is still the reimbursement-client signature,
    # but the envelope now claims to have been signed by
    # patient-agent.
    envelope["sender_id"] = "patient-agent"
    envelope["key_id"] = (
        "patient-agent-ed25519-v1"
    )

    result = verify_request(
        envelope,
        metadata,
        expected_sender_id="patient-agent",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )

def test_modified_text_is_rejected() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    result = verify_request_authentication(
        envelope=envelope,
        expected_sender_id="hospital-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id=MESSAGE_ID,
        text="Tampered request body",
        metadata=metadata,
        now=1001,
    )

    assert result["valid"] is False
    assert result["reason"] == "text digest mismatch"


def test_modified_standard_secure_passport_is_rejected() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    tampered = deepcopy(metadata)
    tampered[
        SECURE_PASSPORT_URI
    ]["state"]["validation_status"] = "rejected"

    result = verify_request(
        envelope,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_modified_extended_secure_passport_is_rejected() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    tampered = deepcopy(metadata)
    tampered[
        EXTENDED_SECURE_PASSPORT_URI
    ]["authorizationDetailsHash"] = "0" * 64

    result = verify_request(
        envelope,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_authorization_amount_tampering_is_rejected_by_binding() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    tampered = deepcopy(
        metadata["authorization_details"]
    )
    tampered[0][
        "maximum_amount"
    ]["value"] = "9000"

    result = verify_authorization_details_binding(
        artifact,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "authorization_details hash mismatch"
    )


def test_authorization_beneficiary_tampering_is_rejected_by_binding() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    tampered = deepcopy(
        metadata["authorization_details"]
    )
    tampered[0][
        "beneficiary"
    ]["reference"] = "Patient/patient-999"

    result = verify_authorization_details_binding(
        artifact,
        tampered,
    )

    assert result["valid"] is False


def test_authorization_coverage_tampering_is_rejected_by_binding() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    tampered = deepcopy(
        metadata["authorization_details"]
    )
    tampered[0][
        "coverage"
    ]["reference"] = "Coverage/other"

    result = verify_authorization_details_binding(
        artifact,
        tampered,
    )

    assert result["valid"] is False


def test_authorization_treatment_tampering_is_rejected_by_binding() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    tampered = deepcopy(
        metadata["authorization_details"]
    )
    tampered[0][
        "treatment"
    ]["code"] = "T999"

    result = verify_authorization_details_binding(
        artifact,
        tampered,
    )

    assert result["valid"] is False


def test_authorization_action_tampering_is_rejected_by_binding() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    tampered = deepcopy(
        metadata["authorization_details"]
    )
    tampered[0]["actions"] = [
        "approve_reimbursement"
    ]

    result = verify_authorization_details_binding(
        artifact,
        tampered,
    )

    assert result["valid"] is False


def test_unauthorized_hop_is_rejected() -> None:
    metadata = make_metadata()
    artifact = deepcopy(
        metadata[
            EXTENDED_SECURE_PASSPORT_URI
        ]
    )

    artifact[
        "delegationChain"
    ][1]["to"] = "analytics-agent"

    result = verify_delegation_chain(
        artifact
    )

    assert result["valid"] is False


def test_destination_substitution_is_rejected() -> None:
    metadata = make_metadata()
    artifact = deepcopy(
        metadata[
            EXTENDED_SECURE_PASSPORT_URI
        ]
    )

    artifact[
        "delegationChain"
    ][2]["to"] = "billing-agent"

    result = verify_delegation_chain(
        artifact
    )

    assert result["valid"] is False


def test_scope_widening_policy_gap_is_still_documented() -> None:
    metadata = make_metadata()
    artifact = deepcopy(
        metadata[
            EXTENDED_SECURE_PASSPORT_URI
        ]
    )

    artifact[
        "delegationChain"
    ][1]["scope"].append(
        "approve_reimbursement"
    )

    result = verify_delegation_chain(
        artifact
    )

    assert result["valid"] is True


def test_request_replay_is_rejected_when_enabled() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    request_replay_cache: set[str] = set()

    first = verify_request(
        envelope,
        metadata,
        replay_cache=request_replay_cache,
        consume_nonce=True,
    )

    assert first["valid"] is True

    second = verify_request(
        envelope,
        metadata,
        replay_cache=request_replay_cache,
        consume_nonce=True,
    )

    assert second["valid"] is False
    assert second["reason"] == (
        "request nonce already consumed"
    )


def test_authorization_artifact_replay_is_rejected_when_enabled() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]
    cache = InMemoryReplayCache()

    first = verify_extended_secure_passport(
        artifact,
        replay_cache=cache,
        now=1003,
    )
    assert first["valid"] is True

    consumed = consume_authorization_nonce(
        artifact,
        cache,
    )
    assert consumed["valid"] is True

    second = verify_extended_secure_passport(
        artifact,
        replay_cache=cache,
        now=1003,
    )

    assert second["valid"] is False
    assert second["reason"] == (
        "authorization nonce already consumed"
    )


def test_expired_authorization_artifact_is_rejected_even_without_replay_cache() -> None:
    metadata = make_metadata()
    artifact = metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]

    result = verify_extended_secure_passport(
        artifact,
        replay_cache=None,
        now=9999999999,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "Extended Secure Passport expired"
    )


def test_request_nonce_and_authorization_nonce_are_distinct() -> None:
    metadata = make_metadata()
    envelope = sign_request(metadata)

    assert envelope["nonce"] != metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]["nonce"]
