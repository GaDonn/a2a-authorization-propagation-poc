from __future__ import annotations

from copy import deepcopy

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
)
from common.agent_keys import (
    load_agent_identity,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
)
from common.request_authentication import (
    PROTECTED_METADATA_FIELDS,
    create_request_authentication,
    select_protected_metadata,
    verify_request_authentication,
)


MESSAGE_ID = "step-c-message-001"
TEXT = "Hospital validated Claim/claim-001."

BASE_CALLER_CONTEXT = {
    "clientId": "hospital-agent",
    "sessionId": "reimbursement-session-001",
    "signature": "demo-base-signature",
    "state": {
        "claim_reference": "Claim/claim-001",
        "validation_status": "validated",
    },
}

EXTENDED_ARTIFACT = {
    "version": "1.0",
    "profile": "authorization-evidence",
    "baseExtensionUri": SECURE_PASSPORT_URI,
    "originCallerContext": {
        "clientId": "patient-agent",
        "sessionId": "reimbursement-session-001",
        "signature": "demo-origin-signature",
        "state": {
            "claim_reference": "Claim/claim-001",
        },
    },
    "originStateHash": "a" * 64,
    "issuedAt": 1000,
    "expiresAt": 2000,
    "nonce": "authorization-nonce-001",
    "authorizationDetailsHash": "b" * 64,
    "delegationChain": [
        {
            "from": "user",
            "to": "patient-agent",
            "scope": ["request_reimbursement"],
            "timestamp": 1000,
        },
        {
            "from": "patient-agent",
            "to": "hospital-agent",
            "scope": ["request_reimbursement"],
            "timestamp": 1001,
        },
        {
            "from": "hospital-agent",
            "to": "insurance-agent",
            "scope": ["validate_claim"],
            "timestamp": 1002,
        },
    ],
    "integrity": {
        "algorithm": "HMAC-SHA256-DEMO",
        "value": "demo-integrity-value",
    },
}

AUTHORIZATION_DETAILS = [
    {
        "type": "healthcare_reimbursement",
        "actions": ["request_reimbursement"],
        "claim": {
            "reference": "Claim/claim-001",
        },
        "maximum_amount": {
            "value": "120",
            "currency": "EUR",
        },
    }
]


def metadata() -> dict:
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
        SECURE_PASSPORT_URI: deepcopy(
            BASE_CALLER_CONTEXT
        ),
        EXTENDED_SECURE_PASSPORT_URI: deepcopy(
            EXTENDED_ARTIFACT
        ),
        "hospital_validation": {
            "status": "validated",
        },
        "hospital_provenance": {
            "agent": "hospital-agent",
        },
        "debug_note": "not security protected",
    }


def create_envelope(
    request_metadata: dict,
) -> dict:
    return create_request_authentication(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=request_metadata,
        identity=load_agent_identity(
            "hospital-agent"
        ),
        now=1000,
        ttl_seconds=60,
        nonce="request-nonce-001",
    )


def verify(
    envelope: dict,
    request_metadata: dict,
) -> dict:
    return verify_request_authentication(
        envelope=envelope,
        expected_sender_id="hospital-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id=MESSAGE_ID,
        text=TEXT,
        metadata=request_metadata,
        now=1001,
    )


def test_c3_protects_standard_secure_passport_uri() -> None:
    assert (
        SECURE_PASSPORT_URI
        in PROTECTED_METADATA_FIELDS
    )


def test_c3_protects_extended_secure_passport_uri() -> None:
    assert (
        EXTENDED_SECURE_PASSPORT_URI
        in PROTECTED_METADATA_FIELDS
    )


def test_legacy_secure_passport_key_is_not_c3_protected() -> None:
    assert (
        "secure_passport"
        not in PROTECTED_METADATA_FIELDS
    )


def test_selected_metadata_contains_both_extensions() -> None:
    selected = select_protected_metadata(
        metadata()
    )

    assert SECURE_PASSPORT_URI in selected
    assert (
        EXTENDED_SECURE_PASSPORT_URI
        in selected
    )


def test_valid_c3_request_with_both_extensions_is_accepted() -> None:
    request_metadata = metadata()
    envelope = create_envelope(
        request_metadata
    )

    result = verify(
        envelope,
        request_metadata,
    )

    assert result["valid"] is True


def test_tampered_standard_secure_passport_is_rejected() -> None:
    original = metadata()
    envelope = create_envelope(original)

    tampered = deepcopy(original)
    tampered[
        SECURE_PASSPORT_URI
    ]["state"]["validation_status"] = "rejected"

    result = verify(
        envelope,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_tampered_extended_secure_passport_is_rejected() -> None:
    original = metadata()
    envelope = create_envelope(original)

    tampered = deepcopy(original)
    tampered[
        EXTENDED_SECURE_PASSPORT_URI
    ]["authorizationDetailsHash"] = (
        "c" * 64
    )

    result = verify(
        envelope,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_tampered_authorization_details_are_rejected() -> None:
    original = metadata()
    envelope = create_envelope(original)

    tampered = deepcopy(original)
    tampered[
        "authorization_details"
    ][0]["maximum_amount"]["value"] = "9000"

    result = verify(
        envelope,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_unprotected_debug_metadata_can_change() -> None:
    original = metadata()
    envelope = create_envelope(original)

    changed = deepcopy(original)
    changed["debug_note"] = "changed"

    result = verify(
        envelope,
        changed,
    )

    assert result["valid"] is True


def test_c3_request_nonce_is_distinct_from_authorization_nonce() -> None:
    request_metadata = metadata()
    envelope = create_envelope(
        request_metadata
    )

    authorization_nonce = request_metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ]["nonce"]

    assert envelope["nonce"] != (
        authorization_nonce
    )
