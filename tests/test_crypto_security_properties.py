from __future__ import annotations

from copy import deepcopy

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
)
from common.agent_keys import (
    key_id_for_agent,
    load_agent_identity,
)
from common.request_authentication import (
    create_request_authentication,
    signature_base_bytes,
    unsigned_envelope_dict,
    verify_request_authentication,
)


TEXT = "I want reimbursement for Claim/claim-001."
MESSAGE_ID = "message-day15-001"
CREATED_AT = 1000
EXPIRES_AT = 1060
VALIDATION_TIME = 1001
REQUEST_NONCE = "request-nonce-day15-001"

PROTECTED_METADATA = {
    "healthcare_resources": {
        "modelVersion": "1.0",
        "resources": {
            "claim": {
                "resourceType": "Claim",
                "id": "claim-001",
                "total": {
                    "value": 120,
                    "currency": "EUR",
                },
            }
        },
    },
    "authorization_details": [
        {
            "type": "healthcare_reimbursement",
            "claim": {
                "reference": "Claim/claim-001",
            },
            "maximum_amount": {
                "value": 120,
                "currency": "EUR",
            },
        }
    ],
    "secure_passport": {
        "passport_type": "extended",
        "authorization_details_hash": "a" * 64,
    },
}


def create_valid_envelope(
    *,
    metadata: dict | None = None,
) -> dict:
    return create_request_authentication(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=(
            PROTECTED_METADATA
            if metadata is None
            else metadata
        ),
        identity=load_agent_identity(
            "patient-agent"
        ),
        now=CREATED_AT,
        ttl_seconds=EXPIRES_AT - CREATED_AT,
        nonce=REQUEST_NONCE,
    )


def verify(
    envelope: dict,
    *,
    text: str = TEXT,
    metadata: dict | None = None,
    expected_sender: str = "patient-agent",
    expected_receiver: str = "hospital-agent",
    expected_message_id: str = MESSAGE_ID,
    now: int | float = VALIDATION_TIME,
    replay_cache: set[str] | None = None,
    consume_nonce: bool = False,
) -> dict:
    return verify_request_authentication(
        envelope=envelope,
        expected_sender_id=expected_sender,
        expected_receiver_id=expected_receiver,
        expected_message_id=expected_message_id,
        text=text,
        metadata=(
            PROTECTED_METADATA
            if metadata is None
            else metadata
        ),
        now=now,
        replay_cache=replay_cache,
        consume_nonce=consume_nonce,
    )


def test_valid_signature_is_accepted() -> None:
    result = verify(create_valid_envelope())

    assert result["valid"] is True
    assert result["sender_id"] == "patient-agent"
    assert result["receiver_id"] == "hospital-agent"
    assert result["key_id"] == (
        "patient-agent-ed25519-v1"
    )


def test_altered_signature_is_rejected() -> None:
    envelope = create_valid_envelope()
    original = envelope["signature"]

    replacement = (
        "A" if original[-1] != "A" else "B"
    )
    envelope["signature"] = (
        original[:-1] + replacement
    )

    result = verify(envelope)

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )


def test_altered_body_is_rejected() -> None:
    result = verify(
        create_valid_envelope(),
        text=TEXT + " altered",
    )

    assert result["valid"] is False
    assert result["reason"] == "text digest mismatch"


def test_declared_sender_different_from_signing_key_is_rejected() -> None:
    envelope = create_valid_envelope()

    # Keep the original Patient signature, but claim that Hospital signed.
    # Also use Hospital's expected key_id so verification reaches the
    # cryptographic key check instead of failing only on key-id lookup.
    envelope["sender_id"] = "hospital-agent"
    envelope["key_id"] = key_id_for_agent(
        "hospital-agent"
    )

    result = verify(
        envelope,
        expected_sender="hospital-agent",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )


def test_altered_destination_is_cryptographically_rejected() -> None:
    envelope = create_valid_envelope()

    # Change both the envelope destination and the receiver expected by the
    # verifier. The ordinary receiver comparison therefore passes, and the
    # Ed25519 failure proves that receiver_id is covered by the signature.
    envelope["receiver_id"] = "insurance-agent"

    result = verify(
        envelope,
        expected_receiver="insurance-agent",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )


def test_expired_timestamp_is_rejected() -> None:
    result = verify(
        create_valid_envelope(),
        now=EXPIRES_AT + 1,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "request-authentication envelope expired"
    )


def test_duplicate_nonce_is_rejected() -> None:
    envelope = create_valid_envelope()
    replay_cache: set[str] = set()

    first = verify(
        envelope,
        replay_cache=replay_cache,
        consume_nonce=True,
    )
    second = verify(
        envelope,
        replay_cache=replay_cache,
        consume_nonce=True,
    )

    assert first["valid"] is True
    assert first["nonce_consumed"] is True
    assert second["valid"] is False
    assert second["reason"] == (
        "request nonce already consumed"
    )


def test_modified_unsigned_metadata_field_is_not_detected() -> None:
    """
    `debug_note` is outside PROTECTED_METADATA_FIELDS.

    This test deliberately documents a coverage boundary: modifying that
    field does not change protected_metadata_digest and therefore does not
    invalidate the request signature.
    """
    original_metadata = {
        **deepcopy(PROTECTED_METADATA),
        "debug_note": "original note",
    }
    envelope = create_valid_envelope(
        metadata=original_metadata
    )

    modified_metadata = deepcopy(
        original_metadata
    )
    modified_metadata["debug_note"] = (
        "modified after signing"
    )

    result = verify(
        envelope,
        metadata=modified_metadata,
    )

    assert result["valid"] is True


def test_modified_protected_metadata_is_rejected() -> None:
    envelope = create_valid_envelope()
    modified_metadata = deepcopy(
        PROTECTED_METADATA
    )
    modified_metadata[
        "authorization_details"
    ][0]["maximum_amount"]["value"] = 5000

    result = verify(
        envelope,
        metadata=modified_metadata,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "protected metadata digest mismatch"
    )


def test_altered_message_id_is_cryptographically_rejected() -> None:
    envelope = create_valid_envelope()

    # Alter the signed field and make the verifier expect the altered value.
    # This bypasses the simple equality guard and demonstrates that
    # message_id is part of the Ed25519 signature base.
    envelope["message_id"] = "message-day15-999"

    result = verify(
        envelope,
        expected_message_id="message-day15-999",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )
