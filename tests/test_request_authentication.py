from __future__ import annotations

from copy import deepcopy

from common.agent_keys import load_agent_identity
from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
)
from common.request_authentication import (
    create_request_authentication,
    sha256_protected_metadata,
    sha256_text,
    verify_request_authentication,
)


TEXT = "I want reimbursement for Claim/claim-001."
METADATA = {
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
    SECURE_PASSPORT_URI: {
        "clientId": "patient-agent",
        "sessionId": "reimbursement-session-001",
        "signature": "demo-state-signature",
        "state": {
            "claim_reference": "Claim/claim-001",
        },
    },
    EXTENDED_SECURE_PASSPORT_URI: {
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
        "delegationChain": [],
        "integrity": {
            "algorithm": "HMAC-SHA256-DEMO",
            "value": "demo-integrity-value",
        },
    },
}


def create_test_envelope() -> dict:
    return create_request_authentication(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id="a2a-message-001",
        text=TEXT,
        metadata=METADATA,
        identity=load_agent_identity("patient-agent"),
        now=1000,
        ttl_seconds=60,
        nonce="request-nonce-001",
    )


def verify(
    envelope: dict,
    *,
    text: str = TEXT,
    metadata: dict | None = None,
    sender: str = "patient-agent",
    receiver: str = "hospital-agent",
    message_id: str = "a2a-message-001",
    now: int | float = 1001,
    replay_cache: set[str] | None = None,
    consume_nonce: bool = False,
) -> dict:
    return verify_request_authentication(
        envelope=envelope,
        expected_sender_id=sender,
        expected_receiver_id=receiver,
        expected_message_id=message_id,
        text=text,
        metadata=METADATA if metadata is None else metadata,
        now=now,
        replay_cache=replay_cache,
        consume_nonce=consume_nonce,
    )


def test_valid_signed_request_envelope() -> None:
    assert verify(create_test_envelope())["valid"] is True


def test_required_identity_and_request_fields_are_present() -> None:
    envelope = create_test_envelope()
    assert envelope["sender_id"] == "patient-agent"
    assert envelope["receiver_id"] == "hospital-agent"
    assert envelope["key_id"] == "patient-agent-ed25519-v1"
    assert envelope["message_id"] == "a2a-message-001"
    assert envelope["created_at"] == 1000
    assert envelope["expires_at"] == 1060
    assert envelope["nonce"] == "request-nonce-001"


def test_text_digest_is_sha256_of_exact_utf8_text() -> None:
    envelope = create_test_envelope()
    assert envelope["text_digest"] == sha256_text(TEXT)
    assert envelope["text_digest"] != sha256_text(TEXT + " ")


def test_metadata_digest_ignores_json_key_order() -> None:
    reordered = {
        SECURE_PASSPORT_URI: METADATA[
            SECURE_PASSPORT_URI
        ],
        EXTENDED_SECURE_PASSPORT_URI: METADATA[
            EXTENDED_SECURE_PASSPORT_URI
        ],
        "authorization_details": METADATA["authorization_details"],
        "healthcare_resources": METADATA["healthcare_resources"],
    }
    assert sha256_protected_metadata(METADATA) == sha256_protected_metadata(reordered)


def test_unprotected_metadata_does_not_change_digest() -> None:
    enriched = deepcopy(METADATA)
    enriched["debug_note"] = "not protected"
    assert sha256_protected_metadata(METADATA) == sha256_protected_metadata(enriched)


def test_text_tampering_is_rejected() -> None:
    result = verify(
        create_test_envelope(),
        text="I want reimbursement for Claim/claim-999.",
    )
    assert result["valid"] is False
    assert result["reason"] == "text digest mismatch"


def test_protected_metadata_tampering_is_rejected() -> None:
    tampered = deepcopy(METADATA)
    tampered["authorization_details"][0]["maximum_amount"]["value"] = 5000
    result = verify(create_test_envelope(), metadata=tampered)
    assert result["valid"] is False
    assert result["reason"] == "protected metadata digest mismatch"


def test_sender_impersonation_is_rejected() -> None:
    result = verify(create_test_envelope(), sender="external-agent")
    assert result["valid"] is False
    assert result["reason"] == "sender_id does not match expected sender"


def test_wrong_receiver_is_rejected() -> None:
    result = verify(create_test_envelope(), receiver="insurance-agent")
    assert result["valid"] is False
    assert result["reason"] == "receiver_id does not match expected receiver"


def test_wrong_message_id_is_rejected() -> None:
    result = verify(create_test_envelope(), message_id="a2a-message-999")
    assert result["valid"] is False
    assert result["reason"] == "message_id does not match the A2A message"


def test_signature_tampering_is_rejected() -> None:
    envelope = create_test_envelope()
    envelope["signature"] = envelope["signature"][:-2] + "AA"
    result = verify(envelope)
    assert result["valid"] is False
    assert result["reason"] == "invalid Ed25519 request signature"


def test_wrong_key_id_is_rejected() -> None:
    envelope = create_test_envelope()
    envelope["key_id"] = "patient-agent-ed25519-v2"
    result = verify(envelope)
    assert result["valid"] is False


def test_expired_envelope_is_rejected() -> None:
    result = verify(create_test_envelope(), now=1061)
    assert result["valid"] is False
    assert result["reason"] == "request-authentication envelope expired"


def test_integral_float_timestamps_from_protobuf_are_accepted() -> None:
    envelope = create_test_envelope()
    envelope["created_at"] = 1000.0
    envelope["expires_at"] = 1060.0
    assert verify(envelope, now=1001.0)["valid"] is True


def test_replay_cache_rejects_consumed_nonce() -> None:
    envelope = create_test_envelope()
    replay_cache: set[str] = set()
    first = verify(envelope, replay_cache=replay_cache, consume_nonce=True)
    second = verify(envelope, replay_cache=replay_cache, consume_nonce=True)
    assert first["valid"] is True
    assert first["nonce_consumed"] is True
    assert second["valid"] is False
    assert second["reason"] == "request nonce already consumed"


def test_verification_can_check_nonce_without_consuming_it() -> None:
    envelope = create_test_envelope()
    replay_cache: set[str] = set()
    first = verify(envelope, replay_cache=replay_cache, consume_nonce=False)
    second = verify(envelope, replay_cache=replay_cache, consume_nonce=False)
    assert first["valid"] is True
    assert second["valid"] is True
    assert replay_cache == set()


def test_hospital_signature_cannot_impersonate_patient() -> None:
    envelope = create_request_authentication(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id="a2a-message-002",
        text="Hospital validated Claim/claim-001.",
        metadata=METADATA,
        identity=load_agent_identity("hospital-agent"),
        now=1000,
        nonce="request-nonce-002",
    )
    result = verify_request_authentication(
        envelope=envelope,
        expected_sender_id="patient-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id="a2a-message-002",
        text="Hospital validated Claim/claim-001.",
        metadata=METADATA,
        now=1001,
    )
    assert result["valid"] is False
    assert result["reason"] == "sender_id does not match expected sender"
