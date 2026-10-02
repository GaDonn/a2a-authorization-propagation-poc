from __future__ import annotations

from copy import deepcopy

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
    CallerContext,
    attach_secure_passport_v1,
    caller_context_to_wire,
    create_caller_context,
    secure_passport_extension_declaration,
    verify_secure_passport_v1,
)


def test_caller_context_wire_fields_match_v1_spec() -> None:
    context = create_caller_context(
        client_id="patient-agent",
        session_id="session-001",
        state={"claim_reference": "Claim/claim-001"},
        sign_state=True,
    )

    wire = caller_context_to_wire(context)

    assert set(wire) == {
        "clientId",
        "sessionId",
        "signature",
        "state",
    }
    assert "client_id" not in wire
    assert "version" not in wire
    assert "passport_type" not in wire


def test_passport_is_attached_under_extension_uri() -> None:
    metadata = {}
    context = create_caller_context(
        client_id="patient-agent",
        state={"consent": True},
        sign_state=True,
    )

    attach_secure_passport_v1(
        metadata,
        context,
    )

    assert SECURE_PASSPORT_URI in metadata
    assert "secure_passport" not in metadata


def test_unknown_caller_context_field_is_rejected() -> None:
    metadata = {
        SECURE_PASSPORT_URI: {
            "clientId": "patient-agent",
            "state": {"consent": True},
            "passport_type": "standard",
        }
    }

    result = verify_secure_passport_v1(
        metadata,
        expected_client_id="patient-agent",
    )

    assert result["valid"] is False
    assert "malformed" in result["reason"]


def test_signed_state_is_verified() -> None:
    metadata = {}
    context = create_caller_context(
        client_id="patient-agent",
        state={
            "claim_reference": "Claim/claim-001",
            "consent": True,
        },
        sign_state=True,
    )
    attach_secure_passport_v1(
        metadata,
        context,
    )

    result = verify_secure_passport_v1(
        metadata,
        expected_client_id="patient-agent",
    )

    assert result["valid"] is True
    assert result["signature_verified"] is True


def test_state_tampering_is_rejected() -> None:
    metadata = {}
    context = create_caller_context(
        client_id="patient-agent",
        state={"consent": True},
        sign_state=True,
    )
    attach_secure_passport_v1(
        metadata,
        context,
    )

    tampered = deepcopy(metadata)
    tampered[SECURE_PASSPORT_URI][
        "state"
    ]["consent"] = False

    result = verify_secure_passport_v1(
        tampered,
        expected_client_id="patient-agent",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Secure Passport state signature"
    )


def test_wrong_client_id_is_rejected() -> None:
    metadata = {}
    context = create_caller_context(
        client_id="patient-agent",
        state={"consent": True},
        sign_state=True,
    )
    attach_secure_passport_v1(
        metadata,
        context,
    )

    result = verify_secure_passport_v1(
        metadata,
        expected_client_id="hospital-agent",
    )

    assert result["valid"] is False
    assert "clientId" in result["reason"]


def test_signature_is_optional_in_data_model() -> None:
    context = CallerContext(
        client_id="patient-agent",
        state={"consent": True},
    )

    assert context.signature is None


def test_high_trust_policy_requires_signature() -> None:
    metadata = {
        SECURE_PASSPORT_URI: {
            "clientId": "patient-agent",
            "state": {"consent": True},
        }
    }

    result = verify_secure_passport_v1(
        metadata,
        expected_client_id="patient-agent",
        require_signature=True,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "missing Secure Passport state signature"
    )


def test_agent_card_declaration_uses_v1_uri() -> None:
    extension = secure_passport_extension_declaration(
        supported_state_keys=[
            "claim_reference",
        ]
    )

    assert extension.uri == SECURE_PASSPORT_URI
    assert extension.required is False
