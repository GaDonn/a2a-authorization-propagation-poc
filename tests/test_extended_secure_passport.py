from __future__ import annotations

from copy import deepcopy

from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
    create_caller_context,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
    add_delegation_entry,
    attach_extended_secure_passport,
    consume_authorization_nonce,
    create_extended_secure_passport,
    extract_extended_secure_passport,
    verify_authorization_details_binding,
    verify_delegation_chain,
    verify_extended_secure_passport,
)
from common.secure_passport import (
    InMemoryReplayCache,
)


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
            "reference": (
                "Coverage/coverage-basic-001"
            ),
        },
        "maximum_amount": {
            "value": "120",
            "currency": "EUR",
        },
    }
]


def make_artifact() -> dict:
    origin = create_caller_context(
        client_id="patient-agent",
        session_id="session-001",
        state={
            "patient_reference": (
                "Patient/patient-001"
            ),
            "claim_reference": (
                "Claim/claim-001"
            ),
        },
        sign_state=True,
    )

    artifact = (
        create_extended_secure_passport(
            origin_caller_context=origin,
            authorization_details=(
                AUTHORIZATION_DETAILS
            ),
            now=1000,
            nonce="auth-nonce-001",
        )
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

    return artifact


def test_extended_passport_uses_separate_uri() -> None:
    assert (
        EXTENDED_SECURE_PASSPORT_URI
        != SECURE_PASSPORT_URI
    )


def test_extended_passport_is_layered_on_v1() -> None:
    artifact = make_artifact()

    assert artifact[
        "baseExtensionUri"
    ] == SECURE_PASSPORT_URI
    assert "originCallerContext" in artifact
    assert artifact[
        "originCallerContext"
    ]["clientId"] == "patient-agent"


def test_extended_passport_attaches_under_proposal_uri() -> None:
    metadata = {}

    attach_extended_secure_passport(
        metadata,
        make_artifact(),
    )

    assert (
        EXTENDED_SECURE_PASSPORT_URI
        in metadata
    )
    assert "secure_passport" not in metadata


def test_extended_passport_verifies() -> None:
    result = verify_extended_secure_passport(
        make_artifact(),
        now=1002,
    )

    assert result["valid"] is True


def test_artifact_tampering_is_rejected() -> None:
    artifact = make_artifact()

    tampered = deepcopy(artifact)
    tampered[
        "authorizationDetailsHash"
    ] = "0" * 64

    result = verify_extended_secure_passport(
        tampered,
        now=1002,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Extended Secure Passport "
        "artifact integrity"
    )


def test_authorization_binding_is_verified() -> None:
    artifact = make_artifact()

    result = (
        verify_authorization_details_binding(
            artifact,
            AUTHORIZATION_DETAILS,
        )
    )

    assert result["valid"] is True


def test_authorization_binding_tamper_is_rejected() -> None:
    artifact = make_artifact()

    tampered = deepcopy(
        AUTHORIZATION_DETAILS
    )
    tampered[0][
        "maximum_amount"
    ]["value"] = "9000"

    result = (
        verify_authorization_details_binding(
            artifact,
            tampered,
        )
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "authorization_details hash mismatch"
    )


def test_complete_delegation_chain_is_valid() -> None:
    artifact = make_artifact()

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

    result = verify_delegation_chain(
        artifact
    )

    assert result["valid"] is True
    assert result["chain_length"] == 3


def test_authorization_replay_is_separate_from_request_replay() -> None:
    artifact = make_artifact()
    cache = InMemoryReplayCache()

    first = verify_extended_secure_passport(
        artifact,
        replay_cache=cache,
        now=1002,
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
        now=1002,
    )

    assert second["valid"] is False
    assert second["reason"] == (
        "authorization nonce already consumed"
    )


def test_origin_caller_context_tamper_is_rejected() -> None:
    artifact = make_artifact()

    tampered = deepcopy(artifact)
    tampered[
        "originCallerContext"
    ]["state"]["claim_reference"] = (
        "Claim/claim-999"
    )

    # Recompute outer demo integrity to model an actor that can create a
    # syntactically valid artifact but cannot forge the Patient's embedded
    # Secure Passport v1 state signature.
    from common.extended_secure_passport import (
        _sign_artifact,
    )

    tampered["integrity"] = (
        _sign_artifact(tampered)
    )

    result = verify_extended_secure_passport(
        tampered,
        now=1002,
    )

    assert result["valid"] is False
    assert "origin CallerContext" in (
        result["reason"]
    )


def test_extract_round_trip() -> None:
    artifact = make_artifact()
    metadata = {}

    attach_extended_secure_passport(
        metadata,
        artifact,
    )

    extracted = (
        extract_extended_secure_passport(
            metadata
        )
    )

    assert extracted is not None
    assert extracted["nonce"] == (
        "auth-nonce-001"
    )
