from __future__ import annotations

from copy import deepcopy

import pytest

from common.secure_passport import (
    InMemoryReplayCache,
    add_delegation_entry,
    canonical_json,
    canonicalize_json,
    consume_authorization_nonce,
    create_secure_passport,
    sha256_json,
    verify_authorization_details_binding,
    verify_secure_passport,
    verify_signature_only,
)


AUTHORIZATION_DETAILS = [
    {
        "type": "healthcare_reimbursement",
        "identifier": "authz-claim-001",
        "actions": ["request_reimbursement"],
        "claim": {"reference": "Claim/claim-001"},
        "beneficiary": {"reference": "Patient/patient-001"},
        "coverage": {"reference": "Coverage/coverage-basic-001"},
        "maximum_amount": {"value": 120, "currency": "EUR"},
        "constraints": {
            "permitted_destination": "insurance-agent",
            "permitted_hops": [
                "patient-agent",
                "hospital-agent",
                "insurance-agent",
            ],
            "max_agent_hops": 2,
            "valid_until": "2026-12-31T23:59:59Z",
        },
    }
]


def create_test_passport() -> dict:
    return create_secure_passport(
        caller_id="patient-agent",
        context_state={
            "patient_reference": "Patient/patient-001",
            "coverage_reference": "Coverage/coverage-basic-001",
            "claim_reference": "Claim/claim-001",
            "consent": True,
        },
        authorization_details=AUTHORIZATION_DETAILS,
        extended=True,
        now=1000,
        nonce="authorization-nonce-001",
    )


def test_rfc8785_object_key_order_does_not_change_output() -> None:
    first = {
        "z": 1,
        "a": {
            "currency": "EUR",
            "value": 120,
        },
    }
    second = {
        "a": {
            "value": 120,
            "currency": "EUR",
        },
        "z": 1,
    }

    assert canonicalize_json(first) == canonicalize_json(second)
    assert sha256_json(first) == sha256_json(second)


def test_canonical_json_has_no_insignificant_whitespace() -> None:
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_array_order_remains_security_relevant() -> None:
    first = {"permitted_hops": ["patient-agent", "hospital-agent"]}
    second = {"permitted_hops": ["hospital-agent", "patient-agent"]}

    assert sha256_json(first) != sha256_json(second)


def test_protobuf_integral_float_normalizes_to_integer() -> None:
    assert canonicalize_json({"amount": 120}) == canonicalize_json(
        {"amount": 120.0}
    )


def test_non_integral_number_is_not_changed_to_integer() -> None:
    assert sha256_json({"amount": 120.5}) != sha256_json(
        {"amount": 120}
    )


def test_unicode_canonicalization_is_stable() -> None:
    first = {"display": "Café", "code": "T123"}
    second = {"code": "T123", "display": "Café"}

    assert canonicalize_json(first) == canonicalize_json(second)


def test_passport_uses_new_authorization_hash_name() -> None:
    passport = create_test_passport()

    assert "authorization_details_hash" in passport
    assert "intent_hash" not in passport


def test_passport_signature_survives_key_reordering() -> None:
    passport = create_test_passport()
    reordered = dict(reversed(list(passport.items())))

    result = verify_signature_only(reordered)

    assert result["valid"] is True


def test_passport_signature_detects_state_tampering() -> None:
    passport = create_test_passport()
    passport["state"]["patient_reference"] = "Patient/patient-999"

    result = verify_signature_only(passport)

    assert result["valid"] is False
    assert result["reason"] == "invalid signature"


def test_authorization_binding_accepts_reordered_object_keys() -> None:
    passport = create_test_passport()
    reordered = deepcopy(AUTHORIZATION_DETAILS)
    detail = reordered[0]
    reordered[0] = {
        "constraints": detail["constraints"],
        "maximum_amount": detail["maximum_amount"],
        "coverage": detail["coverage"],
        "beneficiary": detail["beneficiary"],
        "claim": detail["claim"],
        "actions": detail["actions"],
        "identifier": detail["identifier"],
        "type": detail["type"],
    }

    result = verify_authorization_details_binding(
        passport,
        reordered,
    )

    assert result["valid"] is True


def test_authorization_binding_detects_amount_tampering() -> None:
    passport = create_test_passport()
    tampered = deepcopy(AUTHORIZATION_DETAILS)
    tampered[0]["maximum_amount"]["value"] = 5000

    result = verify_authorization_details_binding(
        passport,
        tampered,
    )

    assert result["valid"] is False
    assert result["reason"] == "authorization_details hash mismatch"


def test_delegation_update_resigns_passport() -> None:
    passport = create_test_passport()
    updated = add_delegation_entry(
        passport,
        from_agent="patient-agent",
        to_agent="hospital-agent",
        scope=["request_reimbursement", "send_to_hospital"],
        now=1001,
    )

    assert verify_signature_only(updated)["valid"] is True
    assert len(updated["delegation_chain"]) == 2


def test_replay_check_does_not_consume_nonce_early() -> None:
    passport = create_test_passport()
    cache = InMemoryReplayCache()

    first = verify_secure_passport(
        passport,
        replay_cache=cache,
        now=1001,
    )
    second = verify_secure_passport(
        passport,
        replay_cache=cache,
        now=1001,
    )

    assert first["valid"] is True
    assert second["valid"] is True
    assert not cache.contains("authorization-nonce-001")


def test_nonce_is_rejected_after_explicit_consumption() -> None:
    passport = create_test_passport()
    cache = InMemoryReplayCache()

    consumed = consume_authorization_nonce(passport, cache)
    replay = verify_secure_passport(
        passport,
        replay_cache=cache,
        now=1001,
    )

    assert consumed["valid"] is True
    assert replay["valid"] is False
    assert replay["reason"] == "authorization nonce already consumed"


def test_expired_passport_is_rejected() -> None:
    passport = create_test_passport()

    result = verify_secure_passport(
        passport,
        now=passport["expires_at"] + 1,
    )

    assert result["valid"] is False
    assert result["reason"] == "passport expired"


def test_extended_passport_requires_authorization_details() -> None:
    with pytest.raises(
        ValueError,
        match="requires authorization_details",
    ):
        create_secure_passport(
            caller_id="patient-agent",
            context_state={"consent": True},
            authorization_details=None,
            extended=True,
            now=1000,
        )

def test_freshness_accepts_integral_floats_from_protobuf_struct() -> None:
    passport = create_test_passport()

    passport["issued_at"] = float(passport["issued_at"])
    passport["expires_at"] = float(passport["expires_at"])

    result = verify_secure_passport(
        passport,
        now=1001.0,
    )

    assert result["valid"] is True
