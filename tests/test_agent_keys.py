from __future__ import annotations

from pathlib import Path

import pytest

from common.agent_keys import (
    AGENT_IDS,
    KEYS_DIRECTORY,
    key_id_for_agent,
    load_agent_identity,
    load_trust_store,
    public_key_bytes,
    resolve_trusted_key,
    sign_bytes,
    verify_bytes,
)


def test_all_principals_have_distinct_keys() -> None:
    identities = [
        load_agent_identity(agent_id)
        for agent_id in AGENT_IDS
    ]

    public_keys = {
        public_key_bytes(identity.public_key)
        for identity in identities
    }

    assert len(public_keys) == 4


def test_agent_identity_contains_required_fields() -> None:
    identity = load_agent_identity(
        "patient-agent"
    )

    assert identity.agent_id == "patient-agent"
    assert identity.key_id == (
        "patient-agent-ed25519-v1"
    )
    assert identity.private_key is not None
    assert identity.public_key is not None


def test_trust_store_contains_public_keys_only() -> None:
    trust_store = load_trust_store()

    assert set(trust_store) == set(AGENT_IDS)

    for trusted in trust_store.values():
        assert trusted.public_key is not None
        assert not hasattr(trusted, "private_key")


def test_each_agent_can_verify_its_own_signature() -> None:
    payload = b"day-11-key-model"

    for agent_id in AGENT_IDS:
        identity = load_agent_identity(agent_id)
        trusted = resolve_trusted_key(
            agent_id=agent_id,
            key_id=identity.key_id,
        )

        signature = sign_bytes(
            identity,
            payload,
        )

        assert verify_bytes(
            trusted,
            payload,
            signature,
        )


def test_signature_fails_with_different_agent_key() -> None:
    payload = b"patient request"

    patient_identity = load_agent_identity(
        "patient-agent"
    )
    hospital_trusted = resolve_trusted_key(
        agent_id="hospital-agent",
        key_id=key_id_for_agent(
            "hospital-agent"
        ),
    )

    signature = sign_bytes(
        patient_identity,
        payload,
    )

    assert not verify_bytes(
        hospital_trusted,
        payload,
        signature,
    )


def test_signature_fails_after_payload_tampering() -> None:
    identity = load_agent_identity(
        "hospital-agent"
    )
    trusted = resolve_trusted_key(
        agent_id="hospital-agent",
        key_id=identity.key_id,
    )

    signature = sign_bytes(
        identity,
        b"original payload",
    )

    assert not verify_bytes(
        trusted,
        b"tampered payload",
        signature,
    )


def test_unknown_agent_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Untrusted agent_id",
    ):
        resolve_trusted_key(
            agent_id="external-agent",
            key_id="external-agent-ed25519-v1",
        )


def test_wrong_key_id_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Untrusted key_id",
    ):
        resolve_trusted_key(
            agent_id="patient-agent",
            key_id="patient-agent-ed25519-v2",
        )


def test_private_and_public_files_exist() -> None:
    expected = []

    for agent_id in AGENT_IDS:
        expected.extend(
            [
                KEYS_DIRECTORY
                / f"{agent_id}.private.pem",
                KEYS_DIRECTORY
                / f"{agent_id}.public.pem",
            ]
        )

    assert all(path.exists() for path in expected)


def test_key_id_is_deterministic() -> None:
    assert key_id_for_agent(
        "insurance-agent"
    ) == "insurance-agent-ed25519-v1"
