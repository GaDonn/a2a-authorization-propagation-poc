from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


AGENT_IDS: Final[tuple[str, ...]] = (
    "reimbursement-client",
    "patient-agent",
    "hospital-agent",
    "insurance-agent",
)

KEYS_DIRECTORY: Final[Path] = (
    Path(__file__).resolve().parent / "keys"
)


@dataclass(frozen=True)
class AgentKeyIdentity:
    agent_id: str
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class TrustedPublicKey:
    agent_id: str
    key_id: str
    public_key: Ed25519PublicKey


def key_id_for_agent(agent_id: str) -> str:
    if agent_id not in AGENT_IDS:
        raise ValueError(f"Unknown agent_id: {agent_id}")

    return f"{agent_id}-ed25519-v1"


def private_key_path(agent_id: str) -> Path:
    return KEYS_DIRECTORY / f"{agent_id}.private.pem"


def public_key_path(agent_id: str) -> Path:
    return KEYS_DIRECTORY / f"{agent_id}.public.pem"


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    if not path.exists():
        raise FileNotFoundError(
            f"Private key not found: {path}. "
            "Run the appropriate key-generation script first."
        )

    key = serialization.load_pem_private_key(
        path.read_bytes(),
        password=None,
    )

    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(
            f"Expected Ed25519 private key in {path}"
        )

    return key


def _read_public_key(path: Path) -> Ed25519PublicKey:
    if not path.exists():
        raise FileNotFoundError(
            f"Public key not found: {path}. "
            "Run the appropriate key-generation script first."
        )

    key = serialization.load_pem_public_key(
        path.read_bytes()
    )

    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(
            f"Expected Ed25519 public key in {path}"
        )

    return key


def load_agent_identity(agent_id: str) -> AgentKeyIdentity:
    if agent_id not in AGENT_IDS:
        raise ValueError(f"Unknown agent_id: {agent_id}")

    private_key = _read_private_key(
        private_key_path(agent_id)
    )
    public_key = _read_public_key(
        public_key_path(agent_id)
    )

    derived_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    stored_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if derived_public != stored_public:
        raise ValueError(
            f"Private/public key mismatch for {agent_id}"
        )

    return AgentKeyIdentity(
        agent_id=agent_id,
        key_id=key_id_for_agent(agent_id),
        private_key=private_key,
        public_key=public_key,
    )


def load_trust_store() -> dict[str, TrustedPublicKey]:
    trust_store: dict[str, TrustedPublicKey] = {}

    for agent_id in AGENT_IDS:
        trust_store[agent_id] = TrustedPublicKey(
            agent_id=agent_id,
            key_id=key_id_for_agent(agent_id),
            public_key=_read_public_key(
                public_key_path(agent_id)
            ),
        )

    return trust_store


def public_key_bytes(
    public_key: Ed25519PublicKey,
) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_base64(
    public_key: Ed25519PublicKey,
) -> str:
    return base64.urlsafe_b64encode(
        public_key_bytes(public_key)
    ).decode("ascii")


def sign_bytes(
    identity: AgentKeyIdentity,
    payload: bytes,
) -> str:
    signature = identity.private_key.sign(payload)
    return base64.urlsafe_b64encode(signature).decode(
        "ascii"
    )


def verify_bytes(
    trusted_key: TrustedPublicKey,
    payload: bytes,
    signature_b64: str,
) -> bool:
    try:
        signature = base64.urlsafe_b64decode(
            signature_b64.encode("ascii")
        )
        trusted_key.public_key.verify(
            signature,
            payload,
        )
        return True
    except (
        InvalidSignature,
        ValueError,
        TypeError,
    ):
        return False


def resolve_trusted_key(
    *,
    agent_id: str,
    key_id: str,
    trust_store: dict[str, TrustedPublicKey] | None = None,
) -> TrustedPublicKey:
    store = trust_store or load_trust_store()

    trusted = store.get(agent_id)
    if trusted is None:
        raise ValueError(
            f"Untrusted agent_id: {agent_id}"
        )

    if trusted.key_id != key_id:
        raise ValueError(
            f"Untrusted key_id for {agent_id}: {key_id}"
        )

    return trusted
