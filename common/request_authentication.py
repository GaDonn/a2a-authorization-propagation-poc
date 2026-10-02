from __future__ import annotations

import copy
import hashlib
import hmac
import time
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from common.agent_keys import (
    AgentKeyIdentity,
    TrustedPublicKey,
    load_agent_identity,
    load_trust_store,
    resolve_trusted_key,
    sign_bytes,
    verify_bytes,
)
from common.a2a_secure_passport_v1 import (
    SECURE_PASSPORT_URI,
)
from common.extended_secure_passport import (
    EXTENDED_SECURE_PASSPORT_URI,
)
from common.secure_passport import canonicalize_json


REQUEST_AUTHENTICATION_VERSION = "1.0"
SIGNATURE_ALGORITHM = "ed25519"
DIGEST_ALGORITHM = "sha-256"
DEFAULT_REQUEST_TTL_SECONDS = 60

PROTECTED_METADATA_FIELDS: tuple[str, ...] = (
    "healthcare_resources",
    "authorization_details",
    SECURE_PASSPORT_URI,
    EXTENDED_SECURE_PASSPORT_URI,
    "hospital_validation",
    "hospital_provenance",
)


class RequestAuthenticationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: Literal["1.0"] = "1.0"
    scheme: Literal["signed-a2a-request-envelope"] = "signed-a2a-request-envelope"
    sender_id: str = Field(min_length=1)
    receiver_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    message_id: str = Field(min_length=1)
    created_at: int
    expires_at: int
    nonce: str = Field(min_length=1)
    text_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    protected_metadata_fields: list[str]
    protected_metadata_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_algorithm: Literal["ed25519"] = "ed25519"
    digest_algorithm: Literal["sha-256"] = "sha-256"
    signature: str = Field(min_length=1)

    @field_validator("created_at", "expires_at", mode="before")
    @classmethod
    def normalize_integral_timestamp(cls, value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("timestamp must not be boolean")
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        raise ValueError("timestamp must be an integer Unix timestamp")


def sha256_text(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def select_protected_metadata(
    metadata: dict[str, Any],
    *,
    field_names: tuple[str, ...] = PROTECTED_METADATA_FIELDS,
) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise TypeError("metadata must be an object")

    selected: dict[str, Any] = {}
    for field_name in field_names:
        if field_name in metadata:
            selected[field_name] = copy.deepcopy(metadata[field_name])
    return selected


def sha256_protected_metadata(
    metadata: dict[str, Any],
    *,
    field_names: tuple[str, ...] = PROTECTED_METADATA_FIELDS,
) -> str:
    protected = select_protected_metadata(metadata, field_names=field_names)
    return hashlib.sha256(canonicalize_json(protected)).hexdigest()


def unsigned_envelope_dict(envelope: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(envelope)
    unsigned.pop("signature", None)
    return unsigned


def signature_base_bytes(unsigned_envelope: dict[str, Any]) -> bytes:
    return canonicalize_json(unsigned_envelope)


def create_request_authentication(
    *,
    sender_id: str,
    receiver_id: str,
    message_id: str,
    text: str,
    metadata: dict[str, Any],
    identity: AgentKeyIdentity | None = None,
    now: int | None = None,
    ttl_seconds: int = DEFAULT_REQUEST_TTL_SECONDS,
    nonce: str | None = None,
) -> dict[str, Any]:
    if sender_id == receiver_id:
        raise ValueError("sender_id and receiver_id must be different")
    if not message_id:
        raise ValueError("message_id is required")
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    signing_identity = identity or load_agent_identity(sender_id)
    if signing_identity.agent_id != sender_id:
        raise ValueError("signing identity does not match sender_id")

    created_at = int(time.time()) if now is None else int(now)
    protected_metadata = select_protected_metadata(metadata)

    unsigned: dict[str, Any] = {
        "version": REQUEST_AUTHENTICATION_VERSION,
        "scheme": "signed-a2a-request-envelope",
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "key_id": signing_identity.key_id,
        "message_id": message_id,
        "created_at": created_at,
        "expires_at": created_at + ttl_seconds,
        "nonce": nonce or str(uuid.uuid4()),
        "text_digest": sha256_text(text),
        "protected_metadata_fields": list(protected_metadata.keys()),
        "protected_metadata_digest": sha256_protected_metadata(metadata),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "digest_algorithm": DIGEST_ALGORITHM,
    }

    signature = sign_bytes(signing_identity, signature_base_bytes(unsigned))
    envelope = {**unsigned, "signature": signature}
    RequestAuthenticationEnvelope.model_validate(envelope)
    return envelope


def verify_request_authentication(
    *,
    envelope: dict[str, Any],
    expected_sender_id: str,
    expected_receiver_id: str,
    expected_message_id: str,
    text: str,
    metadata: dict[str, Any],
    trust_store: dict[str, TrustedPublicKey] | None = None,
    now: int | float | None = None,
    replay_cache: set[str] | None = None,
    consume_nonce: bool = False,
) -> dict[str, Any]:
    try:
        parsed = RequestAuthenticationEnvelope.model_validate(envelope)
    except Exception as error:
        return {"valid": False, "reason": f"invalid request-authentication envelope: {error}"}

    if parsed.sender_id != expected_sender_id:
        return {"valid": False, "reason": "sender_id does not match expected sender"}
    if parsed.receiver_id != expected_receiver_id:
        return {"valid": False, "reason": "receiver_id does not match expected receiver"}
    if parsed.message_id != expected_message_id:
        return {"valid": False, "reason": "message_id does not match the A2A message"}

    if now is None:
        current_time = int(time.time())
    elif isinstance(now, bool):
        return {"valid": False, "reason": "current time must not be boolean"}
    elif isinstance(now, int):
        current_time = now
    elif isinstance(now, float) and now.is_integer():
        current_time = int(now)
    else:
        return {"valid": False, "reason": "current time must be an integer Unix timestamp"}

    if parsed.expires_at <= parsed.created_at:
        return {"valid": False, "reason": "request expiration must follow creation"}
    if current_time < parsed.created_at:
        return {"valid": False, "reason": "request was created in the future"}
    if current_time > parsed.expires_at:
        return {"valid": False, "reason": "request-authentication envelope expired"}

    actual_text_digest = sha256_text(text)
    if not hmac.compare_digest(actual_text_digest, parsed.text_digest):
        return {
            "valid": False,
            "reason": "text digest mismatch",
            "expected": parsed.text_digest,
            "actual": actual_text_digest,
        }

    selected = select_protected_metadata(metadata)
    actual_fields = list(selected.keys())
    if actual_fields != parsed.protected_metadata_fields:
        return {
            "valid": False,
            "reason": "protected metadata field list mismatch",
            "expected": parsed.protected_metadata_fields,
            "actual": actual_fields,
        }

    actual_metadata_digest = sha256_protected_metadata(metadata)
    if not hmac.compare_digest(actual_metadata_digest, parsed.protected_metadata_digest):
        return {
            "valid": False,
            "reason": "protected metadata digest mismatch",
            "expected": parsed.protected_metadata_digest,
            "actual": actual_metadata_digest,
        }

    try:
        trusted_key = resolve_trusted_key(
            agent_id=parsed.sender_id,
            key_id=parsed.key_id,
            trust_store=trust_store or load_trust_store(),
        )
    except ValueError as error:
        return {"valid": False, "reason": str(error)}

    unsigned = unsigned_envelope_dict(parsed.model_dump(mode="json"))
    if not verify_bytes(
        trusted_key,
        signature_base_bytes(unsigned),
        parsed.signature,
    ):
        return {"valid": False, "reason": "invalid Ed25519 request signature"}

    if replay_cache is not None:
        if parsed.nonce in replay_cache:
            return {"valid": False, "reason": "request nonce already consumed"}
        if consume_nonce:
            replay_cache.add(parsed.nonce)

    return {
        "valid": True,
        "reason": "signed A2A request-authentication envelope valid",
        "sender_id": parsed.sender_id,
        "receiver_id": parsed.receiver_id,
        "message_id": parsed.message_id,
        "key_id": parsed.key_id,
        "nonce": parsed.nonce,
        "nonce_consumed": bool(replay_cache is not None and consume_nonce),
    }
