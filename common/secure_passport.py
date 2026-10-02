from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import rfc8785

from common.config import PASSPORT_TTL_SECONDS


def _load_hmac_secret() -> bytes:
    value = os.getenv("A2A_HMAC_SECRET", "")
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("A2A_HMAC_SECRET must contain 64 hexadecimal characters") from error
    if len(value) != 64 or len(key) != 32:
        raise ValueError(
            "Configure A2A_HMAC_SECRET with 64 hexadecimal characters. "
            "Run python -m scripts.generate_demo_secret first."
        )
    return key


# Compatibility name retained for the evaluated modules; no default key is shipped.
DEMO_SECRET = _load_hmac_secret()


# ---------------------------------------------------------------------
# RFC 8785 canonicalization
# ---------------------------------------------------------------------

def normalize_a2a_json(value: Any) -> Any:
    """
    Normalize values received through protobuf Struct.

    protobuf Struct represents JSON numbers as doubles. Values such as 120
    can therefore arrive as 120.0. Converting integral floats back to int
    keeps the application representation stable before RFC 8785
    canonicalization.

    This helper does not reorder arrays and does not alter non-integral
    numbers.
    """
    if isinstance(value, dict):
        return {
            str(key): normalize_a2a_json(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [normalize_a2a_json(item) for item in value]

    if isinstance(value, float) and value.is_integer():
        return int(value)

    return value


def canonicalize_json(value: Any) -> bytes:
    """
    Return RFC 8785 JSON Canonicalization Scheme output as UTF-8 bytes.

    RFC 8785 recursively sorts object properties and preserves array order.
    """
    normalized = normalize_a2a_json(value)
    return rfc8785.dumps(normalized)


def canonical_json(value: Any) -> str:
    """Human-readable UTF-8 form of the RFC 8785 canonical bytes."""
    return canonicalize_json(value).decode("utf-8")


def sha256_json(value: Any) -> str:
    """Return lowercase hexadecimal SHA-256 over RFC 8785 bytes."""
    return hashlib.sha256(canonicalize_json(value)).hexdigest()


# Compatibility name used by non-security helper code.
def sha256_dict(value: Any) -> str:
    return sha256_json(value)


# ---------------------------------------------------------------------
# Prototype HMAC passport integrity
# ---------------------------------------------------------------------

def sign_dict(data: dict) -> str:
    """
    Sign a canonical passport representation with the prototype HMAC key.

    This protects passport integrity in the current configurations. It does
    not establish per-agent sender authenticity. Per-agent Ed25519 request
    authentication is introduced separately in the later signed-request
    configuration.
    """
    signature = hmac.new(
        DEMO_SECRET,
        canonicalize_json(data),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii")


def verify_signature(data: dict, signature: str) -> bool:
    expected = sign_dict(data)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------
# Replay cache
# ---------------------------------------------------------------------

@dataclass
class InMemoryReplayCache:
    """
    Process-local cache for consumed authorization-artifact nonces.

    It is suitable for controlled experiments only. It is not distributed
    and is cleared when the process restarts.
    """

    consumed_nonces: set[str] = field(default_factory=set)

    def contains(self, nonce: str) -> bool:
        return nonce in self.consumed_nonces

    def consume(self, nonce: str) -> bool:
        if nonce in self.consumed_nonces:
            return False
        self.consumed_nonces.add(nonce)
        return True

    def clear(self) -> None:
        self.consumed_nonces.clear()


def verify_authorization_nonce_available(
    passport: dict,
    replay_cache: InMemoryReplayCache | None,
) -> dict:
    if not passport:
        return {"valid": False, "reason": "missing passport"}

    nonce = passport.get("nonce")

    if nonce is None:
        return {
            "valid": True,
            "reason": "standard passport has no authorization nonce",
            "replay_protected": False,
        }

    if not isinstance(nonce, str) or not nonce:
        return {
            "valid": False,
            "reason": "invalid authorization nonce",
            "replay_protected": replay_cache is not None,
        }

    if replay_cache is None:
        return {
            "valid": True,
            "reason": "authorization nonce present but replay cache disabled",
            "replay_protected": False,
            "nonce": nonce,
        }

    if replay_cache.contains(nonce):
        return {
            "valid": False,
            "reason": "authorization nonce already consumed",
            "replay_protected": True,
            "nonce": nonce,
        }

    return {
        "valid": True,
        "reason": "authorization nonce is available",
        "replay_protected": True,
        "nonce": nonce,
    }


def consume_authorization_nonce(
    passport: dict,
    replay_cache: InMemoryReplayCache | None,
) -> dict:
    """
    Consume the nonce only after all required passport, binding, delegation,
    and application checks have succeeded.
    """
    if replay_cache is None:
        return {
            "valid": True,
            "reason": "replay cache disabled; nonce not consumed",
            "replay_protected": False,
        }

    nonce = passport.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return {
            "valid": False,
            "reason": "missing or invalid authorization nonce",
            "replay_protected": True,
        }

    if not replay_cache.consume(nonce):
        return {
            "valid": False,
            "reason": "authorization nonce already consumed",
            "replay_protected": True,
            "nonce": nonce,
        }

    return {
        "valid": True,
        "reason": "authorization nonce consumed",
        "replay_protected": True,
        "nonce": nonce,
    }


# ---------------------------------------------------------------------
# Passport creation
# ---------------------------------------------------------------------

def create_secure_passport(
    caller_id: str,
    context_state: dict,
    authorization_details: list[dict] | None = None,
    extended: bool = False,
    *,
    now: int | None = None,
    nonce: str | None = None,
) -> dict:
    """
    Create a standard or extended Secure Passport.

    Standard passport:
        version, passport_type, client_id, state, signature

    Extended passport additionally contains:
        issued_at, expires_at, nonce,
        authorization_details_hash, delegation_chain
    """
    issued_at = int(time.time()) if now is None else int(now)

    passport = {
        "version": "1.0",
        "passport_type": "extended" if extended else "standard",
        "client_id": caller_id,
        "state": copy.deepcopy(context_state),
    }

    if extended:
        if not authorization_details:
            raise ValueError(
                "extended passport requires authorization_details"
            )

        passport["issued_at"] = issued_at
        passport["expires_at"] = issued_at + PASSPORT_TTL_SECONDS
        passport["nonce"] = nonce or str(uuid.uuid4())
        passport["authorization_details_hash"] = sha256_json(
            authorization_details
        )
        passport["delegation_chain"] = [
            {
                "from": "user",
                "to": caller_id,
                "scope": ["request_reimbursement"],
                "timestamp": issued_at,
            }
        ]

    passport["signature"] = sign_dict(passport)
    return passport


# ---------------------------------------------------------------------
# Passport verification
# ---------------------------------------------------------------------

def verify_signature_only(passport: dict) -> dict:
    if not passport:
        return {"valid": False, "reason": "missing passport"}

    signature = passport.get("signature")
    if not isinstance(signature, str) or not signature:
        return {"valid": False, "reason": "missing signature"}

    payload = copy.deepcopy(passport)
    payload.pop("signature", None)

    if not verify_signature(payload, signature):
        return {"valid": False, "reason": "invalid signature"}

    return {"valid": True, "reason": "signature valid"}


def verify_freshness(
    passport: dict,
    *,
    now: int | float | None = None,
) -> dict:
    if not passport:
        return {"valid": False, "reason": "missing passport"}

    if passport.get("passport_type") == "standard":
        return {
            "valid": True,
            "reason": "standard passport has no freshness fields",
            "freshness_protected": False,
        }

    issued_at = passport.get("issued_at")
    expires_at = passport.get("expires_at")

    def normalize_timestamp(
        value: object,
        field_name: str,
    ) -> int:
        """
        Accept integer timestamps and integral floats produced by
        protobuf Struct, for example 1784308302.0.
        """

        if isinstance(value, bool):
            raise ValueError(
                f"{field_name} must be a Unix timestamp"
            )

        if isinstance(value, int):
            return value

        if isinstance(value, float) and value.is_integer():
            return int(value)

        raise ValueError(
            f"{field_name} must be an integer Unix timestamp"
        )

    try:
        issued_at_value = normalize_timestamp(
            issued_at,
            "issued_at",
        )
        expires_at_value = normalize_timestamp(
            expires_at,
            "expires_at",
        )
    except ValueError as error:
        return {
            "valid": False,
            "reason": str(error),
            "freshness_protected": True,
        }

    if now is None:
        current = int(time.time())
    else:
        try:
            current = normalize_timestamp(
                now,
                "current time",
            )
        except ValueError as error:
            return {
                "valid": False,
                "reason": str(error),
                "freshness_protected": True,
            }

    if expires_at_value <= issued_at_value:
        return {
            "valid": False,
            "reason": "passport expiration must follow issuance",
            "freshness_protected": True,
        }

    if current > expires_at_value:
        return {
            "valid": False,
            "reason": "passport expired",
            "freshness_protected": True,
        }

    return {
        "valid": True,
        "reason": "passport freshness valid",
        "freshness_protected": True,
        "issued_at": issued_at_value,
        "expires_at": expires_at_value,
    }


def verify_secure_passport(
    passport: dict,
    replay_cache: InMemoryReplayCache | None = None,
    *,
    now: int | None = None,
) -> dict:
    """
    Verify signature, freshness, and nonce availability.

    This function never consumes the nonce. Consumption must happen only
    after all other mandatory checks succeed.
    """
    signature_check = verify_signature_only(passport)
    if not signature_check["valid"]:
        return signature_check

    freshness_check = verify_freshness(passport, now=now)
    if not freshness_check["valid"]:
        return freshness_check

    nonce_check = verify_authorization_nonce_available(
        passport,
        replay_cache,
    )
    if not nonce_check["valid"]:
        return nonce_check

    return {
        "valid": True,
        "reason": "passport verification valid",
        "signature": signature_check,
        "freshness": freshness_check,
        "nonce": nonce_check,
    }


# ---------------------------------------------------------------------
# Authorization-details binding
# ---------------------------------------------------------------------

def verify_authorization_details_binding(
    passport: dict,
    authorization_details: list[dict],
) -> dict:
    if not passport:
        return {"valid": False, "reason": "missing passport"}

    if not authorization_details:
        return {
            "valid": False,
            "reason": "missing authorization_details",
        }

    expected_hash = passport.get("authorization_details_hash")
    if not isinstance(expected_hash, str) or not expected_hash:
        return {
            "valid": False,
            "reason": "missing authorization_details_hash",
        }

    actual_hash = sha256_json(authorization_details)

    if not hmac.compare_digest(actual_hash, expected_hash):
        return {
            "valid": False,
            "reason": "authorization_details hash mismatch",
            "expected": expected_hash,
            "actual": actual_hash,
        }

    return {
        "valid": True,
        "reason": "authorization_details hash valid",
        "hash": actual_hash,
    }


# ---------------------------------------------------------------------
# Delegation chain
# ---------------------------------------------------------------------

def add_delegation_entry(
    passport: dict,
    from_agent: str,
    to_agent: str,
    scope: list[str],
    *,
    now: int | None = None,
) -> dict:
    updated = copy.deepcopy(passport)
    timestamp = int(time.time()) if now is None else int(now)

    updated.setdefault("delegation_chain", []).append(
        {
            "from": from_agent,
            "to": to_agent,
            "scope": copy.deepcopy(scope),
            "timestamp": timestamp,
        }
    )

    updated.pop("signature", None)
    updated["signature"] = sign_dict(updated)
    return updated


def verify_delegation_chain(passport: dict) -> dict:
    if not passport:
        return {"valid": False, "reason": "missing passport"}

    chain = passport.get("delegation_chain")
    if not isinstance(chain, list) or not chain:
        return {
            "valid": False,
            "reason": "missing or invalid delegation chain",
        }

    expected_chain = [
        ("user", "patient-agent"),
        ("patient-agent", "hospital-agent"),
        ("hospital-agent", "insurance-agent"),
    ]

    if len(chain) != len(expected_chain):
        return {
            "valid": False,
            "reason": (
                "unexpected delegation chain length: "
                f"expected {len(expected_chain)}, got {len(chain)}"
            ),
            "chain_length": len(chain),
        }

    for index, entry in enumerate(chain):
        if not isinstance(entry, dict):
            return {
                "valid": False,
                "reason": f"delegation entry {index} is not an object",
            }

        for field_name in ("from", "to", "scope", "timestamp"):
            if field_name not in entry:
                return {
                    "valid": False,
                    "reason": (
                        f"delegation entry {index} missing field: "
                        f"{field_name}"
                    ),
                }

        if not isinstance(entry["scope"], list):
            return {
                "valid": False,
                "reason": f"delegation entry {index} scope is not a list",
            }

        expected_from, expected_to = expected_chain[index]
        if (
            entry["from"] != expected_from
            or entry["to"] != expected_to
        ):
            return {
                "valid": False,
                "reason": (
                    f"unexpected delegation entry {index}: expected "
                    f"{expected_from} -> {expected_to}, got "
                    f"{entry['from']} -> {entry['to']}"
                ),
            }

    return {
        "valid": True,
        "reason": "delegation chain structure and expected path valid",
        "chain_length": len(chain),
    }


def is_standard_passport(passport: dict) -> bool:
    return bool(passport) and passport.get("passport_type") == "standard"


def is_extended_passport(passport: dict) -> bool:
    return bool(passport) and passport.get("passport_type") == "extended"
