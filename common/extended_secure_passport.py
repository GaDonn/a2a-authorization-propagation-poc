from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import time
import uuid
from typing import Any

from a2a.types import AgentExtension

from common.a2a_secure_passport_v1 import (
    CallerContext,
    SECURE_PASSPORT_URI,
    caller_context_to_wire,
    verify_secure_passport_v1,
)
from common.config import PASSPORT_TTL_SECONDS
from common.secure_passport import (
    DEMO_SECRET,
    InMemoryReplayCache,
    canonicalize_json,
    normalize_a2a_json,
    sha256_json,
)


EXTENDED_SECURE_PASSPORT_URI = (
    "urn:thesis:a2a:extensions:"
    "extended-secure-passport:authorization-evidence:v1"
)

EXTENDED_SECURE_PASSPORT_VERSION = "1.0"
EXTENDED_SECURE_PASSPORT_PROFILE = (
    "authorization-evidence"
)


def _artifact_payload(
    artifact: dict[str, Any],
) -> dict[str, Any]:
    payload = copy.deepcopy(artifact)
    payload.pop("integrity", None)
    return payload


def _sign_artifact(
    artifact: dict[str, Any],
) -> dict[str, str]:
    """
    Prototype artifact-integrity protection.

    This uses the locally configured shared HMAC key. It provides integrity
    for the Extended Secure Passport artifact but does NOT establish per-agent
    sender authenticity. Per-hop sender authentication remains a separate C3
    mechanism.
    """
    signature = hmac.new(
        DEMO_SECRET,
        canonicalize_json(
            _artifact_payload(artifact)
        ),
        hashlib.sha256,
    ).digest()

    return {
        "algorithm": "HMAC-SHA256-DEMO",
        "value": base64.urlsafe_b64encode(
            signature
        ).decode("ascii"),
    }


def _verify_artifact_integrity(
    artifact: dict[str, Any],
) -> bool:
    integrity = artifact.get("integrity")

    if not isinstance(integrity, dict):
        return False

    if integrity.get("algorithm") != (
        "HMAC-SHA256-DEMO"
    ):
        return False

    actual = integrity.get("value")

    if not isinstance(actual, str) or not actual:
        return False

    expected = _sign_artifact(artifact)[
        "value"
    ]

    return hmac.compare_digest(
        actual,
        expected,
    )


def create_extended_secure_passport(
    *,
    origin_caller_context: CallerContext,
    authorization_details: list[dict[str, Any]],
    now: int | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """
    Create the thesis-proposed Extended Secure Passport.

    The proposal is explicitly layered on top of Secure Passport v1:

    - the standard v1 CallerContext continues to be sent under the official
      Secure Passport URI for the current A2A caller -> callee hop;
    - this separate thesis extension carries transitive authorization evidence;
    - originCallerContext snapshots the original v1 CallerContext that began
      the delegated authorization workflow.
    """
    if not authorization_details:
        raise ValueError(
            "Extended Secure Passport requires "
            "authorization_details"
        )

    issued_at = (
        int(time.time())
        if now is None
        else int(now)
    )

    origin_wire = caller_context_to_wire(
        origin_caller_context
    )

    artifact: dict[str, Any] = {
        "version": (
            EXTENDED_SECURE_PASSPORT_VERSION
        ),
        "profile": (
            EXTENDED_SECURE_PASSPORT_PROFILE
        ),
        "baseExtensionUri": (
            SECURE_PASSPORT_URI
        ),
        "originCallerContext": (
            copy.deepcopy(origin_wire)
        ),
        "originStateHash": sha256_json(
            origin_caller_context.state
        ),
        "issuedAt": issued_at,
        "expiresAt": (
            issued_at
            + PASSPORT_TTL_SECONDS
        ),
        "nonce": (
            nonce
            or str(uuid.uuid4())
        ),
        "authorizationDetailsHash": (
            sha256_json(
                authorization_details
            )
        ),
        "delegationChain": [
            {
                "from": "user",
                "to": (
                    origin_caller_context.client_id
                ),
                "scope": [
                    "request_reimbursement"
                ],
                "timestamp": issued_at,
            }
        ],
    }

    artifact["integrity"] = (
        _sign_artifact(artifact)
    )

    return artifact


def attach_extended_secure_passport(
    metadata: dict[str, Any],
    artifact: dict[str, Any],
) -> None:
    metadata[
        EXTENDED_SECURE_PASSPORT_URI
    ] = copy.deepcopy(artifact)


def extract_extended_secure_passport(
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    raw = metadata.get(
        EXTENDED_SECURE_PASSPORT_URI
    )

    if not isinstance(raw, dict):
        return None

    return normalize_a2a_json(
        copy.deepcopy(raw)
    )


def verify_origin_caller_context(
    artifact: dict[str, Any],
    *,
    expected_origin_client_id: str = (
        "patient-agent"
    ),
) -> dict[str, Any]:
    raw_origin = artifact.get(
        "originCallerContext"
    )

    if not isinstance(raw_origin, dict):
        return {
            "valid": False,
            "reason": (
                "missing originCallerContext"
            ),
        }

    origin_metadata = {
        SECURE_PASSPORT_URI: (
            copy.deepcopy(raw_origin)
        )
    }

    verification = verify_secure_passport_v1(
        origin_metadata,
        expected_client_id=(
            expected_origin_client_id
        ),
        require_signature=True,
    )

    if not verification["valid"]:
        return {
            "valid": False,
            "reason": (
                "invalid origin CallerContext: "
                f"{verification['reason']}"
            ),
        }

    expected_hash = artifact.get(
        "originStateHash"
    )
    actual_hash = sha256_json(
        verification["state"]
    )

    if not isinstance(
        expected_hash,
        str,
    ) or not hmac.compare_digest(
        expected_hash,
        actual_hash,
    ):
        return {
            "valid": False,
            "reason": (
                "origin CallerContext state "
                "hash mismatch"
            ),
        }

    return {
        "valid": True,
        "reason": (
            "origin CallerContext valid "
            "and bound"
        ),
        "client_id": verification[
            "client_id"
        ],
        "state_hash": actual_hash,
    }


def _normalize_timestamp(
    value: object,
    field_name: str,
) -> int:
    if isinstance(value, bool):
        raise ValueError(
            f"{field_name} must be a Unix timestamp"
        )

    if isinstance(value, int):
        return value

    if (
        isinstance(value, float)
        and value.is_integer()
    ):
        return int(value)

    raise ValueError(
        f"{field_name} must be an integer "
        "Unix timestamp"
    )


def verify_extended_secure_passport(
    artifact: dict[str, Any] | None,
    replay_cache: (
        InMemoryReplayCache | None
    ) = None,
    *,
    now: int | float | None = None,
) -> dict[str, Any]:
    if not artifact:
        return {
            "valid": False,
            "reason": (
                "missing Extended Secure Passport"
            ),
        }

    if artifact.get("version") != (
        EXTENDED_SECURE_PASSPORT_VERSION
    ):
        return {
            "valid": False,
            "reason": (
                "unsupported Extended Secure "
                "Passport version"
            ),
        }

    if artifact.get("profile") != (
        EXTENDED_SECURE_PASSPORT_PROFILE
    ):
        return {
            "valid": False,
            "reason": (
                "unexpected Extended Secure "
                "Passport profile"
            ),
        }

    if artifact.get("baseExtensionUri") != (
        SECURE_PASSPORT_URI
    ):
        return {
            "valid": False,
            "reason": (
                "Extended Secure Passport is "
                "not bound to Secure Passport v1"
            ),
        }

    if not _verify_artifact_integrity(
        artifact
    ):
        return {
            "valid": False,
            "reason": (
                "invalid Extended Secure "
                "Passport artifact integrity"
            ),
        }

    try:
        issued_at = _normalize_timestamp(
            artifact.get("issuedAt"),
            "issuedAt",
        )
        expires_at = _normalize_timestamp(
            artifact.get("expiresAt"),
            "expiresAt",
        )
        current = (
            int(time.time())
            if now is None
            else _normalize_timestamp(
                now,
                "current time",
            )
        )
    except ValueError as error:
        return {
            "valid": False,
            "reason": str(error),
        }

    if expires_at <= issued_at:
        return {
            "valid": False,
            "reason": (
                "Extended Secure Passport "
                "expiration must follow issuance"
            ),
        }

    if current > expires_at:
        return {
            "valid": False,
            "reason": (
                "Extended Secure Passport expired"
            ),
        }

    nonce = artifact.get("nonce")

    if not isinstance(nonce, str) or not nonce:
        return {
            "valid": False,
            "reason": (
                "invalid authorization nonce"
            ),
        }

    if (
        replay_cache is not None
        and replay_cache.contains(nonce)
    ):
        return {
            "valid": False,
            "reason": (
                "authorization nonce already "
                "consumed"
            ),
        }

    origin_check = (
        verify_origin_caller_context(
            artifact
        )
    )

    if not origin_check["valid"]:
        return origin_check

    return {
        "valid": True,
        "reason": (
            "Extended Secure Passport valid"
        ),
        "freshness": {
            "issued_at": issued_at,
            "expires_at": expires_at,
        },
        "nonce": {
            "value": nonce,
            "replay_protected": (
                replay_cache is not None
            ),
        },
        "origin": origin_check,
    }


def verify_authorization_details_binding(
    artifact: dict[str, Any],
    authorization_details: list[dict[str, Any]],
) -> dict[str, Any]:
    if not authorization_details:
        return {
            "valid": False,
            "reason": (
                "missing authorization_details"
            ),
        }

    expected_hash = artifact.get(
        "authorizationDetailsHash"
    )

    if not isinstance(
        expected_hash,
        str,
    ) or not expected_hash:
        return {
            "valid": False,
            "reason": (
                "missing authorizationDetailsHash"
            ),
        }

    actual_hash = sha256_json(
        authorization_details
    )

    if not hmac.compare_digest(
        expected_hash,
        actual_hash,
    ):
        return {
            "valid": False,
            "reason": (
                "authorization_details "
                "hash mismatch"
            ),
            "expected": expected_hash,
            "actual": actual_hash,
        }

    return {
        "valid": True,
        "reason": (
            "authorization_details hash valid"
        ),
        "hash": actual_hash,
    }


def add_delegation_entry(
    artifact: dict[str, Any],
    *,
    from_agent: str,
    to_agent: str,
    scope: list[str],
    now: int | None = None,
) -> dict[str, Any]:
    updated = copy.deepcopy(artifact)

    timestamp = (
        int(time.time())
        if now is None
        else int(now)
    )

    updated.setdefault(
        "delegationChain",
        [],
    ).append(
        {
            "from": from_agent,
            "to": to_agent,
            "scope": copy.deepcopy(scope),
            "timestamp": timestamp,
        }
    )

    updated.pop(
        "integrity",
        None,
    )
    updated["integrity"] = (
        _sign_artifact(updated)
    )

    return updated


def verify_delegation_chain(
    artifact: dict[str, Any],
) -> dict[str, Any]:
    chain = artifact.get(
        "delegationChain"
    )

    if not isinstance(chain, list) or not chain:
        return {
            "valid": False,
            "reason": (
                "missing or invalid "
                "delegation chain"
            ),
        }

    expected_chain = [
        ("user", "patient-agent"),
        (
            "patient-agent",
            "hospital-agent",
        ),
        (
            "hospital-agent",
            "insurance-agent",
        ),
    ]

    if len(chain) != len(expected_chain):
        return {
            "valid": False,
            "reason": (
                "unexpected delegation chain "
                "length: expected "
                f"{len(expected_chain)}, "
                f"got {len(chain)}"
            ),
        }

    for index, entry in enumerate(chain):
        if not isinstance(entry, dict):
            return {
                "valid": False,
                "reason": (
                    "delegation entry "
                    f"{index} is not an object"
                ),
            }

        for field_name in (
            "from",
            "to",
            "scope",
            "timestamp",
        ):
            if field_name not in entry:
                return {
                    "valid": False,
                    "reason": (
                        "delegation entry "
                        f"{index} missing field: "
                        f"{field_name}"
                    ),
                }

        if not isinstance(
            entry["scope"],
            list,
        ):
            return {
                "valid": False,
                "reason": (
                    "delegation entry "
                    f"{index} scope is not a list"
                ),
            }

        expected_from, expected_to = (
            expected_chain[index]
        )

        if (
            entry["from"]
            != expected_from
            or entry["to"]
            != expected_to
        ):
            return {
                "valid": False,
                "reason": (
                    "unexpected delegation "
                    f"entry {index}: expected "
                    f"{expected_from} -> "
                    f"{expected_to}, got "
                    f"{entry['from']} -> "
                    f"{entry['to']}"
                ),
            }

    return {
        "valid": True,
        "reason": (
            "delegation chain structure "
            "and expected path valid"
        ),
        "chain_length": len(chain),
    }


def consume_authorization_nonce(
    artifact: dict[str, Any],
    replay_cache: (
        InMemoryReplayCache | None
    ),
) -> dict[str, Any]:
    if replay_cache is None:
        return {
            "valid": True,
            "reason": (
                "replay cache disabled; "
                "nonce not consumed"
            ),
            "replay_protected": False,
        }

    nonce = artifact.get("nonce")

    if not isinstance(nonce, str) or not nonce:
        return {
            "valid": False,
            "reason": (
                "missing or invalid "
                "authorization nonce"
            ),
            "replay_protected": True,
        }

    if not replay_cache.consume(nonce):
        return {
            "valid": False,
            "reason": (
                "authorization nonce already "
                "consumed"
            ),
            "replay_protected": True,
            "nonce": nonce,
        }

    return {
        "valid": True,
        "reason": (
            "authorization nonce consumed"
        ),
        "replay_protected": True,
        "nonce": nonce,
    }


def extended_secure_passport_extension_declaration(
) -> AgentExtension:
    return AgentExtension(
        uri=EXTENDED_SECURE_PASSPORT_URI,
        description=(
            "Thesis-proposed extension layered on "
            "A2A Secure Passport v1 to carry "
            "transitive fine-grained authorization "
            "and delegation evidence."
        ),
        required=False,
        params={
            "baseExtensionUri": (
                SECURE_PASSPORT_URI
            ),
            "profile": (
                EXTENDED_SECURE_PASSPORT_PROFILE
            ),
        },
    )
