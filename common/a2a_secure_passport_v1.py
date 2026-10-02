from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from a2a.types import AgentExtension

from common.agent_keys import (
    key_id_for_agent,
    load_agent_identity,
    resolve_trusted_key,
    sign_bytes,
    verify_bytes,
)
from common.secure_passport import canonicalize_json


SECURE_PASSPORT_URI = (
    "https://github.com/a2aproject/a2a-samples/"
    "tree/main/samples/python/extensions/secure-passport"
)


class CallerContext(BaseModel):
    """
    Secure Passport Extension v1 CallerContext wire model.

    The aliases intentionally match the v1 specification:
      clientId, signature, sessionId, state

    Unknown fields are rejected, matching the sample implementation.
    """

    client_id: str = Field(
        ...,
        alias="clientId",
    )
    signature: str | None = Field(
        default=None,
        alias="signature",
    )
    session_id: str | None = Field(
        default=None,
        alias="sessionId",
    )
    state: dict[str, Any]

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )


def create_caller_context(
    *,
    client_id: str,
    state: dict[str, Any],
    session_id: str | None = None,
    sign_state: bool = True,
) -> CallerContext:
    """
    Create a Secure Passport v1 CallerContext.

    The extension specification defines `signature` as a digital signature
    over the complete `state` object but does not prescribe a signature
    algorithm or JSON canonicalization algorithm.

    This prototype uses the project's existing Ed25519 identity for the
    calling agent and RFC 8785 canonical JSON bytes for deterministic
    signing. This is a concrete cryptographic realization of the v1
    signature field, not an additional field in the extension.
    """
    state_copy = copy.deepcopy(state)

    signature = None
    if sign_state:
        identity = load_agent_identity(client_id)
        signature = sign_bytes(
            identity,
            canonicalize_json(state_copy),
        )

    return CallerContext(
        client_id=client_id,
        session_id=session_id,
        signature=signature,
        state=state_copy,
    )


def caller_context_to_wire(
    context: CallerContext,
) -> dict[str, Any]:
    """Serialize using the exact v1 JSON field names."""
    return context.model_dump(
        by_alias=True,
        exclude_none=True,
        mode="json",
    )


def attach_secure_passport_v1(
    metadata: dict[str, Any],
    context: CallerContext,
) -> None:
    """
    Attach the CallerContext under the mandatory Secure Passport URI key.
    """
    metadata[SECURE_PASSPORT_URI] = (
        caller_context_to_wire(context)
    )


def extract_secure_passport_v1(
    metadata: dict[str, Any],
) -> CallerContext | None:
    """
    Extract and strictly validate the CallerContext from A2A metadata.
    """
    raw = metadata.get(SECURE_PASSPORT_URI)
    if raw is None:
        return None

    try:
        return CallerContext.model_validate(
            copy.deepcopy(raw)
        )
    except ValidationError:
        return None


def verify_secure_passport_v1(
    metadata: dict[str, Any],
    *,
    expected_client_id: str | None = None,
    require_signature: bool = True,
) -> dict[str, Any]:
    """
    Verify a Secure Passport v1 CallerContext.

    Structural validation follows the extension sample.
    For this high-trust healthcare experiment, deployment policy requires the
    optional v1 `signature` field and verifies it over the complete `state`.
    """
    raw = metadata.get(SECURE_PASSPORT_URI)
    if raw is None:
        return {
            "valid": False,
            "reason": "missing Secure Passport v1 CallerContext",
        }

    try:
        context = CallerContext.model_validate(
            copy.deepcopy(raw)
        )
    except ValidationError as error:
        return {
            "valid": False,
            "reason": (
                "malformed Secure Passport v1 CallerContext: "
                f"{error}"
            ),
        }

    if (
        expected_client_id is not None
        and context.client_id != expected_client_id
    ):
        return {
            "valid": False,
            "reason": (
                "Secure Passport clientId does not match "
                "expected calling agent"
            ),
        }

    if context.signature is None:
        if require_signature:
            return {
                "valid": False,
                "reason": (
                    "missing Secure Passport state signature"
                ),
            }

        return {
            "valid": True,
            "reason": (
                "Secure Passport v1 structure valid; "
                "state is unsigned"
            ),
            "client_id": context.client_id,
            "session_id": context.session_id,
            "state": copy.deepcopy(context.state),
            "signature_verified": False,
        }

    try:
        trusted_key = resolve_trusted_key(
            agent_id=context.client_id,
            key_id=key_id_for_agent(
                context.client_id
            ),
        )
    except ValueError as error:
        return {
            "valid": False,
            "reason": str(error),
        }

    signature_valid = verify_bytes(
        trusted_key,
        canonicalize_json(context.state),
        context.signature,
    )

    if not signature_valid:
        return {
            "valid": False,
            "reason": (
                "invalid Secure Passport state signature"
            ),
        }

    return {
        "valid": True,
        "reason": (
            "Secure Passport v1 CallerContext and "
            "state signature valid"
        ),
        "client_id": context.client_id,
        "session_id": context.session_id,
        "state": copy.deepcopy(context.state),
        "signature_verified": True,
    }


def secure_passport_extension_declaration(
    *,
    supported_state_keys: list[str] | None = None,
) -> AgentExtension:
    """
    Build the AgentCard declaration required by Secure Passport v1.
    """
    params: dict[str, Any] = {}

    if supported_state_keys:
        params["supportedStateKeys"] = list(
            supported_state_keys
        )

    return AgentExtension(
        uri=SECURE_PASSPORT_URI,
        description=(
            "Receives A2A Secure Passport Extension v1 "
            "CallerContext metadata."
        ),
        required=False,
        params=params,
    )
