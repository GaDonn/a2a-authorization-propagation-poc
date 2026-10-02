from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter_ns
from typing import Any

from google.protobuf.json_format import MessageToDict

from a2a.server.agent_execution import RequestContext

from common.request_authentication import (
    verify_request_authentication,
)


@dataclass
class RequestReplayCache:
    consumed_nonces: set[str] = field(default_factory=set)

    def clear(self) -> None:
        self.consumed_nonces.clear()


PATIENT_REQUEST_REPLAY_CACHE = RequestReplayCache()
HOSPITAL_REQUEST_REPLAY_CACHE = RequestReplayCache()
INSURANCE_REQUEST_REPLAY_CACHE = RequestReplayCache()


def extract_message_metadata(
    context: RequestContext,
) -> dict[str, Any]:
    if not context.message or not context.message.metadata:
        return {}

    return MessageToDict(context.message.metadata)


def extract_message_id(
    context: RequestContext,
) -> str:
    if not context.message:
        return ""

    return str(
        getattr(context.message, "message_id", "") or ""
    )


def remove_request_authentication(
    metadata: dict[str, Any],
) -> dict[str, Any]:
    cleaned = dict(metadata)
    cleaned.pop("request_authentication", None)
    return cleaned


def rejection_stage(reason: str) -> str:
    if reason == "invalid Ed25519 request signature":
        return "request_signature_verification"
    if reason == "text digest mismatch":
        return "request_text_digest_verification"
    if reason == "protected metadata digest mismatch":
        return "protected_metadata_digest_verification"
    if reason == "request nonce already consumed":
        return "request_nonce_verification"
    if "expired" in reason or "future" in reason:
        return "request_timestamp_verification"
    if "sender_id" in reason:
        return "sender_identity_verification"
    if "receiver_id" in reason:
        return "receiver_identity_verification"
    if "message_id" in reason:
        return "message_id_binding_verification"
    if "key_id" in reason or "Untrusted agent_id" in reason:
        return "trusted_key_resolution"
    return "request_authentication_verification"


def verify_incoming_request_fail_closed(
    *,
    context: RequestContext,
    expected_sender_id: str,
    expected_receiver_id: str,
    replay_cache: RequestReplayCache,
    consume_nonce: bool = True,
    now: int | float | None = None,
) -> dict[str, Any]:
    """
    Verify request authentication at AgentExecutor entry.

    The reported cost measures only the project request-authentication
    verification call. It excludes HTTP transport, A2A SDK parsing,
    application processing, logging, and response serialization.
    """
    if not context.message:
        return {
            "valid": False,
            "reason": "missing A2A message",
            "rejection_stage": "a2a_message_extraction",
        }

    metadata = extract_message_metadata(context)
    envelope = metadata.get("request_authentication")

    if envelope is None:
        return {
            "valid": False,
            "reason": "missing request_authentication envelope",
            "rejection_stage": "request_envelope_extraction",
        }

    message_id = extract_message_id(context)
    if not message_id:
        return {
            "valid": False,
            "reason": "missing A2A message_id",
            "rejection_stage": "message_id_extraction",
        }

    text = context.get_user_input()
    application_metadata = remove_request_authentication(
        metadata
    )

    started_ns = perf_counter_ns()

    verification = verify_request_authentication(
        envelope=envelope,
        expected_sender_id=expected_sender_id,
        expected_receiver_id=expected_receiver_id,
        expected_message_id=message_id,
        text=text,
        metadata=application_metadata,
        replay_cache=replay_cache.consumed_nonces,
        consume_nonce=consume_nonce,
        now=now,
    )

    elapsed_ns = perf_counter_ns() - started_ns

    measured = {
        **verification,
        "verification_time_ns": elapsed_ns,
        "verification_time_ms": elapsed_ns / 1_000_000,
    }

    if not measured["valid"]:
        measured["rejection_stage"] = rejection_stage(
            measured["reason"]
        )
        return measured

    return {
        **measured,
        "metadata": application_metadata,
        "text": text,
        "message_id": message_id,
    }
