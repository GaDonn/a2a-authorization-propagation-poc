from __future__ import annotations

from types import SimpleNamespace

from google.protobuf.struct_pb2 import Struct

from common.agent_keys import (
    load_agent_identity,
    sign_bytes,
)
from common.fail_closed import (
    RequestReplayCache,
    verify_incoming_request_fail_closed,
)
from common.request_authentication import (
    create_request_authentication,
    signature_base_bytes,
    unsigned_envelope_dict,
)


class FakeContext:
    def __init__(
        self,
        *,
        message_id: str,
        text: str,
        metadata: dict,
    ) -> None:
        struct = Struct()
        struct.update(metadata)

        self.message = SimpleNamespace(
            message_id=message_id,
            metadata=struct,
        )
        self._text = text

    def get_user_input(self) -> str:
        return self._text


TEXT = "I want reimbursement for Claim/claim-001."
MESSAGE_ID = "a2a-message-001"
FIXED_NOW = 1001

APPLICATION_METADATA = {
    "healthcare_resources": {
        "modelVersion": "1.0",
        "resources": {
            "claim": {
                "resourceType": "Claim",
                "id": "claim-001",
            }
        },
    },
    "authorization_details": [
        {
            "type": "healthcare_reimbursement",
            "claim": {
                "reference": "Claim/claim-001",
            },
        }
    ],
}


def signed_metadata() -> dict:
    envelope = create_request_authentication(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=APPLICATION_METADATA,
        identity=load_agent_identity(
            "patient-agent"
        ),
        now=1000,
        ttl_seconds=60,
        nonce="request-nonce-001",
    )

    return {
        **APPLICATION_METADATA,
        "request_authentication": envelope,
    }


def verify_context(
    context: FakeContext,
    *,
    cache: RequestReplayCache | None = None,
) -> dict:
    return verify_incoming_request_fail_closed(
        context=context,
        expected_sender_id="patient-agent",
        expected_receiver_id="hospital-agent",
        replay_cache=cache or RequestReplayCache(),
        consume_nonce=True,
        now=FIXED_NOW,
    )


def test_legitimate_request_is_accepted() -> None:
    context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=signed_metadata(),
    )

    result = verify_context(context)

    assert result["valid"] is True
    assert result["metadata"] == APPLICATION_METADATA


def test_missing_envelope_is_rejected() -> None:
    context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=APPLICATION_METADATA,
    )

    result = verify_context(context)

    assert result["valid"] is False
    assert result["reason"] == (
        "missing request_authentication envelope"
    )


def test_wrong_signing_key_is_rejected() -> None:
    metadata = signed_metadata()
    envelope = metadata["request_authentication"]

    unsigned = unsigned_envelope_dict(envelope)
    hospital_identity = load_agent_identity(
        "hospital-agent"
    )

    envelope["signature"] = sign_bytes(
        hospital_identity,
        signature_base_bytes(unsigned),
    )

    context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=metadata,
    )

    result = verify_context(context)

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )


def test_text_tampering_is_rejected_before_application_use() -> None:
    context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT + " tampered",
        metadata=signed_metadata(),
    )

    result = verify_context(context)

    assert result["valid"] is False
    assert result["reason"] == "text digest mismatch"
    assert "metadata" not in result


def test_message_id_mismatch_is_rejected() -> None:
    context = FakeContext(
        message_id="a2a-message-999",
        text=TEXT,
        metadata=signed_metadata(),
    )

    result = verify_context(context)

    assert result["valid"] is False
    assert result["reason"] == (
        "message_id does not match the A2A message"
    )


def test_request_replay_is_rejected() -> None:
    cache = RequestReplayCache()

    first_context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=signed_metadata(),
    )
    second_context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=signed_metadata(),
    )

    first = verify_context(
        first_context,
        cache=cache,
    )
    second = verify_context(
        second_context,
        cache=cache,
    )

    assert first["valid"] is True
    assert second["valid"] is False
    assert second["reason"] == (
        "request nonce already consumed"
    )


def test_wrong_private_key_is_rejected() -> None:
    metadata = signed_metadata()
    envelope = metadata["request_authentication"]

    unsigned = unsigned_envelope_dict(envelope)
    wrong_identity = load_agent_identity(
        "hospital-agent"
    )

    envelope["signature"] = sign_bytes(
        wrong_identity,
        signature_base_bytes(unsigned),
    )

    context = FakeContext(
        message_id=MESSAGE_ID,
        text=TEXT,
        metadata=metadata,
    )

    result = verify_context(context)

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )
