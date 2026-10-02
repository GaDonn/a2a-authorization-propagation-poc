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


def forged_context() -> FakeContext:
    message_id = "sender-impersonation-001"
    text = "I want reimbursement for Claim/claim-001."
    metadata = {
        "healthcare_resources": {
            "modelVersion": "1.0",
        }
    }

    envelope = create_request_authentication(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id=message_id,
        text=text,
        metadata=metadata,
        identity=load_agent_identity(
            "patient-agent"
        ),
        now=1000,
        ttl_seconds=60,
        nonce="sender-impersonation-nonce",
    )

    unsigned = unsigned_envelope_dict(
        envelope
    )

    envelope["signature"] = sign_bytes(
        load_agent_identity(
            "reimbursement-client"
        ),
        signature_base_bytes(unsigned),
    )

    return FakeContext(
        message_id=message_id,
        text=text,
        metadata={
            **metadata,
            "request_authentication": envelope,
        },
    )


def test_sender_impersonation_is_rejected_at_signature_stage() -> None:
    result = verify_incoming_request_fail_closed(
        context=forged_context(),
        expected_sender_id="patient-agent",
        expected_receiver_id="hospital-agent",
        replay_cache=RequestReplayCache(),
        now=1001,
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "invalid Ed25519 request signature"
    )
    assert result["rejection_stage"] == (
        "request_signature_verification"
    )


def test_verification_cost_is_reported() -> None:
    result = verify_incoming_request_fail_closed(
        context=forged_context(),
        expected_sender_id="patient-agent",
        expected_receiver_id="hospital-agent",
        replay_cache=RequestReplayCache(),
        now=1001,
    )

    assert isinstance(
        result["verification_time_ns"],
        int,
    )
    assert result["verification_time_ns"] > 0
    assert result["verification_time_ms"] > 0


def test_application_metadata_is_not_exposed_on_rejection() -> None:
    result = verify_incoming_request_fail_closed(
        context=forged_context(),
        expected_sender_id="patient-agent",
        expected_receiver_id="hospital-agent",
        replay_cache=RequestReplayCache(),
        now=1001,
    )

    assert "metadata" not in result
    assert "text" not in result
