from __future__ import annotations

from types import SimpleNamespace

from google.protobuf.struct_pb2 import Struct

from common.agent_keys import (
    AGENT_IDS,
    load_agent_identity,
    public_key_bytes,
)
from common.fail_closed import (
    RequestReplayCache,
    verify_incoming_request_fail_closed,
)
from common.request_authentication import (
    create_request_authentication,
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


def signed_context(
    *,
    sender_id: str,
    receiver_id: str,
    message_id: str,
    text: str,
    nonce: str,
    metadata: dict | None = None,
) -> FakeContext:
    application_metadata = metadata or {}

    envelope = create_request_authentication(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_id=message_id,
        text=text,
        metadata=application_metadata,
        identity=load_agent_identity(sender_id),
        now=1000,
        ttl_seconds=60,
        nonce=nonce,
    )

    return FakeContext(
        message_id=message_id,
        text=text,
        metadata={
            **application_metadata,
            "request_authentication": envelope,
        },
    )


def verify_hop(
    *,
    context: FakeContext,
    sender_id: str,
    receiver_id: str,
) -> dict:
    return verify_incoming_request_fail_closed(
        context=context,
        expected_sender_id=sender_id,
        expected_receiver_id=receiver_id,
        replay_cache=RequestReplayCache(),
        now=1001,
    )


def test_four_principals_have_distinct_public_keys() -> None:
    assert set(AGENT_IDS) == {
        "reimbursement-client",
        "patient-agent",
        "hospital-agent",
        "insurance-agent",
    }

    keys = {
        public_key_bytes(
            load_agent_identity(agent_id).public_key
        )
        for agent_id in AGENT_IDS
    }

    assert len(keys) == 4


def test_client_to_patient_hop_is_valid() -> None:
    context = signed_context(
        sender_id="reimbursement-client",
        receiver_id="patient-agent",
        message_id="message-client-patient",
        text="I want reimbursement for treatment T123.",
        nonce="nonce-client-patient",
    )

    result = verify_hop(
        context=context,
        sender_id="reimbursement-client",
        receiver_id="patient-agent",
    )

    assert result["valid"] is True
    assert result["key_id"] == (
        "reimbursement-client-ed25519-v1"
    )


def test_patient_to_hospital_hop_is_valid() -> None:
    context = signed_context(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id="message-patient-hospital",
        text="I want reimbursement for Claim/claim-001.",
        nonce="nonce-patient-hospital",
        metadata={
            "healthcare_resources": {
                "modelVersion": "1.0",
            }
        },
    )

    result = verify_hop(
        context=context,
        sender_id="patient-agent",
        receiver_id="hospital-agent",
    )

    assert result["valid"] is True
    assert result["key_id"] == (
        "patient-agent-ed25519-v1"
    )


def test_hospital_to_insurance_hop_is_valid() -> None:
    context = signed_context(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id="message-hospital-insurance",
        text="Hospital validated Claim/claim-001.",
        nonce="nonce-hospital-insurance",
        metadata={
            "hospital_validation": {
                "status": "validated",
            }
        },
    )

    result = verify_hop(
        context=context,
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
    )

    assert result["valid"] is True
    assert result["key_id"] == (
        "hospital-agent-ed25519-v1"
    )


def test_all_hops_use_distinct_message_ids_and_nonces() -> None:
    hops = [
        signed_context(
            sender_id="reimbursement-client",
            receiver_id="patient-agent",
            message_id="message-client-patient",
            text="request",
            nonce="nonce-client-patient",
        ),
        signed_context(
            sender_id="patient-agent",
            receiver_id="hospital-agent",
            message_id="message-patient-hospital",
            text="request",
            nonce="nonce-patient-hospital",
        ),
        signed_context(
            sender_id="hospital-agent",
            receiver_id="insurance-agent",
            message_id="message-hospital-insurance",
            text="request",
            nonce="nonce-hospital-insurance",
        ),
    ]

    message_ids = {
        hop.message.message_id
        for hop in hops
    }
    nonces = {
        hop.message.metadata[
            "request_authentication"
        ].struct_value.fields["nonce"].string_value
        if False else None
        for hop in []
    }

    assert len(message_ids) == 3

    # Re-read through protobuf JSON conversion by verifying each hop and
    # collect the nonce returned by successful verification.
    results = [
        verify_hop(
            context=hops[0],
            sender_id="reimbursement-client",
            receiver_id="patient-agent",
        ),
        verify_hop(
            context=hops[1],
            sender_id="patient-agent",
            receiver_id="hospital-agent",
        ),
        verify_hop(
            context=hops[2],
            sender_id="hospital-agent",
            receiver_id="insurance-agent",
        ),
    ]

    verified_nonces = {
        result["nonce"]
        for result in results
    }

    assert len(verified_nonces) == 3


def test_client_signature_cannot_be_used_for_patient_hospital_hop() -> None:
    context = signed_context(
        sender_id="reimbursement-client",
        receiver_id="hospital-agent",
        message_id="wrong-hop",
        text="request",
        nonce="wrong-hop-nonce",
    )

    result = verify_hop(
        context=context,
        sender_id="patient-agent",
        receiver_id="hospital-agent",
    )

    assert result["valid"] is False
    assert result["reason"] == (
        "sender_id does not match expected sender"
    )
