from __future__ import annotations

import copy
from uuid import uuid4

import httpx
from google.protobuf.struct_pb2 import Struct

from a2a.client import A2ACardResolver
from a2a.client.client import ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest

from common.request_authentication import (
    create_request_authentication,
)


def dict_to_struct(data: dict | None) -> Struct:
    struct = Struct()
    if data:
        struct.update(data)
    return struct


def extract_text_from_sdk_response(response) -> str:
    if response is None:
        return ""

    if isinstance(response, tuple):
        response = response[0]

    if hasattr(response, "parts"):
        texts = []
        for part in response.parts:
            if getattr(part, "text", ""):
                texts.append(part.text)
        return "\n".join(texts)

    if hasattr(response, "message"):
        return extract_text_from_sdk_response(response.message)

    return str(response)


async def send_message(
    agent_url: str,
    text: str,
    metadata: dict | None = None,
    *,
    sender_id: str | None = None,
    receiver_id: str | None = None,
    sign_request: bool = False,
) -> str:
    """
    Send one standard A2A Message.

    When sign_request=True, this function creates the real A2A message_id
    first and binds the request-authentication envelope to that same ID.

    The signed envelope is carried inside Message.metadata under the
    `request_authentication` key.
    """
    message_id = str(uuid4())
    outgoing_metadata = copy.deepcopy(metadata or {})

    if sign_request:
        if not sender_id or not receiver_id:
            raise ValueError(
                "sender_id and receiver_id are required "
                "when sign_request=True"
            )

        if "request_authentication" in outgoing_metadata:
            raise ValueError(
                "metadata already contains request_authentication"
            )

        envelope = create_request_authentication(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message_id=message_id,
            text=text,
            metadata=outgoing_metadata,
        )

        outgoing_metadata["request_authentication"] = envelope

    async with httpx.AsyncClient(timeout=30.0) as httpx_client:
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=agent_url,
        )

        card = await resolver.get_agent_card()

        client_factory = ClientFactory(
            config=ClientConfig(streaming=False)
        )
        client = client_factory.create(card)

        message = Message(
            message_id=message_id,
            role=Role.ROLE_USER,
            parts=[Part(text=text)],
            metadata=dict_to_struct(outgoing_metadata),
        )

        request = SendMessageRequest(
            message=message,
        )

        last_response = None

        async for response in client.send_message(request):
            last_response = response

        return extract_text_from_sdk_response(last_response)
