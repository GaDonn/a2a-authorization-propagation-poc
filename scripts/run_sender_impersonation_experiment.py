from __future__ import annotations

import asyncio
import copy
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx
from google.protobuf.struct_pb2 import Struct

from a2a.client import A2ACardResolver
from a2a.client.client import ClientConfig
from a2a.client.client_factory import ClientFactory
from a2a.types import (
    Message,
    Part,
    Role,
    SendMessageRequest,
)

from common.agent_keys import (
    load_agent_identity,
    sign_bytes,
)
from common.request_authentication import (
    create_request_authentication,
    signature_base_bytes,
    unsigned_envelope_dict,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
    / "local"
    / "attacks"
    / "sender_impersonation"
)
HOSPITAL_URL = "http://127.0.0.1:12001"


def wait_for_port(
    host: str,
    port: int,
    timeout_seconds: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        try:
            with socket.create_connection(
                (host, port),
                timeout=0.5,
            ):
                return
        except OSError:
            time.sleep(0.2)

    raise TimeoutError(
        f"Service did not open {host}:{port}"
    )


def extract_response_text(response) -> str:
    if response is None:
        return ""

    if isinstance(response, tuple):
        response = response[0]

    if hasattr(response, "parts"):
        return "\n".join(
            part.text
            for part in response.parts
            if getattr(part, "text", "")
        )

    if hasattr(response, "message"):
        return extract_response_text(
            response.message
        )

    return str(response)


def forge_impersonated_envelope(
    *,
    message_id: str,
    text: str,
    metadata: dict,
) -> dict:
    """
    Declare patient-agent but sign with reimbursement-client.

    The envelope is initially created as a structurally valid Patient
    envelope. Its signature is then replaced with a signature made by the
    attacker's private key over the same canonical unsigned envelope.
    """
    envelope = create_request_authentication(
        sender_id="patient-agent",
        receiver_id="hospital-agent",
        message_id=message_id,
        text=text,
        metadata=metadata,
        identity=load_agent_identity(
            "patient-agent"
        ),
    )

    unsigned = unsigned_envelope_dict(envelope)

    attacker_identity = load_agent_identity(
        "reimbursement-client"
    )

    envelope["signature"] = sign_bytes(
        attacker_identity,
        signature_base_bytes(unsigned),
    )

    return envelope


async def send_forged_request() -> str:
    message_id = str(uuid4())
    text = "I want reimbursement for Claim/claim-001."

    application_metadata = {
        "healthcare_resources": {
            "modelVersion": "1.0",
            "resources": {},
        }
    }

    envelope = forge_impersonated_envelope(
        message_id=message_id,
        text=text,
        metadata=application_metadata,
    )

    metadata = {
        **copy.deepcopy(application_metadata),
        "request_authentication": envelope,
    }

    struct = Struct()
    struct.update(metadata)

    async with httpx.AsyncClient(
        timeout=30.0
    ) as httpx_client:
        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=HOSPITAL_URL,
        )
        card = await resolver.get_agent_card()

        client = ClientFactory(
            config=ClientConfig(streaming=False)
        ).create(card)

        message = Message(
            message_id=message_id,
            role=Role.ROLE_USER,
            parts=[Part(text=text)],
            metadata=struct,
        )

        request = SendMessageRequest(
            message=message
        )

        last_response = None

        async for response in client.send_message(
            request
        ):
            last_response = response

        return extract_response_text(
            last_response
        )


def stop_process(
    process: subprocess.Popen[str],
) -> None:
    if process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def parse_verification_block(
    hospital_log: str,
) -> dict:
    marker = (
        "--- FAIL-CLOSED REQUEST VERIFICATION "
        "AT HOSPITAL ---"
    )
    start = hospital_log.find(marker)
    if start < 0:
        return {}

    json_start = hospital_log.find("{", start)
    if json_start < 0:
        return {}

    depth = 0
    in_string = False
    escaped = False

    for index in range(
        json_start,
        len(hospital_log),
    ):
        char = hospital_log[index]

        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(
                    hospital_log[
                        json_start:index + 1
                    ]
                )

    return {}


def main() -> None:
    RESULTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    environment.update(
        {
            "MODE": "extended",
            "ATTACK": "none",
            "REQUEST_AUTHENTICATION": "on",
            "REPLAY_PROTECTION": "off",
        }
    )

    hospital_log_path = (
        RESULTS_DIR / "hospital.log"
    )
    log_file = hospital_log_path.open(
        "w",
        encoding="utf-8",
    )

    hospital = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hospital_agent",
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_port(
            "127.0.0.1",
            12001,
        )

        client_started_ns = time.perf_counter_ns()
        response = asyncio.run(
            send_forged_request()
        )
        round_trip_ns = (
            time.perf_counter_ns()
            - client_started_ns
        )

        time.sleep(0.5)

    finally:
        stop_process(hospital)
        log_file.close()

    hospital_log = hospital_log_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    verification = parse_verification_block(
        hospital_log
    )

    rejected = (
        verification.get("valid") is False
        and verification.get("reason")
        == "invalid Ed25519 request signature"
        and "Hospital rejected request before "
        "healthcare processing"
        in response
    )

    report = {
        "attack": "sender_impersonation",
        "declared_sender": "patient-agent",
        "actual_signing_key": (
            "reimbursement-client-ed25519-v1"
        ),
        "receiver": "hospital-agent",
        "accepted": not rejected,
        "rejected": rejected,
        "rejection_stage": verification.get(
            "rejection_stage"
        ),
        "error_message": verification.get(
            "reason"
        ),
        "verification_time_ns": (
            verification.get(
                "verification_time_ns"
            )
        ),
        "verification_time_ms": (
            verification.get(
                "verification_time_ms"
            )
        ),
        "client_round_trip_time_ns": (
            round_trip_ns
        ),
        "client_round_trip_time_ms": (
            round_trip_ns / 1_000_000
        ),
        "application_logic_reached": (
            "EXTENDED PASSPORT VERIFICATION "
            "AT HOSPITAL"
            in hospital_log
        ),
        "forwarded_to_insurance": (
            "FINAL METADATA FORWARDED BY HOSPITAL"
            in hospital_log
        ),
        "response": response,
        "passed": (
            rejected
            and verification.get(
                "rejection_stage"
            )
            == "request_signature_verification"
            and "EXTENDED PASSPORT VERIFICATION "
            "AT HOSPITAL"
            not in hospital_log
            and "FINAL METADATA FORWARDED BY "
            "HOSPITAL"
            not in hospital_log
        ),
    }

    report_path = (
        RESULTS_DIR
        / "sender_impersonation_report.json"
    )
    report_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    print(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
    )

    raise SystemExit(
        0 if report["passed"] else 1
    )


if __name__ == "__main__":
    main()
