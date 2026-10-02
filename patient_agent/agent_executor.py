from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

from common.config import (
    ATTACK,
    HOSPITAL_URL,
    MODE,
    REQUEST_AUTHENTICATION,
)
from common.healthcare_factory import (
    create_validated_patient_payload,
    dump_for_a2a,
)
from common.logging_utils import log_agent_header, pretty_print
from common.extended_secure_passport import (
    add_delegation_entry as add_extended_delegation_entry,
    attach_extended_secure_passport,
    create_extended_secure_passport,
)
from common.a2a_secure_passport_v1 import (
    attach_secure_passport_v1,
    create_caller_context,
)
from common.wire_client import send_message
from common.fail_closed import (
    PATIENT_REQUEST_REPLAY_CACHE,
    verify_incoming_request_fail_closed,
)

class PatientAgentExecutor(AgentExecutor):
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        user_text = context.get_user_input()

        log_agent_header(
            "patient-agent",
            MODE,
            ATTACK,
        )

        if REQUEST_AUTHENTICATION == "on":
            request_verification = (
                verify_incoming_request_fail_closed(
                    context=context,
                    expected_sender_id=(
                        "reimbursement-client"
                    ),
                    expected_receiver_id=(
                        "patient-agent"
                    ),
                    replay_cache=(
                        PATIENT_REQUEST_REPLAY_CACHE
                    ),
                    consume_nonce=True,
                )
            )

            pretty_print(
                "FAIL-CLOSED REQUEST VERIFICATION AT PATIENT",
                request_verification,
            )

            if not request_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Patient rejected request before "
                        "reimbursement processing: "
                        f"{request_verification['reason']}."
                    )
                )
                return

            text = request_verification["text"]

        else:
            text = context.get_user_input()

        print(f"USER TEXT: {text}")

        # Day 7 evaluates only the benign Patient Agent output.
        # Attack generation will be restored after all agents have been
        # migrated to the revised data model.
        if ATTACK != "none":
            response = (
                "Patient Agent Day 7: attack execution is temporarily "
                "disabled. Use ATTACK=none while validating the revised "
                "Patient Agent payload."
            )

            await event_queue.enqueue_event(
                new_agent_text_message(response)
            )
            return

        (
            healthcare_model,
            authorization_model,
        ) = create_validated_patient_payload()

        healthcare_resources = dump_for_a2a(
            healthcare_model
        )

        authorization_envelope = dump_for_a2a(
            authorization_model
        )

        authorization_details = authorization_envelope[
            "authorization_details"
        ]

        metadata = {
            "healthcare_resources": healthcare_resources,
        }

        pretty_print(
            "FHIR-LIKE HEALTHCARE RESOURCES CREATED BY PATIENT",
            healthcare_resources,
        )

        if MODE == "baseline":
            print(
                "Baseline mode: sending FHIR-like application data "
                "without additional authorization evidence."
            )

        elif MODE == "passport":
            print(
                "Passport mode: sending FHIR-like application data "
                "with a standard contextual Secure Passport."
            )

            caller_context = create_caller_context(
                client_id="patient-agent",
                session_id="reimbursement-session-001",
                state={
                    "patient_id": "P001",
                    "patient_reference": "Patient/patient-001",
                    "coverage_reference": (
                        "Coverage/coverage-basic-001"
                    ),
                    "claim_reference": "Claim/claim-001",
                    "insurance_plan": "basic",
                    "consent": True,
                },
                sign_state=True,
            )

            attach_secure_passport_v1(
                metadata,
                caller_context,
            )

            pretty_print(
                "A2A SECURE PASSPORT V1 CALLERCONTEXT CREATED",
                caller_context.model_dump(
                    by_alias=True,
                    exclude_none=True,
                    mode="json",
                ),
            )

        elif MODE == "extended":
            print(
                "Extended mode: using Secure Passport v1 "
                "plus the thesis-proposed authorization-evidence extension."
            )

            pretty_print(
                "AUTHORIZATION DETAILS CREATED BY PATIENT",
                authorization_details,
            )

            origin_context = create_caller_context(
                client_id="patient-agent",
                session_id="reimbursement-session-001",
                state={
                    "patient_id": "P001",
                    "patient_reference": "Patient/patient-001",
                    "coverage_reference": (
                        "Coverage/coverage-basic-001"
                    ),
                    "claim_reference": "Claim/claim-001",
                    "insurance_plan": "basic",
                    "consent": True,
                },
                sign_state=True,
            )

            attach_secure_passport_v1(
                metadata,
                origin_context,
            )

            extended_passport = (
                create_extended_secure_passport(
                    origin_caller_context=(
                        origin_context
                    ),
                    authorization_details=(
                        authorization_details
                    ),
                )
            )

            extended_passport = (
                add_extended_delegation_entry(
                    extended_passport,
                    from_agent="patient-agent",
                    to_agent="hospital-agent",
                    scope=[
                        "request_reimbursement",
                        "send_to_hospital",
                    ],
                )
            )

            metadata["authorization_details"] = (
                authorization_details
            )

            attach_extended_secure_passport(
                metadata,
                extended_passport,
            )

            pretty_print(
                "SECURE PASSPORT V1 ORIGIN CALLERCONTEXT",
                origin_context.model_dump(
                    by_alias=True,
                    exclude_none=True,
                    mode="json",
                ),
            )

            pretty_print(
                "PROPOSED EXTENDED SECURE PASSPORT CREATED",
                extended_passport,
            )

        else:
            response = (
                f"Patient Agent error: unknown MODE {MODE}"
            )

            await event_queue.enqueue_event(
                new_agent_text_message(response)
            )
            return

        pretty_print(
            "FINAL A2A METADATA CREATED BY PATIENT",
            metadata,
        )

        hospital_response = await send_message(
            agent_url=HOSPITAL_URL,
            text="I want reimbursement for Claim/claim-001.",
            metadata=metadata,
            sender_id="patient-agent",
            receiver_id="hospital-agent",
            sign_request=(
                REQUEST_AUTHENTICATION == "on"
            ),
        )

        final_text = (
            "Patient Agent received response from Hospital Agent:\n"
            f"{hospital_response}"
        )

        await event_queue.enqueue_event(
            new_agent_text_message(final_text)
        )

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        raise Exception("Cancel not supported")