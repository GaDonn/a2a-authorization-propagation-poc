from google.protobuf.json_format import MessageToDict
from pydantic import ValidationError

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

from common.config import (
    ATTACK,
    INSURANCE_URL,
    MODE,
    REQUEST_AUTHENTICATION,
)
from common.hospital_processing import (
    create_hospital_provenance,
    create_hospital_validation,
    prepare_hospital_forward_metadata,
    validate_extended_workflow,
    validate_healthcare_resources,
)
from common.logging_utils import log_agent_header, pretty_print
from common.extended_secure_passport import (
    add_delegation_entry as add_extended_delegation_entry,
    attach_extended_secure_passport,
    extract_extended_secure_passport,
    verify_authorization_details_binding,
    verify_extended_secure_passport,
)
from common.a2a_secure_passport_v1 import (
    attach_secure_passport_v1,
    create_caller_context,
    verify_secure_passport_v1,
)
from common.wire_client import send_message

from common.fail_closed import (
    HOSPITAL_REQUEST_REPLAY_CACHE,
    verify_incoming_request_fail_closed,
)

def get_metadata(context: RequestContext) -> dict:
    if not context.message or not context.message.metadata:
        return {}
    return MessageToDict(context.message.metadata)


class HospitalAgentExecutor(AgentExecutor):
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        log_agent_header(
            "hospital-agent",
            MODE,
            ATTACK,
        )

        if REQUEST_AUTHENTICATION == "on":
            request_verification = (
                verify_incoming_request_fail_closed(
                    context=context,
                    expected_sender_id="patient-agent",
                    expected_receiver_id="hospital-agent",
                    replay_cache=(
                        HOSPITAL_REQUEST_REPLAY_CACHE
                    ),
                    consume_nonce=True,
                )
            )

            pretty_print(
                "FAIL-CLOSED REQUEST VERIFICATION AT HOSPITAL",
                request_verification,
            )

            if not request_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request before "
                        "healthcare processing: "
                        f"{request_verification['reason']}."
                    )
                )
                return

            text = request_verification["text"]
            metadata = request_verification["metadata"]

        else:
            text = context.get_user_input()
            metadata = get_metadata(context)

        print(
            f"TEXT RECEIVED BY HOSPITAL: {text}"
        )

        if ATTACK != "none":
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Hospital Agent Day 8: attack execution is temporarily "
                    "disabled. Use ATTACK=none."
                )
            )
            return

        healthcare_resources = metadata.get("healthcare_resources")
        authorization_details = metadata.get("authorization_details")
        extended_passport = (
            extract_extended_secure_passport(
                metadata
            )
        )

        if healthcare_resources is None:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Hospital rejected request: missing healthcare_resources."
                )
            )
            return

        try:
            healthcare_model = validate_healthcare_resources(
                healthcare_resources
            )
        except ValidationError as error:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Hospital rejected request: invalid healthcare resources: "
                    f"{error}"
                )
            )
            return

        updated_passport = None

        if MODE == "baseline":
            print(
                "Baseline mode: application data validated without "
                "additional authorization evidence."
            )

        elif MODE == "passport":
            verification = verify_secure_passport_v1(
                metadata,
                expected_client_id="patient-agent",
                require_signature=True,
            )
            pretty_print(
                "STANDARD PASSPORT VERIFICATION AT HOSPITAL",
                verification,
            )

            if not verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: "
                        f"{verification['reason']}."
                    )
                )
                return

        elif MODE == "extended":
            if authorization_details is None:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: missing authorization_details."
                    )
                )
                return

            base_passport_verification = (
                verify_secure_passport_v1(
                    metadata,
                    expected_client_id=(
                        "patient-agent"
                    ),
                    require_signature=True,
                )
            )

            pretty_print(
                "SECURE PASSPORT V1 VERIFICATION AT HOSPITAL",
                base_passport_verification,
            )

            if not base_passport_verification[
                "valid"
            ]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: "
                        f"{base_passport_verification['reason']}."
                    )
                )
                return

            passport_verification = (
                verify_extended_secure_passport(
                    extended_passport
                )
            )

            pretty_print(
                "PROPOSED EXTENDED SECURE PASSPORT "
                "VERIFICATION AT HOSPITAL",
                passport_verification,
            )

            if not passport_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: "
                        f"{passport_verification['reason']}."
                    )
                )
                return

            binding_check = (
                verify_authorization_details_binding(
                    extended_passport,
                    authorization_details,
                )
            )

            pretty_print(
                "AUTHORIZATION-DETAILS BINDING CHECK AT HOSPITAL",
                binding_check,
            )

            if not binding_check["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: "
                        f"{binding_check['reason']}."
                    )
                )
                return

            try:
                validate_extended_workflow(
                    healthcare_resources,
                    authorization_details,
                )
            except ValidationError as error:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Hospital rejected request: healthcare resources "
                        "and authorization details are inconsistent: "
                        f"{error}"
                    )
                )
                return

            updated_passport = (
                add_extended_delegation_entry(
                    extended_passport,
                    from_agent="hospital-agent",
                    to_agent="insurance-agent",
                    scope=[
                        "validate_claim",
                        "request_insurance_authorization",
                    ],
                )
            )

        else:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    f"Hospital Agent error: unknown MODE {MODE}"
                )
            )
            return

        try:
            validation = create_hospital_validation(
                healthcare_model
            )
            hospital_provenance = create_hospital_provenance(
                healthcare_model
            )
        except (ValidationError, ValueError) as error:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Hospital rejected request during application "
                    f"validation: {error}"
                )
            )
            return

        outgoing_metadata = prepare_hospital_forward_metadata(
            metadata,
            validation=validation,
            hospital_provenance=hospital_provenance,
            updated_passport=None,
        )

        if MODE == "extended":
            hospital_context = create_caller_context(
                client_id="hospital-agent",
                session_id="reimbursement-session-001",
                state={
                    "claim_reference": "Claim/claim-001",
                    "patient_reference": "Patient/patient-001",
                    "coverage_reference": (
                        "Coverage/coverage-basic-001"
                    ),
                    "validation_status": "validated",
                    "source_context_client_id": (
                        "patient-agent"
                    ),
                },
                sign_state=True,
            )

            attach_secure_passport_v1(
                outgoing_metadata,
                hospital_context,
            )

            attach_extended_secure_passport(
                outgoing_metadata,
                updated_passport,
            )

            pretty_print(
                "SECURE PASSPORT V1 CALLERCONTEXT "
                "CREATED BY HOSPITAL FOR INSURANCE",
                hospital_context.model_dump(
                    by_alias=True,
                    exclude_none=True,
                    mode="json",
                ),
            )

            pretty_print(
                "UPDATED PROPOSED EXTENDED SECURE PASSPORT",
                updated_passport,
            )

        if MODE == "passport":
            hospital_context = create_caller_context(
                client_id="hospital-agent",
                session_id="reimbursement-session-001",
                state={
                    "claim_reference": "Claim/claim-001",
                    "patient_reference": "Patient/patient-001",
                    "coverage_reference": (
                        "Coverage/coverage-basic-001"
                    ),
                    "validation_status": "validated",
                    "source_context_client_id": (
                        "patient-agent"
                    ),
                },
                sign_state=True,
            )

            attach_secure_passport_v1(
                outgoing_metadata,
                hospital_context,
            )

            pretty_print(
                "A2A SECURE PASSPORT V1 CALLERCONTEXT "
                "CREATED BY HOSPITAL",
                hospital_context.model_dump(
                    by_alias=True,
                    exclude_none=True,
                    mode="json",
                ),
            )

        pretty_print(
            "FINAL METADATA FORWARDED BY HOSPITAL",
            outgoing_metadata,
        )

        insurance_response = await send_message(
            agent_url=INSURANCE_URL,
            text=(
                "Hospital validated Claim/claim-001. "
                "Please process the reimbursement request."
            ),
            metadata=outgoing_metadata,
            sender_id="hospital-agent",
            receiver_id="insurance-agent",
            sign_request=(
                REQUEST_AUTHENTICATION == "on"
            ),
        )

        await event_queue.enqueue_event(
            new_agent_text_message(
                "Hospital Agent received from Insurance Agent:\n"
                f"{insurance_response}"
            )
        )

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        raise Exception("Cancel not supported")
