from google.protobuf.json_format import MessageToDict
from pydantic import ValidationError

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message

from common.config import (
    ATTACK,
    MODE,
    REPLAY_PROTECTION,
    REQUEST_AUTHENTICATION,
)
from common.insurance_processing import (
    make_deterministic_decision,
    validate_insurance_input,
)
from common.logging_utils import log_agent_header, pretty_print
from common.secure_passport import (
    InMemoryReplayCache,
)
from common.extended_secure_passport import (
    consume_authorization_nonce,
    extract_extended_secure_passport,
    verify_authorization_details_binding,
    verify_delegation_chain,
    verify_extended_secure_passport,
)
from common.a2a_secure_passport_v1 import (
    verify_secure_passport_v1,
)

from common.fail_closed import (
    INSURANCE_REQUEST_REPLAY_CACHE,
    verify_incoming_request_fail_closed,
)

AUTHORIZATION_REPLAY_CACHE = InMemoryReplayCache()


def get_metadata(context: RequestContext) -> dict:
    if not context.message or not context.message.metadata:
        return {}
    return MessageToDict(context.message.metadata)


class InsuranceAgentExecutor(AgentExecutor):
    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        log_agent_header(
            "insurance-agent",
            MODE,
            ATTACK,
        )

        if REQUEST_AUTHENTICATION == "on":
            request_verification = (
                verify_incoming_request_fail_closed(
                    context=context,
                    expected_sender_id="hospital-agent",
                    expected_receiver_id="insurance-agent",
                    replay_cache=(
                        INSURANCE_REQUEST_REPLAY_CACHE
                    ),
                    consume_nonce=True,
                )
            )

            pretty_print(
                "FAIL-CLOSED REQUEST VERIFICATION AT INSURANCE",
                request_verification,
            )

            if not request_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request before "
                        "reimbursement processing: "
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
            f"TEXT RECEIVED BY INSURANCE: {text}"
        )

        if ATTACK != "none":
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Insurance Agent Day 9: attack execution is temporarily "
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
        hospital_validation = metadata.get("hospital_validation")
        hospital_provenance = metadata.get("hospital_provenance")

        required_application_fields = {
            "healthcare_resources": healthcare_resources,
            "hospital_validation": hospital_validation,
            "hospital_provenance": hospital_provenance,
        }
        missing = [
            name for name, value in required_application_fields.items()
            if value is None
        ]
        if missing:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Insurance rejected request: missing "
                    + ", ".join(missing)
                    + "."
                )
            )
            return

        authorization_for_validation = None

        if MODE == "baseline":
            print(
                "Baseline mode: validating the FHIR-like application workflow "
                "without additional authorization evidence."
            )

        elif MODE == "passport":
            passport_verification = verify_secure_passport_v1(
                metadata,
                expected_client_id="hospital-agent",
                require_signature=True,
            )
            pretty_print(
                "STANDARD PASSPORT VERIFICATION AT INSURANCE",
                passport_verification,
            )
            if not passport_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
                        f"{passport_verification['reason']}."
                    )
                )
                return

        elif MODE == "extended":
            if authorization_details is None:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: missing authorization_details."
                    )
                )
                return

            base_passport_verification = (
                verify_secure_passport_v1(
                    metadata,
                    expected_client_id=(
                        "hospital-agent"
                    ),
                    require_signature=True,
                )
            )

            pretty_print(
                "SECURE PASSPORT V1 VERIFICATION AT INSURANCE",
                base_passport_verification,
            )

            if not base_passport_verification[
                "valid"
            ]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
                        f"{base_passport_verification['reason']}."
                    )
                )
                return

            replay_cache = (
                AUTHORIZATION_REPLAY_CACHE
                if REPLAY_PROTECTION == "on"
                else None
            )

            passport_verification = (
                verify_extended_secure_passport(
                    extended_passport,
                    replay_cache=replay_cache,
                )
            )

            pretty_print(
                "PROPOSED EXTENDED SECURE PASSPORT "
                "VERIFICATION AT INSURANCE",
                passport_verification,
            )

            if not passport_verification["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
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
                "AUTHORIZATION-DETAILS BINDING CHECK AT INSURANCE",
                binding_check,
            )

            if not binding_check["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
                        f"{binding_check['reason']}."
                    )
                )
                return

            delegation_check = (
                verify_delegation_chain(
                    extended_passport
                )
            )

            pretty_print(
                "DELEGATION CHAIN CHECK AT INSURANCE",
                delegation_check,
            )

            if not delegation_check["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
                        f"{delegation_check['reason']}."
                    )
                )
                return

            authorization_for_validation = (
                authorization_details
            )

        else:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    f"Insurance Agent error: unknown MODE {MODE}"
                )
            )
            return

        try:
            (
                healthcare_model,
                authorization_model,
                hospital_validation_model,
                _,
            ) = validate_insurance_input(
                healthcare_resources=healthcare_resources,
                hospital_validation=hospital_validation,
                hospital_provenance=hospital_provenance,
                authorization_details=authorization_for_validation,
            )
        except (ValidationError, ValueError) as error:
            await event_queue.enqueue_event(
                new_agent_text_message(
                    "Insurance rejected request during deterministic "
                    f"validation: {error}"
                )
            )
            return

        if MODE == "extended" and REPLAY_PROTECTION == "on":
            nonce_consumption = consume_authorization_nonce(
                extended_passport,
                AUTHORIZATION_REPLAY_CACHE,
            )

            pretty_print(
                "AUTHORIZATION NONCE CONSUMPTION AT INSURANCE",
                nonce_consumption,
            )

            if not nonce_consumption["valid"]:
                await event_queue.enqueue_event(
                    new_agent_text_message(
                        "Insurance rejected request: "
                        f"{nonce_consumption['reason']}."
                    )
                )
                return

        decision = make_deterministic_decision(
            healthcare=healthcare_model,
            authorization=authorization_model,
            hospital_validation=hospital_validation_model,
        )

        pretty_print(
            "INSURANCE DETERMINISTIC DECISION",
            decision.model_dump(mode="json"),
        )

        if decision.decision == "approved":
            response = (
                "Insurance approved reimbursement for "
                f"{decision.claim_reference}, beneficiary "
                f"{decision.beneficiary_reference}, coverage "
                f"{decision.coverage_reference}, amount "
                f"{decision.amount} {decision.currency}. "
                f"Reason: {decision.reason}"
            )
        else:
            response = (
                "Insurance rejected reimbursement for "
                f"{decision.claim_reference}. Reason: {decision.reason}"
            )

        await event_queue.enqueue_event(new_agent_text_message(response))

    async def cancel(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        raise Exception("Cancel not supported")
