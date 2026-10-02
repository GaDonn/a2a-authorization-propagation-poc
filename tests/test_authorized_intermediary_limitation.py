from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from common.a2a_secure_passport_v1 import (
    attach_secure_passport_v1,
    create_caller_context,
    verify_secure_passport_v1,
)
from common.agent_keys import load_agent_identity
from common.extended_secure_passport import (
    add_delegation_entry,
    attach_extended_secure_passport,
    create_extended_secure_passport,
    verify_authorization_details_binding,
    verify_delegation_chain,
    verify_extended_secure_passport,
)
from common.healthcare_factory import (
    create_validated_patient_payload,
    dump_for_a2a,
)
from common.hospital_processing import (
    create_hospital_provenance,
    create_hospital_validation,
    prepare_hospital_forward_metadata,
    validate_extended_workflow,
    validate_healthcare_resources,
)
from common.insurance_processing import (
    make_deterministic_decision,
    validate_insurance_input,
)
from common.request_authentication import (
    create_request_authentication,
    verify_request_authentication,
)
from common.secure_passport import sha256_json


FIXED_TIME = datetime(2026, 7, 17, 10, 10, tzinfo=timezone.utc)
FIXED_UNIX = int(FIXED_TIME.timestamp())
REQUEST_TEXT = (
    "Hospital validated Claim/claim-001. "
    "Please process the reimbursement request."
)
MESSAGE_ID = "authorized-intermediary-message-001"


def test_authorized_hospital_can_replace_authorization_and_reauthenticate() -> None:
    # Build the same validated application and authorization data used by the PoC.
    healthcare_model, authorization_model = create_validated_patient_payload(
        now=FIXED_TIME
    )
    healthcare_resources = dump_for_a2a(healthcare_model)
    original_authorization_details = dump_for_a2a(authorization_model)[
        "authorization_details"
    ]

    # Build the Patient-originated C1 and C2 objects received by the Hospital.
    origin_context = create_caller_context(
        client_id="patient-agent",
        session_id="reimbursement-session-001",
        state={
            "patient_id": "P001",
            "patient_reference": "Patient/patient-001",
            "coverage_reference": "Coverage/coverage-basic-001",
            "claim_reference": "Claim/claim-001",
            "insurance_plan": "basic",
            "consent": True,
        },
        sign_state=True,
    )

    artifact = create_extended_secure_passport(
        origin_caller_context=origin_context,
        authorization_details=original_authorization_details,
        now=FIXED_UNIX,
        nonce="authorized-intermediary-auth-nonce-001",
    )
    artifact = add_delegation_entry(
        artifact,
        from_agent="patient-agent",
        to_agent="hospital-agent",
        scope=[
            "request_reimbursement",
            "send_to_hospital",
        ],
        now=FIXED_UNIX + 1,
    )

    patient_metadata = {
        "healthcare_resources": healthcare_resources,
        "authorization_details": deepcopy(original_authorization_details),
    }
    attach_secure_passport_v1(patient_metadata, origin_context)
    attach_extended_secure_passport(patient_metadata, artifact)

    # Confirm that the data received by the Hospital are initially valid.
    assert verify_secure_passport_v1(
        patient_metadata,
        expected_client_id="patient-agent",
        require_signature=True,
    )["valid"] is True
    assert verify_extended_secure_passport(
        artifact,
        now=FIXED_UNIX + 2,
    )["valid"] is True
    assert verify_authorization_details_binding(
        artifact,
        original_authorization_details,
    )["valid"] is True
    validate_extended_workflow(
        healthcare_resources,
        original_authorization_details,
    )

    # Malicious behavior by an authorized Hospital Agent:
    # widen the maximum amount, update the public hash, and use the normal
    # delegation update to recompute the shared HMAC.
    modified_authorization_details = deepcopy(original_authorization_details)
    modified_authorization_details[0]["maximum_amount"]["value"] = "9000"

    modified_artifact = deepcopy(artifact)
    modified_artifact["authorizationDetailsHash"] = sha256_json(
        modified_authorization_details
    )
    modified_artifact = add_delegation_entry(
        modified_artifact,
        from_agent="hospital-agent",
        to_agent="insurance-agent",
        scope=[
            "validate_claim",
            "request_insurance_authorization",
        ],
        now=FIXED_UNIX + 3,
    )

    # Build the legitimate Hospital enrichment and current-caller context.
    validated_healthcare = validate_healthcare_resources(healthcare_resources)
    hospital_validation = create_hospital_validation(
        validated_healthcare,
        now=FIXED_TIME,
    )
    hospital_provenance = create_hospital_provenance(
        validated_healthcare,
        now=FIXED_TIME,
    )

    outgoing_metadata = prepare_hospital_forward_metadata(
        {
            "healthcare_resources": healthcare_resources,
            "authorization_details": modified_authorization_details,
        },
        validation=hospital_validation,
        hospital_provenance=hospital_provenance,
        updated_passport=None,
    )

    hospital_context = create_caller_context(
        client_id="hospital-agent",
        session_id="reimbursement-session-001",
        state={
            "claim_reference": "Claim/claim-001",
            "patient_reference": "Patient/patient-001",
            "coverage_reference": "Coverage/coverage-basic-001",
            "validation_status": "validated",
            "source_context_client_id": "patient-agent",
        },
        sign_state=True,
    )
    attach_secure_passport_v1(outgoing_metadata, hospital_context)
    attach_extended_secure_passport(outgoing_metadata, modified_artifact)

    # The Hospital creates a fresh, valid C3 envelope with its legitimate key.
    envelope = create_request_authentication(
        sender_id="hospital-agent",
        receiver_id="insurance-agent",
        message_id=MESSAGE_ID,
        text=REQUEST_TEXT,
        metadata=outgoing_metadata,
        identity=load_agent_identity("hospital-agent"),
        now=FIXED_UNIX + 4,
        ttl_seconds=60,
        nonce="authorized-intermediary-request-nonce-001",
    )

    # Mirror the Insurance Agent verification order.
    request_check = verify_request_authentication(
        envelope=envelope,
        expected_sender_id="hospital-agent",
        expected_receiver_id="insurance-agent",
        expected_message_id=MESSAGE_ID,
        text=REQUEST_TEXT,
        metadata=outgoing_metadata,
        now=FIXED_UNIX + 5,
    )
    caller_check = verify_secure_passport_v1(
        outgoing_metadata,
        expected_client_id="hospital-agent",
        require_signature=True,
    )
    artifact_check = verify_extended_secure_passport(
        modified_artifact,
        now=FIXED_UNIX + 5,
    )
    binding_check = verify_authorization_details_binding(
        modified_artifact,
        modified_authorization_details,
    )
    delegation_check = verify_delegation_chain(modified_artifact)

    assert request_check["valid"] is True
    assert caller_check["valid"] is True
    assert artifact_check["valid"] is True
    assert binding_check["valid"] is True
    assert delegation_check["valid"] is True

    healthcare, authorization, validation, _ = validate_insurance_input(
        healthcare_resources=outgoing_metadata["healthcare_resources"],
        hospital_validation=outgoing_metadata["hospital_validation"],
        hospital_provenance=outgoing_metadata["hospital_provenance"],
        authorization_details=outgoing_metadata["authorization_details"],
    )
    decision = make_deterministic_decision(
        healthcare=healthcare,
        authorization=authorization,
        hospital_validation=validation,
        now=FIXED_TIME,
    )

    assert modified_authorization_details[0]["maximum_amount"]["value"] == "9000"
    assert decision.decision == "approved"
    assert decision.amount == 120
    assert decision.currency == "EUR"
