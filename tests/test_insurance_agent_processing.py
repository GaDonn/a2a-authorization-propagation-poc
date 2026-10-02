from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from common.healthcare_factory import (
    create_validated_patient_payload,
    dump_for_a2a,
)
from common.hospital_processing import (
    create_hospital_provenance,
    create_hospital_validation,
    prepare_hospital_forward_metadata,
    validate_healthcare_resources,
)
from common.insurance_processing import (
    make_deterministic_decision,
    resolve_reimbursement_references,
    validate_insurance_input,
)


FIXED_TIME = datetime(2026, 7, 17, 10, 10, tzinfo=timezone.utc)


def build_insurance_metadata() -> dict:
    healthcare_model, authorization_model = (
        create_validated_patient_payload(now=FIXED_TIME)
    )
    healthcare = dump_for_a2a(healthcare_model)
    authorization_details = dump_for_a2a(
        authorization_model
    )["authorization_details"]

    validated_healthcare = validate_healthcare_resources(healthcare)
    hospital_validation = create_hospital_validation(
        validated_healthcare,
        now=FIXED_TIME,
    )
    hospital_provenance = create_hospital_provenance(
        validated_healthcare,
        now=FIXED_TIME,
    )

    return prepare_hospital_forward_metadata(
        {
            "healthcare_resources": healthcare,
            "authorization_details": authorization_details,
        },
        validation=hospital_validation,
        hospital_provenance=hospital_provenance,
    )


def test_insurance_resolves_benign_references() -> None:
    metadata = build_insurance_metadata()
    healthcare, _, _, _ = validate_insurance_input(
        healthcare_resources=metadata["healthcare_resources"],
        hospital_validation=metadata["hospital_validation"],
        hospital_provenance=metadata["hospital_provenance"],
        authorization_details=metadata["authorization_details"],
    )

    assert resolve_reimbursement_references(healthcare) == {
        "patient": "Patient/patient-001",
        "coverage": "Coverage/coverage-basic-001",
        "claim": "Claim/claim-001",
    }


def test_insurance_accepts_valid_extended_input() -> None:
    metadata = build_insurance_metadata()
    healthcare, authorization, validation, _ = validate_insurance_input(
        healthcare_resources=metadata["healthcare_resources"],
        hospital_validation=metadata["hospital_validation"],
        hospital_provenance=metadata["hospital_provenance"],
        authorization_details=metadata["authorization_details"],
    )

    decision = make_deterministic_decision(
        healthcare=healthcare,
        authorization=authorization,
        hospital_validation=validation,
        now=FIXED_TIME,
    )

    assert decision.decision == "approved"
    assert decision.amount == 120
    assert decision.currency == "EUR"


def test_insurance_decision_is_deterministic() -> None:
    metadata = build_insurance_metadata()
    parsed = validate_insurance_input(
        healthcare_resources=metadata["healthcare_resources"],
        hospital_validation=metadata["hospital_validation"],
        hospital_provenance=metadata["hospital_provenance"],
        authorization_details=metadata["authorization_details"],
    )

    first = make_deterministic_decision(
        healthcare=parsed[0],
        authorization=parsed[1],
        hospital_validation=parsed[2],
        now=FIXED_TIME,
    )
    second = make_deterministic_decision(
        healthcare=parsed[0],
        authorization=parsed[1],
        hospital_validation=parsed[2],
        now=FIXED_TIME,
    )

    assert first == second


def test_insurance_rejects_claim_patient_substitution() -> None:
    metadata = build_insurance_metadata()
    metadata["healthcare_resources"]["resources"]["claim"]["patient"][
        "reference"
    ] = "Patient/patient-999"

    with pytest.raises(ValidationError):
        validate_insurance_input(
            healthcare_resources=metadata["healthcare_resources"],
            hospital_validation=metadata["hospital_validation"],
            hospital_provenance=metadata["hospital_provenance"],
            authorization_details=metadata["authorization_details"],
        )


def test_insurance_rejects_coverage_substitution() -> None:
    metadata = build_insurance_metadata()
    metadata["authorization_details"][0]["coverage"]["reference"] = (
        "Coverage/coverage-premium-999"
    )

    with pytest.raises(ValidationError, match="Coverage"):
        validate_insurance_input(
            healthcare_resources=metadata["healthcare_resources"],
            hospital_validation=metadata["hospital_validation"],
            hospital_provenance=metadata["hospital_provenance"],
            authorization_details=metadata["authorization_details"],
        )


def test_insurance_rejects_amount_above_authorization() -> None:
    metadata = build_insurance_metadata()
    claim = metadata["healthcare_resources"]["resources"]["claim"]
    claim["item"][0]["unitPrice"]["value"] = 5000
    claim["item"][0]["net"]["value"] = 5000
    claim["total"]["value"] = 5000

    with pytest.raises(ValidationError, match="exceeds"):
        validate_insurance_input(
            healthcare_resources=metadata["healthcare_resources"],
            hospital_validation=metadata["hospital_validation"],
            hospital_provenance=metadata["hospital_provenance"],
            authorization_details=metadata["authorization_details"],
        )


def test_insurance_rejects_wrong_hospital_claim_reference() -> None:
    metadata = build_insurance_metadata()
    metadata["hospital_validation"]["claim_reference"] = "Claim/claim-999"

    with pytest.raises(ValueError, match="different Claim"):
        validate_insurance_input(
            healthcare_resources=metadata["healthcare_resources"],
            hospital_validation=metadata["hospital_validation"],
            hospital_provenance=metadata["hospital_provenance"],
            authorization_details=metadata["authorization_details"],
        )


def test_insurance_rejects_wrong_hospital_provenance_agent() -> None:
    metadata = build_insurance_metadata()
    metadata["hospital_provenance"]["agent"][0]["who"]["reference"] = (
        "Organization/external-agent"
    )

    with pytest.raises(ValueError, match="hospital-agent"):
        validate_insurance_input(
            healthcare_resources=metadata["healthcare_resources"],
            hospital_validation=metadata["hospital_validation"],
            hospital_provenance=metadata["hospital_provenance"],
            authorization_details=metadata["authorization_details"],
        )


def test_baseline_input_can_be_validated_without_authorization() -> None:
    metadata = build_insurance_metadata()
    healthcare, authorization, validation, _ = validate_insurance_input(
        healthcare_resources=metadata["healthcare_resources"],
        hospital_validation=metadata["hospital_validation"],
        hospital_provenance=metadata["hospital_provenance"],
        authorization_details=None,
    )

    decision = make_deterministic_decision(
        healthcare=healthcare,
        authorization=authorization,
        hospital_validation=validation,
        now=FIXED_TIME,
    )

    assert authorization is None
    assert decision.decision == "approved"
