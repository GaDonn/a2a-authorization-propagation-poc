from copy import deepcopy
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
    validate_extended_workflow,
    validate_healthcare_resources,
)


FIXED_TIME = datetime(2026, 7, 17, 10, 5, tzinfo=timezone.utc)


def build_received_metadata() -> dict:
    healthcare_model, authorization_model = create_validated_patient_payload(
        now=FIXED_TIME
    )
    return {
        "healthcare_resources": dump_for_a2a(healthcare_model),
        "authorization_details": dump_for_a2a(
            authorization_model
        )["authorization_details"],
    }


def test_hospital_accepts_benign_healthcare_structure() -> None:
    metadata = build_received_metadata()
    model = validate_healthcare_resources(
        metadata["healthcare_resources"]
    )
    assert model.resources.claim.id == "claim-001"


def test_hospital_accepts_benign_extended_workflow() -> None:
    metadata = build_received_metadata()
    model = validate_extended_workflow(
        metadata["healthcare_resources"],
        metadata["authorization_details"],
    )
    assert model.authorization.authorization_details[0].identifier == (
        "authz-claim-001"
    )


def test_hospital_validation_is_valid() -> None:
    metadata = build_received_metadata()
    healthcare = validate_healthcare_resources(
        metadata["healthcare_resources"]
    )
    result = create_hospital_validation(
        healthcare,
        now=FIXED_TIME,
    )
    assert result.status == "validated"
    assert all(check.passed for check in result.checks)


def test_hospital_adds_separate_provenance() -> None:
    metadata = build_received_metadata()
    healthcare = validate_healthcare_resources(
        metadata["healthcare_resources"]
    )
    provenance = create_hospital_provenance(
        healthcare,
        now=FIXED_TIME,
    )
    assert provenance.target[0].reference == "Claim/claim-001"
    assert provenance.agent[0].who.reference == (
        "Organization/hospital-agent"
    )


def test_forwarding_preserves_received_objects() -> None:
    received = build_received_metadata()
    original = deepcopy(received)
    healthcare = validate_healthcare_resources(
        received["healthcare_resources"]
    )
    validation = create_hospital_validation(
        healthcare,
        now=FIXED_TIME,
    )
    provenance = create_hospital_provenance(
        healthcare,
        now=FIXED_TIME,
    )

    outgoing = prepare_hospital_forward_metadata(
        received,
        validation=validation,
        hospital_provenance=provenance,
    )

    assert received == original
    assert outgoing["healthcare_resources"] == original[
        "healthcare_resources"
    ]
    assert outgoing["authorization_details"] == original[
        "authorization_details"
    ]


def test_forwarding_adds_only_allowed_enrichment() -> None:
    received = build_received_metadata()
    healthcare = validate_healthcare_resources(
        received["healthcare_resources"]
    )
    validation = create_hospital_validation(
        healthcare,
        now=FIXED_TIME,
    )
    provenance = create_hospital_provenance(
        healthcare,
        now=FIXED_TIME,
    )

    outgoing = prepare_hospital_forward_metadata(
        received,
        validation=validation,
        hospital_provenance=provenance,
    )

    assert set(outgoing) == {
        "healthcare_resources",
        "authorization_details",
        "hospital_validation",
        "hospital_provenance",
    }


def test_beneficiary_change_is_rejected() -> None:
    metadata = build_received_metadata()
    metadata["healthcare_resources"]["resources"]["claim"][
        "patient"
    ]["reference"] = "Patient/patient-999"

    with pytest.raises(ValidationError):
        validate_healthcare_resources(
            metadata["healthcare_resources"]
        )


def test_claim_above_authorized_maximum_is_rejected() -> None:
    metadata = build_received_metadata()
    claim = metadata["healthcare_resources"]["resources"]["claim"]
    claim["item"][0]["unitPrice"]["value"] = 5000
    claim["item"][0]["net"]["value"] = 5000
    claim["total"]["value"] = 5000

    with pytest.raises(ValidationError, match="exceeds"):
        validate_extended_workflow(
            metadata["healthcare_resources"],
            metadata["authorization_details"],
        )
