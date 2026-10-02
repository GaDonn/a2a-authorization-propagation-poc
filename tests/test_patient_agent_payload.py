from datetime import datetime, timezone

from common.healthcare_factory import (
    create_validated_patient_payload,
    dump_for_a2a,
)
from common.secure_passport import (
    add_delegation_entry,
    create_secure_passport,
    verify_authorization_details_binding,
    verify_secure_passport,
)


FIXED_TIME = datetime(
    2026,
    7,
    17,
    10,
    0,
    0,
    tzinfo=timezone.utc,
)


def build_metadata() -> dict:
    (
        healthcare_model,
        authorization_model,
    ) = create_validated_patient_payload(
        now=FIXED_TIME
    )

    healthcare_resources = dump_for_a2a(
        healthcare_model
    )

    authorization_details = dump_for_a2a(
        authorization_model
    )["authorization_details"]

    passport = create_secure_passport(
        caller_id="patient-agent",
        context_state={
            "patient_id": "P001",
            "patient_reference": "Patient/patient-001",
            "coverage_reference": (
                "Coverage/coverage-basic-001"
            ),
            "claim_reference": "Claim/claim-001",
            "insurance_plan": "basic",
            "consent": True,
        },
        authorization_details=authorization_details,
        extended=True,
    )

    passport = add_delegation_entry(
        passport=passport,
        from_agent="patient-agent",
        to_agent="hospital-agent",
        scope=[
            "request_reimbursement",
            "send_to_hospital",
        ],
    )

    return {
        "healthcare_resources": healthcare_resources,
        "authorization_details": authorization_details,
        "secure_passport": passport,
    }


def test_patient_metadata_has_three_separate_objects() -> None:
    metadata = build_metadata()

    assert set(metadata) == {
        "healthcare_resources",
        "authorization_details",
        "secure_passport",
    }


def test_healthcare_resources_contain_four_resources() -> None:
    metadata = build_metadata()

    resources = metadata[
        "healthcare_resources"
    ]["resources"]

    assert set(resources) == {
        "patient",
        "coverage",
        "claim",
        "provenance",
    }


def test_authorization_details_are_separate_from_claim() -> None:
    metadata = build_metadata()

    claim = metadata[
        "healthcare_resources"
    ]["resources"]["claim"]

    authorization = metadata[
        "authorization_details"
    ][0]

    assert authorization["claim"]["reference"] == (
        f"Claim/{claim['id']}"
    )

    assert "authorization_details" not in claim


def test_output_uses_fhir_class_alias() -> None:
    metadata = build_metadata()

    coverage = metadata[
        "healthcare_resources"
    ]["resources"]["coverage"]

    assert "class" in coverage
    assert "class_" not in coverage


def test_patient_payload_is_stable_for_fixed_time() -> None:
    first = build_metadata()
    second = build_metadata()

    assert (
        first["healthcare_resources"]
        ==
        second["healthcare_resources"]
    )

    assert (
        first["authorization_details"]
        ==
        second["authorization_details"]
    )


def test_current_passport_signature_is_valid() -> None:
    metadata = build_metadata()

    result = verify_secure_passport(
        metadata["secure_passport"]
    )

    assert result["valid"] is True


def test_authorization_details_hash_binds_authorization_details() -> None:
    metadata = build_metadata()

    result = verify_authorization_details_binding(
        metadata["secure_passport"],
        metadata["authorization_details"],
    )

    assert result["valid"] is True


def test_patient_delegation_reaches_hospital_only() -> None:
    metadata = build_metadata()

    chain = metadata[
        "secure_passport"
    ]["delegation_chain"]

    assert chain[0]["from"] == "user"
    assert chain[0]["to"] == "patient-agent"

    assert chain[1]["from"] == "patient-agent"
    assert chain[1]["to"] == "hospital-agent"

    assert len(chain) == 2