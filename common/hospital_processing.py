from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from common.healthcare_models import (
    HealthcareResourceSet,
    ProvenanceResource,
    ValidatedWorkflowInput,
)


class HospitalValidationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    passed: bool
    detail: str = Field(min_length=1)


class HospitalValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["validated"] = "validated"
    claim_reference: str
    validated_by: Literal["hospital-agent"] = "hospital-agent"
    validated_at: datetime
    checks: list[HospitalValidationCheck]


def _iso_z(value: datetime) -> str:
    utc_value = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc_value.isoformat().replace("+00:00", "Z")


def validate_healthcare_resources(
    healthcare_resources: dict,
) -> HealthcareResourceSet:
    return HealthcareResourceSet.model_validate(healthcare_resources)


def validate_extended_workflow(
    healthcare_resources: dict,
    authorization_details: list[dict],
) -> ValidatedWorkflowInput:
    return ValidatedWorkflowInput.model_validate(
        {
            "healthcare": healthcare_resources,
            "authorization": {
                "authorization_details": authorization_details,
            },
        }
    )


def create_hospital_validation(
    healthcare: HealthcareResourceSet,
    *,
    now: datetime | None = None,
) -> HospitalValidationResult:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resources = healthcare.resources
    claim = resources.claim
    coverage = resources.coverage

    checks = [
        HospitalValidationCheck(
            name="healthcare_structure",
            passed=True,
            detail="Patient, Coverage, Claim, and initial Provenance are structurally valid.",
        ),
        HospitalValidationCheck(
            name="reference_consistency",
            passed=True,
            detail="Patient, Coverage, Claim, and Provenance references are mutually consistent.",
        ),
        HospitalValidationCheck(
            name="claim_monetary_consistency",
            passed=True,
            detail="Claim line amounts and total are internally consistent.",
        ),
        HospitalValidationCheck(
            name="coverage_status",
            passed=coverage.status == "active",
            detail=f"Coverage status is '{coverage.status}'.",
        ),
        HospitalValidationCheck(
            name="claim_status",
            passed=claim.status == "active",
            detail=f"Claim status is '{claim.status}'.",
        ),
    ]

    failed = [check.name for check in checks if not check.passed]
    if failed:
        raise ValueError(
            "Hospital application validation failed: " + ", ".join(failed)
        )

    return HospitalValidationResult(
        claim_reference=claim.reference,
        validated_at=current,
        checks=checks,
    )


def create_hospital_provenance(
    healthcare: HealthcareResourceSet,
    *,
    now: datetime | None = None,
) -> ProvenanceResource:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resources = healthcare.resources

    payload: dict[str, Any] = {
        "resourceType": "Provenance",
        "id": f"provenance-hospital-validation-{resources.claim.id}",
        "target": [{"reference": resources.claim.reference}],
        "occurredDateTime": _iso_z(current),
        "recorded": _iso_z(current + timedelta(seconds=1)),
        "activity": {
            "coding": [
                {
                    "system": "https://example.org/fhir/CodeSystem/provenance-activity",
                    "code": "claim-validation",
                    "display": "Synthetic claim validation",
                }
            ]
        },
        "patient": {"reference": resources.patient.reference},
        "agent": [
            {
                "type": {
                    "coding": [
                        {
                            "system": "https://example.org/fhir/CodeSystem/provenance-agent-type",
                            "code": "validator",
                            "display": "Validator",
                        }
                    ]
                },
                "role": [
                    {
                        "coding": [
                            {
                                "system": "https://example.org/fhir/CodeSystem/agent-security-role",
                                "code": "hospital-validator",
                                "display": "Hospital claim validator",
                            }
                        ]
                    }
                ],
                "who": {"reference": "Organization/hospital-agent"},
            }
        ],
        "entity": [
            {
                "role": "source",
                "what": {"reference": resources.coverage.reference},
            }
        ],
    }

    return ProvenanceResource.model_validate(payload)


def prepare_hospital_forward_metadata(
    received_metadata: dict,
    *,
    validation: HospitalValidationResult,
    hospital_provenance: ProvenanceResource,
    updated_passport: dict | None = None,
) -> dict:
    outgoing = copy.deepcopy(received_metadata)

    outgoing["hospital_validation"] = validation.model_dump(mode="json")
    outgoing["hospital_provenance"] = hospital_provenance.model_dump(
        by_alias=True,
        mode="json",
    )

    if updated_passport is not None:
        outgoing["secure_passport"] = copy.deepcopy(updated_passport)

    return outgoing
