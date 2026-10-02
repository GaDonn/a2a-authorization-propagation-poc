from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from common.healthcare_models import (
    HealthcareResourceSet,
    ProvenanceResource,
    ValidatedWorkflowInput,
)
from common.hospital_processing import HospitalValidationResult


class InsuranceDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]
    claim_reference: str
    beneficiary_reference: str
    coverage_reference: str
    amount: Decimal
    currency: str
    decided_by: Literal["insurance-agent"] = "insurance-agent"
    decided_at: datetime
    reason: str = Field(min_length=1)


def validate_hospital_enrichment(
    *,
    hospital_validation: dict,
    hospital_provenance: dict,
    healthcare: HealthcareResourceSet,
) -> tuple[HospitalValidationResult, ProvenanceResource]:
    validation = HospitalValidationResult.model_validate(hospital_validation)
    provenance = ProvenanceResource.model_validate(hospital_provenance)

    claim_ref = healthcare.resources.claim.reference
    patient_ref = healthcare.resources.patient.reference
    coverage_ref = healthcare.resources.coverage.reference

    errors: list[str] = []

    if validation.status != "validated":
        errors.append("Hospital validation status is not validated.")
    if validation.claim_reference != claim_ref:
        errors.append("Hospital validation references a different Claim.")
    if not validation.checks or not all(check.passed for check in validation.checks):
        errors.append("Hospital validation contains a failed or missing check.")

    if claim_ref not in {target.reference for target in provenance.target}:
        errors.append("Hospital Provenance does not target the received Claim.")
    if provenance.patient.reference != patient_ref:
        errors.append("Hospital Provenance references a different Patient.")
    if "Organization/hospital-agent" not in {
        agent.who.reference for agent in provenance.agent
    }:
        errors.append("Hospital Provenance does not identify hospital-agent.")
    if coverage_ref not in {
        entity.what.reference for entity in provenance.entity
    }:
        errors.append("Hospital Provenance does not reference the received Coverage.")

    if errors:
        raise ValueError(" ".join(errors))

    return validation, provenance


def resolve_reimbursement_references(
    healthcare: HealthcareResourceSet,
) -> dict[str, str]:
    resources = healthcare.resources
    patient_ref = resources.patient.reference
    coverage_ref = resources.coverage.reference
    claim_ref = resources.claim.reference

    if resources.coverage.beneficiary.reference != patient_ref:
        raise ValueError("Coverage beneficiary does not resolve to the Patient resource.")
    if resources.claim.patient.reference != patient_ref:
        raise ValueError("Claim patient does not resolve to the Patient resource.")
    if coverage_ref not in {
        entry.coverage.reference for entry in resources.claim.insurance
    }:
        raise ValueError("Claim insurance does not resolve to the Coverage resource.")

    return {
        "patient": patient_ref,
        "coverage": coverage_ref,
        "claim": claim_ref,
    }


def make_deterministic_decision(
    *,
    healthcare: HealthcareResourceSet,
    authorization: ValidatedWorkflowInput | None,
    hospital_validation: HospitalValidationResult,
    now: datetime | None = None,
) -> InsuranceDecision:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resources = healthcare.resources
    claim = resources.claim
    coverage = resources.coverage
    references = resolve_reimbursement_references(healthcare)

    if coverage.status != "active":
        return InsuranceDecision(
            decision="rejected",
            claim_reference=references["claim"],
            beneficiary_reference=references["patient"],
            coverage_reference=references["coverage"],
            amount=claim.total.value,
            currency=claim.total.currency,
            decided_at=current,
            reason="Coverage is not active.",
        )

    if claim.status != "active":
        return InsuranceDecision(
            decision="rejected",
            claim_reference=references["claim"],
            beneficiary_reference=references["patient"],
            coverage_reference=references["coverage"],
            amount=claim.total.value,
            currency=claim.total.currency,
            decided_at=current,
            reason="Claim is not active.",
        )

    if not all(check.passed for check in hospital_validation.checks):
        return InsuranceDecision(
            decision="rejected",
            claim_reference=references["claim"],
            beneficiary_reference=references["patient"],
            coverage_reference=references["coverage"],
            amount=claim.total.value,
            currency=claim.total.currency,
            decided_at=current,
            reason="Hospital validation contains a failed check.",
        )

    if authorization is not None:
        details = authorization.authorization.authorization_details[0]
        if claim.total.currency != details.maximum_amount.currency:
            return InsuranceDecision(
                decision="rejected",
                claim_reference=references["claim"],
                beneficiary_reference=references["patient"],
                coverage_reference=references["coverage"],
                amount=claim.total.value,
                currency=claim.total.currency,
                decided_at=current,
                reason="Claim and authorization currencies differ.",
            )
        if claim.total.value > details.maximum_amount.value:
            return InsuranceDecision(
                decision="rejected",
                claim_reference=references["claim"],
                beneficiary_reference=references["patient"],
                coverage_reference=references["coverage"],
                amount=claim.total.value,
                currency=claim.total.currency,
                decided_at=current,
                reason="Claim exceeds the authorized maximum amount.",
            )

    return InsuranceDecision(
        decision="approved",
        claim_reference=references["claim"],
        beneficiary_reference=references["patient"],
        coverage_reference=references["coverage"],
        amount=claim.total.value,
        currency=claim.total.currency,
        decided_at=current,
        reason=(
            "Claim, Coverage, beneficiary, Hospital validation, and applicable "
            "authorization constraints are valid."
        ),
    )


def validate_insurance_input(
    *,
    healthcare_resources: dict,
    hospital_validation: dict,
    hospital_provenance: dict,
    authorization_details: list[dict] | None,
) -> tuple[
    HealthcareResourceSet,
    ValidatedWorkflowInput | None,
    HospitalValidationResult,
    ProvenanceResource,
]:
    healthcare = HealthcareResourceSet.model_validate(healthcare_resources)

    authorization: ValidatedWorkflowInput | None = None
    if authorization_details is not None:
        authorization = ValidatedWorkflowInput.model_validate(
            {
                "healthcare": healthcare_resources,
                "authorization": {
                    "authorization_details": authorization_details,
                },
            }
        )

    validation, provenance = validate_hospital_enrichment(
        hospital_validation=hospital_validation,
        hospital_provenance=hospital_provenance,
        healthcare=healthcare,
    )

    resolve_reimbursement_references(healthcare)
    return healthcare, authorization, validation, provenance
