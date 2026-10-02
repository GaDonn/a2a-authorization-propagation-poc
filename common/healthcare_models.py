from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


FHIR_REFERENCE_PATTERN = r"^(Patient|Coverage|Claim|Organization)/[A-Za-z0-9\-.]{1,64}$"
CURRENCY_PATTERN = r"^[A-Z]{3}$"


class StrictModel(BaseModel):
    """Base class for project-local, synthetic FHIR-like models."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class Identifier(StrictModel):
    system: str = Field(min_length=1)
    value: str = Field(min_length=1)


class Reference(StrictModel):
    reference: str = Field(pattern=FHIR_REFERENCE_PATTERN)


class OrganizationIdentifier(StrictModel):
    identifier: Identifier
    display: str = Field(min_length=1)


class Coding(StrictModel):
    system: str = Field(min_length=1)
    code: str = Field(min_length=1)
    display: str | None = None


class CodeableConcept(StrictModel):
    coding: Annotated[list[Coding], Field(min_length=1)]


class Money(StrictModel):
    value: Decimal = Field(ge=0)
    currency: str = Field(pattern=CURRENCY_PATTERN)


class Quantity(StrictModel):
    value: Decimal = Field(gt=0)


class Period(StrictModel):
    start: date
    end: date

    @model_validator(mode="after")
    def validate_period(self) -> "Period":
        if self.end < self.start:
            raise ValueError("Coverage period end must not precede start.")
        return self


class PatientResource(StrictModel):
    resourceType: Literal["Patient"] = "Patient"
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9\-.]{1,64}$")
    identifier: Annotated[list[Identifier], Field(min_length=1)]
    active: bool

    @property
    def reference(self) -> str:
        return f"Patient/{self.id}"


class CoverageClass(StrictModel):
    type: CodeableConcept
    value: Identifier
    name: str = Field(min_length=1)


class CoverageResource(StrictModel):
    resourceType: Literal["Coverage"] = "Coverage"
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9\-.]{1,64}$")
    identifier: Annotated[list[Identifier], Field(min_length=1)]
    status: Literal["active", "cancelled", "draft", "entered-in-error"]
    kind: Literal["insurance", "self-pay", "other"]
    beneficiary: Reference
    period: Period
    insurer: OrganizationIdentifier
    class_: Annotated[list[CoverageClass], Field(min_length=1)] = Field(
        alias="class",
        serialization_alias="class",
    )

    @field_validator("beneficiary")
    @classmethod
    def beneficiary_must_reference_patient(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Patient/"):
            raise ValueError("Coverage.beneficiary must reference a Patient.")
        return value

    @property
    def reference(self) -> str:
        return f"Coverage/{self.id}"


class ClaimInsurance(StrictModel):
    sequence: int = Field(ge=1)
    focal: bool
    coverage: Reference

    @field_validator("coverage")
    @classmethod
    def coverage_must_reference_coverage(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Coverage/"):
            raise ValueError("Claim.insurance.coverage must reference Coverage.")
        return value


class ClaimItem(StrictModel):
    sequence: int = Field(ge=1)
    productOrService: CodeableConcept
    servicedDate: date
    unitPrice: Money
    quantity: Quantity
    net: Money

    @model_validator(mode="after")
    def validate_line_amount(self) -> "ClaimItem":
        if self.unitPrice.currency != self.net.currency:
            raise ValueError("Claim item unitPrice and net currencies must match.")

        expected = self.unitPrice.value * self.quantity.value
        if self.net.value != expected:
            raise ValueError(
                f"Claim item net must equal unitPrice × quantity; "
                f"expected {expected}, got {self.net.value}."
            )
        return self


class ClaimResource(StrictModel):
    resourceType: Literal["Claim"] = "Claim"
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9\-.]{1,64}$")
    identifier: Annotated[list[Identifier], Field(min_length=1)]
    status: Literal["active", "cancelled", "draft", "entered-in-error"]
    type: CodeableConcept
    use: Literal["claim", "preauthorization", "predetermination"]
    patient: Reference
    created: datetime
    insurer: OrganizationIdentifier
    provider: OrganizationIdentifier
    priority: CodeableConcept
    insurance: Annotated[list[ClaimInsurance], Field(min_length=1)]
    item: Annotated[list[ClaimItem], Field(min_length=1)]
    total: Money

    @field_validator("patient")
    @classmethod
    def patient_must_reference_patient(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Patient/"):
            raise ValueError("Claim.patient must reference a Patient.")
        return value

    @model_validator(mode="after")
    def validate_claim_total(self) -> "ClaimResource":
        currencies = {item.net.currency for item in self.item}
        currencies.add(self.total.currency)

        if len(currencies) != 1:
            raise ValueError("All Claim item and total currencies must match.")

        expected_total = sum((item.net.value for item in self.item), Decimal("0"))
        if self.total.value != expected_total:
            raise ValueError(
                f"Claim.total must equal the sum of item.net values; "
                f"expected {expected_total}, got {self.total.value}."
            )

        sequences = [item.sequence for item in self.item]
        if len(sequences) != len(set(sequences)):
            raise ValueError("Claim item sequence values must be unique.")

        insurance_sequences = [entry.sequence for entry in self.insurance]
        if len(insurance_sequences) != len(set(insurance_sequences)):
            raise ValueError("Claim insurance sequence values must be unique.")

        if not any(entry.focal for entry in self.insurance):
            raise ValueError("Claim must contain at least one focal insurance entry.")

        return self

    @property
    def reference(self) -> str:
        return f"Claim/{self.id}"


class ProvenanceAgent(StrictModel):
    type: CodeableConcept
    role: Annotated[list[CodeableConcept], Field(min_length=1)]
    who: Reference


class ProvenanceEntity(StrictModel):
    role: Literal["revision", "quotation", "source", "instantiates", "removal"]
    what: Reference


class ProvenanceResource(StrictModel):
    resourceType: Literal["Provenance"] = "Provenance"
    id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9\-.]{1,64}$")
    target: Annotated[list[Reference], Field(min_length=1)]
    occurredDateTime: datetime
    recorded: datetime
    activity: CodeableConcept
    patient: Reference
    agent: Annotated[list[ProvenanceAgent], Field(min_length=1)]
    entity: Annotated[list[ProvenanceEntity], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_provenance(self) -> "ProvenanceResource":
        if self.recorded < self.occurredDateTime:
            raise ValueError(
                "Provenance.recorded must not precede occurredDateTime."
            )

        if not any(ref.reference.startswith("Claim/") for ref in self.target):
            raise ValueError("Provenance.target must include a Claim reference.")

        if not self.patient.reference.startswith("Patient/"):
            raise ValueError("Provenance.patient must reference a Patient.")

        return self


class HealthcareResources(StrictModel):
    patient: PatientResource
    coverage: CoverageResource
    claim: ClaimResource
    provenance: ProvenanceResource

    @model_validator(mode="after")
    def validate_cross_resource_references(self) -> "HealthcareResources":
        patient_ref = self.patient.reference
        coverage_ref = self.coverage.reference
        claim_ref = self.claim.reference

        errors: list[str] = []

        if self.coverage.beneficiary.reference != patient_ref:
            errors.append(
                "Coverage.beneficiary does not match the Patient resource."
            )

        if self.claim.patient.reference != patient_ref:
            errors.append("Claim.patient does not match the Patient resource.")

        claim_coverage_refs = {
            entry.coverage.reference for entry in self.claim.insurance
        }
        if coverage_ref not in claim_coverage_refs:
            errors.append(
                "Claim.insurance does not reference the Coverage resource."
            )

        provenance_targets = {entry.reference for entry in self.provenance.target}
        if claim_ref not in provenance_targets:
            errors.append(
                "Provenance.target does not reference the Claim resource."
            )

        if self.provenance.patient.reference != patient_ref:
            errors.append(
                "Provenance.patient does not match the Patient resource."
            )

        provenance_agent_refs = {
            agent.who.reference for agent in self.provenance.agent
        }
        if patient_ref not in provenance_agent_refs:
            errors.append(
                "Provenance.agent does not identify the Patient resource."
            )

        provenance_entity_refs = {
            entity.what.reference for entity in self.provenance.entity
        }
        if coverage_ref not in provenance_entity_refs:
            errors.append(
                "Provenance.entity does not reference the Coverage resource."
            )

        if errors:
            raise ValueError(" ".join(errors))

        return self


class HealthcareResourceSet(StrictModel):
    modelVersion: Literal["1.0"] = "1.0"
    resources: HealthcareResources


class TreatmentAuthorization(StrictModel):
    system: str = Field(min_length=1)
    code: str = Field(min_length=1)


class ConsentAuthorization(StrictModel):
    status: Literal["granted"]
    purpose: Literal["reimbursement_processing"]


class AuthorizationConstraints(StrictModel):
    permitted_destination: str = Field(min_length=1)
    permitted_hops: Annotated[list[str], Field(min_length=2)]
    max_agent_hops: int = Field(ge=1)
    valid_until: datetime

    @model_validator(mode="after")
    def validate_constraints(self) -> "AuthorizationConstraints":
        if len(self.permitted_hops) != len(set(self.permitted_hops)):
            raise ValueError("permitted_hops must not contain duplicates.")

        if self.permitted_destination != self.permitted_hops[-1]:
            raise ValueError(
                "permitted_destination must equal the final permitted hop."
            )

        expected_hops = len(self.permitted_hops) - 1
        if self.max_agent_hops != expected_hops:
            raise ValueError(
                "max_agent_hops must equal len(permitted_hops) - 1."
            )

        return self


class AuthorizationDetails(StrictModel):
    type: Literal["healthcare_reimbursement"] = "healthcare_reimbursement"
    identifier: str = Field(min_length=1)
    actions: Annotated[list[Literal["request_reimbursement"]], Field(min_length=1, max_length=1)]
    claim: Reference
    beneficiary: Reference
    coverage: Reference
    treatment: TreatmentAuthorization
    maximum_amount: Money
    consent: ConsentAuthorization
    constraints: AuthorizationConstraints

    @field_validator("claim")
    @classmethod
    def claim_must_reference_claim(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Claim/"):
            raise ValueError("authorization_details.claim must reference Claim.")
        return value

    @field_validator("beneficiary")
    @classmethod
    def beneficiary_must_reference_patient(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Patient/"):
            raise ValueError(
                "authorization_details.beneficiary must reference Patient."
            )
        return value

    @field_validator("coverage")
    @classmethod
    def coverage_must_reference_coverage(cls, value: Reference) -> Reference:
        if not value.reference.startswith("Coverage/"):
            raise ValueError(
                "authorization_details.coverage must reference Coverage."
            )
        return value


class AuthorizationDetailsEnvelope(StrictModel):
    authorization_details: Annotated[
        list[AuthorizationDetails],
        Field(min_length=1),
    ]


class ValidatedWorkflowInput(StrictModel):
    """Combined validation used later by the agents."""

    healthcare: HealthcareResourceSet
    authorization: AuthorizationDetailsEnvelope

    @model_validator(mode="after")
    def validate_authorization_against_resources(self) -> "ValidatedWorkflowInput":
        resources = self.healthcare.resources

        if len(self.authorization.authorization_details) != 1:
            raise ValueError(
                "The prototype currently supports exactly one authorization detail."
            )

        details = self.authorization.authorization_details[0]
        claim = resources.claim

        errors: list[str] = []

        if details.claim.reference != claim.reference:
            errors.append("Authorization Claim reference does not match Claim.")

        if details.beneficiary.reference != resources.patient.reference:
            errors.append(
                "Authorization beneficiary does not match Patient."
            )

        if details.coverage.reference != resources.coverage.reference:
            errors.append("Authorization Coverage does not match Coverage.")

        claim_coding = claim.item[0].productOrService.coding[0]
        if (
            details.treatment.system != claim_coding.system
            or details.treatment.code != claim_coding.code
        ):
            errors.append("Authorization treatment does not match Claim item.")

        if claim.total.currency != details.maximum_amount.currency:
            errors.append(
                "Authorization and Claim currencies do not match."
            )
        elif claim.total.value > details.maximum_amount.value:
            errors.append(
                "Claim total exceeds the authorized maximum amount."
            )

        if errors:
            raise ValueError(" ".join(errors))

        return self
