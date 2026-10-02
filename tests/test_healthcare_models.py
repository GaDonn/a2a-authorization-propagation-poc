from copy import deepcopy
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from common.healthcare_models import (
    AuthorizationDetailsEnvelope,
    HealthcareResourceSet,
    ValidatedWorkflowInput,
)


def benign_healthcare_payload() -> dict:
    return {
        "modelVersion": "1.0",
        "resources": {
            "patient": {
                "resourceType": "Patient",
                "id": "patient-001",
                "identifier": [
                    {
                        "system": "https://example.org/fhir/identifier/patient",
                        "value": "P001",
                    }
                ],
                "active": True,
            },
            "coverage": {
                "resourceType": "Coverage",
                "id": "coverage-basic-001",
                "identifier": [
                    {
                        "system": "https://example.org/fhir/identifier/coverage",
                        "value": "COV-BASIC-001",
                    }
                ],
                "status": "active",
                "kind": "insurance",
                "beneficiary": {"reference": "Patient/patient-001"},
                "period": {
                    "start": "2026-01-01",
                    "end": "2026-12-31",
                },
                "insurer": {
                    "identifier": {
                        "system": "https://example.org/fhir/identifier/organization",
                        "value": "insurance-agent",
                    },
                    "display": "Synthetic Insurance Organization",
                },
                "class": [
                    {
                        "type": {
                            "coding": [
                                {
                                    "system": "http://terminology.hl7.org/CodeSystem/coverage-class",
                                    "code": "plan",
                                    "display": "Plan",
                                }
                            ]
                        },
                        "value": {
                            "system": "https://example.org/fhir/identifier/insurance-plan",
                            "value": "basic",
                        },
                        "name": "Basic synthetic plan",
                    }
                ],
            },
            "claim": {
                "resourceType": "Claim",
                "id": "claim-001",
                "identifier": [
                    {
                        "system": "https://example.org/fhir/identifier/claim",
                        "value": "CLM-001",
                    }
                ],
                "status": "active",
                "type": {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/claim-type",
                            "code": "professional",
                            "display": "Professional",
                        }
                    ]
                },
                "use": "claim",
                "patient": {"reference": "Patient/patient-001"},
                "created": "2026-07-17T10:00:00Z",
                "insurer": {
                    "identifier": {
                        "system": "https://example.org/fhir/identifier/organization",
                        "value": "insurance-agent",
                    },
                    "display": "Synthetic Insurance Organization",
                },
                "provider": {
                    "identifier": {
                        "system": "https://example.org/fhir/identifier/organization",
                        "value": "hospital-agent",
                    },
                    "display": "Synthetic Hospital Organization",
                },
                "priority": {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/processpriority",
                            "code": "normal",
                            "display": "Normal",
                        }
                    ]
                },
                "insurance": [
                    {
                        "sequence": 1,
                        "focal": True,
                        "coverage": {
                            "reference": "Coverage/coverage-basic-001"
                        },
                    }
                ],
                "item": [
                    {
                        "sequence": 1,
                        "productOrService": {
                            "coding": [
                                {
                                    "system": "https://example.org/fhir/CodeSystem/treatment",
                                    "code": "T123",
                                    "display": "Synthetic treatment T123",
                                }
                            ]
                        },
                        "servicedDate": "2026-07-15",
                        "unitPrice": {"value": 120, "currency": "EUR"},
                        "quantity": {"value": 1},
                        "net": {"value": 120, "currency": "EUR"},
                    }
                ],
                "total": {"value": 120, "currency": "EUR"},
            },
            "provenance": {
                "resourceType": "Provenance",
                "id": "provenance-claim-001",
                "target": [{"reference": "Claim/claim-001"}],
                "occurredDateTime": "2026-07-17T10:00:00Z",
                "recorded": "2026-07-17T10:00:01Z",
                "activity": {
                    "coding": [
                        {
                            "system": "https://example.org/fhir/CodeSystem/provenance-activity",
                            "code": "claim-creation",
                            "display": "Synthetic claim creation",
                        }
                    ]
                },
                "patient": {"reference": "Patient/patient-001"},
                "agent": [
                    {
                        "type": {
                            "coding": [
                                {
                                    "system": "http://terminology.hl7.org/CodeSystem/provenance-participant-type",
                                    "code": "author",
                                    "display": "Author",
                                }
                            ]
                        },
                        "role": [
                            {
                                "coding": [
                                    {
                                        "system": "https://example.org/fhir/CodeSystem/agent-security-role",
                                        "code": "requestor",
                                        "display": "Reimbursement requestor",
                                    }
                                ]
                            }
                        ],
                        "who": {"reference": "Patient/patient-001"},
                    }
                ],
                "entity": [
                    {
                        "role": "source",
                        "what": {
                            "reference": "Coverage/coverage-basic-001"
                        },
                    }
                ],
            },
        },
    }


def benign_authorization_payload() -> dict:
    return {
        "authorization_details": [
            {
                "type": "healthcare_reimbursement",
                "identifier": "authz-claim-001",
                "actions": ["request_reimbursement"],
                "claim": {"reference": "Claim/claim-001"},
                "beneficiary": {"reference": "Patient/patient-001"},
                "coverage": {
                    "reference": "Coverage/coverage-basic-001"
                },
                "treatment": {
                    "system": "https://example.org/fhir/CodeSystem/treatment",
                    "code": "T123",
                },
                "maximum_amount": {
                    "value": 120,
                    "currency": "EUR",
                },
                "consent": {
                    "status": "granted",
                    "purpose": "reimbursement_processing",
                },
                "constraints": {
                    "permitted_destination": "insurance-agent",
                    "permitted_hops": [
                        "patient-agent",
                        "hospital-agent",
                        "insurance-agent",
                    ],
                    "max_agent_hops": 2,
                    "valid_until": "2026-12-31T23:59:59Z",
                },
            }
        ]
    }


def test_benign_healthcare_payload_is_valid() -> None:
    model = HealthcareResourceSet.model_validate(
        benign_healthcare_payload()
    )
    assert model.resources.claim.total.value == 120


def test_benign_authorization_payload_is_valid() -> None:
    model = AuthorizationDetailsEnvelope.model_validate(
        benign_authorization_payload()
    )
    assert model.authorization_details[0].identifier == "authz-claim-001"


def test_combined_workflow_input_is_valid() -> None:
    model = ValidatedWorkflowInput.model_validate(
        {
            "healthcare": benign_healthcare_payload(),
            "authorization": benign_authorization_payload(),
        }
    )
    assert model.healthcare.resources.patient.id == "patient-001"


def test_claim_total_must_equal_item_sum() -> None:
    payload = benign_healthcare_payload()
    payload["resources"]["claim"]["total"]["value"] = 5000

    with pytest.raises(ValidationError, match="Claim.total"):
        HealthcareResourceSet.model_validate(payload)


def test_claim_item_net_must_equal_price_times_quantity() -> None:
    payload = benign_healthcare_payload()
    payload["resources"]["claim"]["item"][0]["net"]["value"] = 5000

    with pytest.raises(ValidationError, match="unitPrice"):
        HealthcareResourceSet.model_validate(payload)


def test_cross_resource_beneficiary_substitution_is_rejected() -> None:
    payload = benign_healthcare_payload()
    payload["resources"]["coverage"]["beneficiary"]["reference"] = (
        "Patient/patient-999"
    )
    payload["resources"]["claim"]["patient"]["reference"] = (
        "Patient/patient-999"
    )

    with pytest.raises(ValidationError, match="Patient resource"):
        HealthcareResourceSet.model_validate(payload)


def test_wrong_reference_type_is_rejected() -> None:
    payload = benign_healthcare_payload()
    payload["resources"]["claim"]["patient"]["reference"] = (
        "Coverage/coverage-basic-001"
    )

    with pytest.raises(ValidationError, match="must reference a Patient"):
        HealthcareResourceSet.model_validate(payload)


def test_unknown_field_is_rejected() -> None:
    payload = benign_healthcare_payload()
    payload["resources"]["patient"]["unexpected"] = "not allowed"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        HealthcareResourceSet.model_validate(payload)


def test_scope_widening_action_is_rejected_by_model() -> None:
    payload = benign_authorization_payload()
    payload["authorization_details"][0]["actions"] = [
        "request_reimbursement",
        "approve_claim",
    ]

    with pytest.raises(ValidationError):
        AuthorizationDetailsEnvelope.model_validate(payload)


def test_destination_must_be_final_hop() -> None:
    payload = benign_authorization_payload()
    payload["authorization_details"][0]["constraints"][
        "permitted_destination"
    ] = "external-agent"

    with pytest.raises(ValidationError, match="final permitted hop"):
        AuthorizationDetailsEnvelope.model_validate(payload)


def test_max_agent_hops_must_match_path() -> None:
    payload = benign_authorization_payload()
    payload["authorization_details"][0]["constraints"][
        "max_agent_hops"
    ] = 4

    with pytest.raises(ValidationError, match="len\\(permitted_hops\\) - 1"):
        AuthorizationDetailsEnvelope.model_validate(payload)


def test_claim_cannot_exceed_authorized_maximum() -> None:
    healthcare = benign_healthcare_payload()
    healthcare["resources"]["claim"]["item"][0]["unitPrice"]["value"] = 121
    healthcare["resources"]["claim"]["item"][0]["net"]["value"] = 121
    healthcare["resources"]["claim"]["total"]["value"] = 121

    with pytest.raises(ValidationError, match="exceeds"):
        ValidatedWorkflowInput.model_validate(
            {
                "healthcare": healthcare,
                "authorization": benign_authorization_payload(),
            }
        )


def test_authorization_treatment_must_match_claim() -> None:
    authorization = benign_authorization_payload()
    authorization["authorization_details"][0]["treatment"]["code"] = "T999"

    with pytest.raises(ValidationError, match="treatment"):
        ValidatedWorkflowInput.model_validate(
            {
                "healthcare": benign_healthcare_payload(),
                "authorization": authorization,
            }
        )


def test_authorization_beneficiary_must_match_patient() -> None:
    authorization = benign_authorization_payload()
    authorization["authorization_details"][0]["beneficiary"][
        "reference"
    ] = "Patient/patient-999"

    with pytest.raises(ValidationError, match="beneficiary"):
        ValidatedWorkflowInput.model_validate(
            {
                "healthcare": benign_healthcare_payload(),
                "authorization": authorization,
            }
        )
