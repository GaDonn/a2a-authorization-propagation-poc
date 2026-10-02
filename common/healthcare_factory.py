from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common.healthcare_models import (
    AuthorizationDetailsEnvelope,
    HealthcareResourceSet,
    ValidatedWorkflowInput,
)


DATA_DIRECTORY = Path(__file__).resolve().parent / "data"

HEALTHCARE_TEMPLATE_PATH = (
    DATA_DIRECTORY / "healthcare_resources_template.json"
)

AUTHORIZATION_TEMPLATE_PATH = (
    DATA_DIRECTORY / "authorization_details_template.json"
)


def _load_json(path: Path) -> dict:
    """Load a project-local JSON template."""

    if not path.exists():
        raise FileNotFoundError(
            f"Required Patient Agent template not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _iso_z(value: datetime) -> str:
    """Serialize a UTC datetime using an explicit Z suffix."""

    utc_value = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc_value.isoformat().replace("+00:00", "Z")


def create_healthcare_resources(
    *,
    now: datetime | None = None,
) -> HealthcareResourceSet:
    """
    Create and validate the synthetic FHIR-like resource set.

    The object contains separate Patient, Coverage, Claim, and
    Provenance resources.
    """

    current_time = (
        now or datetime.now(timezone.utc)
    ).astimezone(timezone.utc)

    payload = copy.deepcopy(
        _load_json(HEALTHCARE_TEMPLATE_PATH)
    )

    claim_created = current_time.replace(microsecond=0)
    provenance_recorded = claim_created + timedelta(seconds=1)

    claim = payload["resources"]["claim"]
    provenance = payload["resources"]["provenance"]

    claim["created"] = _iso_z(claim_created)

    provenance["occurredDateTime"] = _iso_z(claim_created)
    provenance["recorded"] = _iso_z(provenance_recorded)

    return HealthcareResourceSet.model_validate(payload)


def create_authorization_details(
    *,
    now: datetime | None = None,
) -> AuthorizationDetailsEnvelope:
    """
    Create and validate the RAR-inspired authorization_details array.

    Authorization details remain separate from the Claim and other
    healthcare resources.
    """

    current_time = (
        now or datetime.now(timezone.utc)
    ).astimezone(timezone.utc)

    payload = copy.deepcopy(
        _load_json(AUTHORIZATION_TEMPLATE_PATH)
    )

    valid_until = current_time + timedelta(minutes=5)

    details = payload["authorization_details"][0]
    details["constraints"]["valid_until"] = _iso_z(valid_until)

    return AuthorizationDetailsEnvelope.model_validate(payload)


def create_validated_patient_payload(
    *,
    now: datetime | None = None,
) -> tuple[
    HealthcareResourceSet,
    AuthorizationDetailsEnvelope,
]:
    """
    Create the two Patient Agent objects and verify their consistency.

    The function verifies that Claim, Patient, Coverage, treatment,
    currency, and maximum authorized amount agree.
    """

    healthcare = create_healthcare_resources(now=now)
    authorization = create_authorization_details(now=now)

    ValidatedWorkflowInput.model_validate(
        {
            "healthcare": healthcare.model_dump(
                by_alias=True,
                mode="json",
            ),
            "authorization": authorization.model_dump(
                by_alias=True,
                mode="json",
            ),
        }
    )

    return healthcare, authorization


def dump_for_a2a(model) -> dict:
    """
    Convert a validated Pydantic model into JSON-compatible data.

    by_alias=True is required so that the FHIR-like field `class`
    is serialized as `class`, rather than the Python field `class_`.
    """

    return model.model_dump(
        by_alias=True,
        mode="json",
    )