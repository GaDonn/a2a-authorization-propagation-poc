import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)


MODE = os.getenv("MODE", "baseline").lower()
ATTACK = os.getenv("ATTACK", "none").lower()

REPLAY_PROTECTION = os.getenv("REPLAY_PROTECTION", "off").lower()

PATIENT_URL = os.getenv("PATIENT_URL", "http://127.0.0.1:12000")
HOSPITAL_URL = os.getenv("HOSPITAL_URL", "http://127.0.0.1:12001")
INSURANCE_URL = os.getenv("INSURANCE_URL", "http://127.0.0.1:12002")

PASSPORT_TTL_SECONDS = int(os.getenv("PASSPORT_TTL_SECONDS", "300"))

REQUEST_AUTHENTICATION = (
    os.getenv(
        "REQUEST_AUTHENTICATION",
        "off",
    )
    .strip()
    .lower()
)

if REQUEST_AUTHENTICATION not in {
    "on",
    "off",
}:
    raise ValueError(
        "REQUEST_AUTHENTICATION must be 'on' or 'off'"
    )
