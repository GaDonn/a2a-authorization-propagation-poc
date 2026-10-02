"""Distribution configuration must not silently supply an HMAC secret."""
from __future__ import annotations

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("value", ["", "not-a-hex-key", "ab" * 31, "ab" * 33])
def test_invalid_explicit_hmac_secret_fails_closed(value: str) -> None:
    environment = dict(os.environ, A2A_HMAC_SECRET=value)
    completed = subprocess.run(
        [sys.executable, "-c", "import common.secure_passport"],
        env=environment, capture_output=True, text=True,
    )
    assert completed.returncode != 0
    assert "A2A_HMAC_SECRET" in completed.stderr


def test_explicit_secret_takes_precedence_over_local_dotenv() -> None:
    environment = dict(os.environ, A2A_HMAC_SECRET="ab" * 32)
    completed = subprocess.run(
        [sys.executable, "-c",
         "from common.secure_passport import DEMO_SECRET; "
         "assert DEMO_SECRET == bytes.fromhex('ab' * 32)"],
        env=environment, capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr
