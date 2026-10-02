"""Create the local shared HMAC key without shipping a default secret."""
from __future__ import annotations

import os
import secrets
from pathlib import Path


def main() -> None:
    target = Path(__file__).resolve().parents[1] / ".env"
    # Exclusive creation prevents accidental changes to an existing experiment.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write("# Local research demo configuration; do not commit.\n")
        handle.write(f"A2A_HMAC_SECRET={secrets.token_hex(32)}\n")
    print("Created local .env with a new shared HMAC key.")


if __name__ == "__main__":
    main()
