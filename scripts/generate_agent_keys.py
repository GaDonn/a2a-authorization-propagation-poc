from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from common.agent_keys import (
    AGENT_IDS,
    KEYS_DIRECTORY,
    private_key_path,
    public_key_path,
)


def write_private_key(
    path: Path,
    private_key: Ed25519PrivateKey,
) -> None:
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(data)

    if os.name != "nt":
        path.chmod(0o600)


def write_public_key(
    path: Path,
    private_key: Ed25519PrivateKey,
) -> None:
    data = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(data)


def main() -> None:
    KEYS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    for agent_id in AGENT_IDS:
        private_path = private_key_path(agent_id)
        public_path = public_key_path(agent_id)

        if private_path.exists() or public_path.exists():
            raise FileExistsError(
                f"Key files already exist for {agent_id}. "
                "Delete them explicitly before rotating keys."
            )

        private_key = Ed25519PrivateKey.generate()

        write_private_key(
            private_path,
            private_key,
        )
        write_public_key(
            public_path,
            private_key,
        )

        print(
            f"generated {agent_id}: "
            f"{private_path.name}, "
            f"{public_path.name}"
        )


if __name__ == "__main__":
    main()
