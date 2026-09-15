#!/usr/bin/env python3
"""Offline Ed25519 release signing. Never print or publish private key material."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path


def sign(payload: dict, private_key: Path) -> dict:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key.read_bytes(), password=None)
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return {
        "payload": base64.b64encode(encoded).decode(),
        "signature": base64.b64encode(key.sign(encoded)).decode(),
    }


def generate(private: Path, public: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if private.exists() or public.exists():
        raise RuntimeError("Refusing to overwrite an existing signing key")
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
    public.parent.mkdir(parents=True, exist_ok=True)
    public.write_text(
        key.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    signing = sub.add_parser("sign")
    signing.add_argument("--private", type=Path, required=True)
    signing.add_argument("--manifest", type=Path, required=True)
    signing.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        generate(args.private, args.public)
    else:
        args.output.write_text(
            json.dumps(sign(json.loads(args.manifest.read_text()), args.private), indent=2) + "\n"
        )
