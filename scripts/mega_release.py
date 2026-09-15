#!/usr/bin/env python3
"""Create a signed engine release artifact locally; publishing is a separate CI step."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import tempfile
from pathlib import Path

from build_common import SUPPORTED_TARGETS, sha256
from mega_build import package
from mega_sign import sign


def release(
    runtime: Path,
    output: Path,
    private: Path,
    tag: str,
    sequence: int,
    public_key: Path | None = None,
) -> Path:
    mega = runtime / "mega"
    metadata = json.loads((mega / "engine.json").read_text())
    version = metadata["version"]
    if (
        not version
        or not version.isascii()
        or any(not (c.isalnum() or c in "._-") for c in version)
    ):
        raise ValueError("Engine version must be a simple ASCII identifier")
    if (
        metadata["platform"] not in SUPPORTED_TARGETS
        or metadata["protocol_version"] != 1
        or metadata["data_format_version"] != 1
    ):
        raise ValueError("Engine platform or protocol is not supported")
    if metadata["engine"] != "megabasterd" or metadata["format"] != 1:
        raise ValueError("Invalid engine metadata")
    revision = metadata["upstream_revision"]
    if len(revision) != 40 or any(c not in "0123456789abcdefABCDEF" for c in revision):
        raise ValueError("Engine upstream revision must be a full commit hash")
    if not tag or any(not (c.isalnum() or c in "._-") for c in tag):
        raise ValueError("Release tag must be a simple version identifier")
    if sequence < 1:
        raise ValueError("Release sequence must be positive and monotonically increasing")
    name = f"megabasterd-{metadata['version']}-{metadata['platform']}.tar.gz"
    archive = output / name
    with tempfile.TemporaryDirectory(prefix="anydown-engine-release-") as temporary:
        staged = Path(temporary) / "mega"
        shutil.copytree(mega, staged)
        metadata["sequence"] = sequence
        (staged / "engine.json").write_text(json.dumps(metadata, indent=2) + "\n")
        package(staged, archive)
    payload = {
        key: metadata[key]
        for key in (
            "format",
            "engine",
            "version",
            "protocol_version",
            "data_format_version",
            "upstream_revision",
            "platform",
            "runtime_version",
        )
    }
    payload.update(
        sequence=sequence,
        resume_compatible=False,
        archive={
            "url": f"https://github.com/HJSTheJoker/anydown-engines/releases/download/{tag}/{name}",
            "sha256": sha256(archive),
            "bytes": archive.stat().st_size,
        },
    )
    manifest = output / f"megabasterd-{metadata['platform']}.json"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    envelope = sign(payload, private)
    pin = public_key or Path(__file__).with_name("mega-update-public-key.hex")
    trusted = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin.read_text().strip()))
    trusted.verify(base64.b64decode(envelope["signature"]), base64.b64decode(envelope["payload"]))
    manifest.write_text(json.dumps(envelope, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    args = parser.parse_args()
    print(
        release(
            args.runtime.resolve(),
            args.output.resolve(),
            args.private.resolve(),
            args.tag,
            args.sequence,
        )
    )
