"""Meaningful release-boundary checks without downloading or running Java."""

import base64
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_common import SUPPORTED_TARGETS
from mega_bootstrap import pins
from mega_build import package
from mega_release import release
from mega_sign import generate, sign


class MegaPackagingTests(unittest.TestCase):
    def test_every_target_has_pinned_java21_build_and_runtime(self):
        lock = pins()
        self.assertEqual(set(lock["platforms"]), set(SUPPORTED_TARGETS))
        for platform in lock["platforms"].values():
            for kind in ("jdk", "jre"):
                self.assertTrue(platform[kind]["version"].startswith("21."))
                self.assertEqual(len(platform[kind]["sha256"]), 64)
                self.assertTrue(
                    platform[kind]["url"].startswith(
                        "https://github.com/adoptium/temurin21-binaries/"
                    )
                )
        self.assertEqual(len(lock["java_source"]["sha256"]), 64)

    def test_archive_dereferences_legal_links_and_keeps_java_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mega = root / "mega"
            (mega / "java/bin").mkdir(parents=True)
            java = mega / "java/bin/java"
            java.write_text("test")
            java.chmod(0o755)
            (mega / "legal.txt").write_text("licence")
            (mega / "legal-link.txt").symlink_to("legal.txt")
            archive = root / "engine.tar.gz"
            package(mega, archive)
            with tarfile.open(archive) as tar:
                self.assertTrue(
                    all(member.isfile() or member.isdir() for member in tar.getmembers())
                )
                self.assertTrue(tar.getmember("mega/java/bin/java").mode & 0o111)
                self.assertEqual(tar.extractfile("mega/legal-link.txt").read(), b"licence")
            first = archive.read_bytes()
            package(mega, archive)
            self.assertEqual(first, archive.read_bytes())

    def test_release_sequence_matches_signed_archive_metadata(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography release-signing dependency is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            mega = runtime / "mega"
            mega.mkdir(parents=True)
            metadata = {
                "format": 1,
                "engine": "megabasterd",
                "version": "8.58-anydown.1",
                "sequence": 1,
                "protocol_version": 1,
                "data_format_version": 1,
                "upstream_revision": "a" * 40,
                "platform": SUPPORTED_TARGETS[0],
                "runtime_version": "21",
            }
            (mega / "engine.json").write_text(json.dumps(metadata))
            private = root / "key.pem"
            public = root / "public.hex"
            generate(private, public)
            manifest = release(
                runtime, root / "out", private, "v8.58-anydown.1", 7, public_key=public
            )
            payload = json.loads(base64.b64decode(json.loads(manifest.read_text())["payload"]))
            self.assertEqual(payload["sequence"], 7)
            archive = next((root / "out").glob("*.tar.gz"))
            with tarfile.open(archive) as tar:
                self.assertEqual(json.load(tar.extractfile("mega/engine.json"))["sequence"], 7)
            self.assertEqual(json.loads((mega / "engine.json").read_text())["sequence"], 1)
            with self.assertRaises(ValueError):
                release(runtime, root / "bad", private, "../bad-tag", 8, public_key=public)
            metadata["version"] = "../escape"
            (mega / "engine.json").write_text(json.dumps(metadata))
            with self.assertRaises(ValueError):
                release(runtime, root / "bad", private, "good-tag", 8, public_key=public)

    def test_signature_authenticates_exact_payload_and_private_permissions(self):
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            self.skipTest("cryptography release-signing dependency is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "key.pem"
            public = root / "public.hex"
            generate(private, public)
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(RuntimeError):
                generate(private, public)
            envelope = sign({"version": "8.58", "sequence": 1}, private)
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public.read_text().strip()))
            payload = base64.b64decode(envelope["payload"])
            signature = base64.b64decode(envelope["signature"])
            key.verify(signature, payload)
            with self.assertRaises(InvalidSignature):
                key.verify(signature, payload + b" ")


if __name__ == "__main__":
    unittest.main()
