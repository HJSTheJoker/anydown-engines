"""Guard the Linux JVM loader-context audit without weakening package requirements."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_runtime import audit, linux_loader_environment


class MegaRuntimeAuditTests(unittest.TestCase):
    def fixture(self, directory: str) -> tuple[Path, Path, Path]:
        root = Path(directory).resolve()
        java = root / "mega/java"
        (java / "bin").mkdir(parents=True)
        (java / "lib/server").mkdir(parents=True)
        (java / "bin/java").write_bytes(b"launcher")
        jvm = java / "lib/server/libjvm.so"
        jvm.write_bytes(b"jvm")
        library = java / "lib/libjava.so"
        # Minimal header lets the auditor validate EM_X86_64 before mocked ldd.
        library.write_bytes(b"\x7fELF\x02\x01" + bytes(12) + (62).to_bytes(2, "little"))
        return root, java, library

    def test_loader_context_is_private_and_does_not_mask_launcher_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root, java, library = self.fixture(directory)
            with patch.dict(
                os.environ,
                {
                    "LD_LIBRARY_PATH": "/developer/lib",
                    "LD_PRELOAD": "/developer/preload.so",
                    "LD_AUDIT": "/developer/audit.so",
                },
            ):
                environment = linux_loader_environment(library, root)
                self.assertEqual(environment["LD_LIBRARY_PATH"], str(java / "lib/server"))
                self.assertNotIn("LD_PRELOAD", environment)
                self.assertNotIn("LD_AUDIT", environment)
                self.assertNotIn(
                    "LD_LIBRARY_PATH", linux_loader_environment(java / "bin/java", root)
                )
                ordinary = root / "bin/ffmpeg"
                ordinary.parent.mkdir()
                ordinary.write_bytes(b"tool")
                self.assertNotIn("LD_LIBRARY_PATH", linux_loader_environment(ordinary, root))

    def test_missing_bundled_jvm_is_not_supplied_or_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            root, java, library = self.fixture(directory)
            (java / "lib/server/libjvm.so").unlink()
            self.assertNotIn("LD_LIBRARY_PATH", linux_loader_environment(library, root))
            self.assert_failure(root, "libjvm.so => not found\n", "")

    def test_missing_system_library_still_fails_in_jvm_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            self.assert_failure(root, "libasound.so.2 => not found\n", "")

    def test_newer_glibc_requirement_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, _ = self.fixture(directory)
            self.assert_failure(
                root, "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n", "Name: GLIBC_2.40"
            )

    def assert_failure(self, root: Path, ldd_output: str, version_output: str) -> None:
        def command(arguments, **options):
            output = ldd_output if arguments[0] == "ldd" else version_output
            return subprocess.CompletedProcess(arguments, 0, stdout=output, stderr="")

        with (
            patch("audit_runtime.sys.platform", "linux"),
            patch("audit_runtime.subprocess.run", side_effect=command),
        ):
            result = audit(root, "x86_64-unknown-linux-gnu")
        self.assertFalse(result["ok"])
        self.assertEqual(result["binaries_checked"], 1)
        self.assertTrue(result["failures"])


if __name__ == "__main__":
    unittest.main()
