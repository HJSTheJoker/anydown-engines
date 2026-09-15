#!/usr/bin/env python3
"""Exercise a relocated, read-only headless engine with a private writable profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def verify(mega: Path, relocate: bool = True) -> dict:
    metadata = json.loads((mega / "engine.json").read_text())
    if hashlib.sha256((mega / "engine.jar").read_bytes()).hexdigest() != metadata["jar_sha256"]:
        raise RuntimeError("Bundled engine checksum mismatch")
    with tempfile.TemporaryDirectory(prefix="AnyDown MEGA smoke ") as temporary:
        root = Path(temporary)
        destination = root / "Relocated engine" if relocate else mega
        if relocate:
            shutil.copytree(mega, destination, symlinks=True)
            for path in [destination, *destination.rglob("*")]:
                if not path.is_symlink():
                    path.chmod(path.stat().st_mode & ~0o222)
        profile = root / "private profile"
        profile.mkdir(mode=0o700)
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(root),
            "TMPDIR": str(root),
            "LANG": "en_US.UTF-8",
        }
        with (root / "stderr.log").open("w") as errors:
            process = subprocess.Popen(
                [
                    str(destination / "java/bin/java"),
                    "-Djava.awt.headless=true",
                    "-jar",
                    str(destination / "engine.jar"),
                    "--data-dir",
                    str(profile),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=errors,
                env=env,
                cwd=profile,
                text=True,
                bufsize=1,
            )
            assert process.stdin and process.stdout
            responses: queue.Queue = queue.Queue()

            def receive() -> None:
                try:
                    for line in process.stdout:
                        responses.put(json.loads(line))
                except Exception as error:
                    responses.put({"_read_error": str(error)})
                finally:
                    responses.put({"_closed": True})

            reader = threading.Thread(target=receive, daemon=True)
            reader.start()
            sequence = 0

            def call(method: str, params: dict | None = None) -> object:
                nonlocal sequence
                sequence += 1
                process.stdin.write(
                    json.dumps(
                        {"jsonrpc": "2.0", "id": sequence, "method": method, "params": params or {}}
                    )
                    + "\n"
                )
                process.stdin.flush()
                deadline = time.monotonic() + 30
                while True:
                    try:
                        item = responses.get(timeout=max(0.001, deadline - time.monotonic()))
                    except queue.Empty as error:
                        raise RuntimeError(f"Headless engine timed out during {method}") from error
                    if "_read_error" in item or "_closed" in item:
                        raise RuntimeError(f"Headless engine protocol failed during {method}")
                    if item.get("id") != sequence:
                        continue
                    if item.get("error"):
                        raise RuntimeError(f"Headless {method} failed: {item['error']}")
                    return item["result"]

            def completed(task: dict) -> dict:
                deadline = time.monotonic() + 30
                while task.get("status") not in ("completed", "failed", "cancelled"):
                    if time.monotonic() > deadline:
                        raise RuntimeError("Headless file utility did not finish")
                    time.sleep(0.02)
                    task = call("utility.status", {"id": task["id"]})
                if task["status"] != "completed":
                    raise RuntimeError(f"Headless file utility failed: {task}")
                return task

            try:
                handshake = call("engine.handshake", {"protocolVersion": 1})
                if handshake.get("protocolVersion") != 1 or handshake.get("dataVersion") != 1:
                    raise RuntimeError("Headless engine protocol is incompatible")
                snapshot = call("engine.snapshot")
                if snapshot.get("transfers"):
                    raise RuntimeError("An empty profile unexpectedly contains transfers")
                call("settings.get")
                accounts = call("account.list")
                if accounts.get("accounts"):
                    raise RuntimeError("An empty profile unexpectedly contains accounts")
                data = bytes(range(256)) * 1024 + b"headless"
                source = root / "fixture.bin"
                source.write_bytes(data)
                parts = root / "parts"
                parts.mkdir()
                split = completed(
                    call(
                        "utility.split",
                        {"path": str(source), "outputDirectory": str(parts), "partBytes": 100000},
                    )
                )
                output = root / "merged.bin"
                completed(
                    call("utility.merge", {"parts": split["outputs"], "outputPath": str(output)})
                )
                if output.read_bytes() != data:
                    raise RuntimeError("Headless split/merge failed byte integrity")
                call("engine.shutdown")
                return {
                    "headless": True,
                    "relocated": relocate,
                    "read_only_engine": relocate,
                    "system_java_required": False,
                    "empty_profile": True,
                    "settings_and_accounts": True,
                    "split_merge_integrity": True,
                    "handshake": handshake,
                }
            finally:
                process.stdin.close()
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                reader.join(timeout=2)
                process.stdout.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mega", type=Path)
    parser.add_argument("--no-relocate", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify(args.mega.resolve(), not args.no_relocate), indent=2))
