"""Small, dependency-free helpers shared by AnyDown's build commands.

Build output is kept in .build/logs. No helper installs a user service, changes
global package managers, or disables HTTPS certificate verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / ".build"
LOGS = BUILD / "logs"
LOCK_PATH = ROOT / "scripts" / "tools.lock.json"
SUPPORTED_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)


def host_target() -> str:
    machine = {"arm64": "aarch64", "amd64": "x86_64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    suffix = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu"}.get(platform.system())
    target = f"{machine}-{suffix}"
    if target not in SUPPORTED_TARGETS:
        raise RuntimeError(f"Unsupported native build platform: {target}")
    return target


def run(
    command: list[str | Path],
    *,
    label: str,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 3600,
) -> None:
    """Run without a shell and save noisy output instead of flooding the terminal."""
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{label}.log"
    args = [str(part) for part in command]
    print(f"[{label}] {shlex.join(args)}", flush=True)
    started = time.monotonic()
    with log.open("w") as output:
        output.write(f"cwd: {cwd}\ncommand: {shlex.join(args)}\n\n")
        output.flush()
        result = subprocess.run(
            args, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=timeout
        )
    if result.returncode:
        lines = log.read_text(errors="replace").splitlines()
        # Some tools put thousands of copied-file errors on one line. Keep the
        # first exact error text while leaving the complete detail in the log.
        excerpt = "\n".join(line[:1200] for line in lines[-35:])
        print(excerpt[:14000], flush=True)
        raise RuntimeError(f"{label} failed ({result.returncode}); full output: {log}")
    print(f"[{label}] passed in {time.monotonic() - started:.1f}s; log: {log}", flush=True)


def capture(command: list[str | Path], *, cwd: Path = ROOT) -> str:
    result = subprocess.run(
        [str(part) for part in command], cwd=cwd, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed: {result.stderr[-3000:]}")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lock() -> dict:
    return json.loads(LOCK_PATH.read_text())


def worker_source_digest() -> str:
    """Detect edits to every local Python module that can enter the frozen worker."""
    digest = hashlib.sha256()
    paths = [ROOT / "engines/worker.py", ROOT / "engines/uv.lock", ROOT / "engines/sources.lock.json"]
    for directory in ("engines/anydown_engines", "downloader", "utils", "app"):
        paths.extend((ROOT / directory).rglob("*.py"))
    for path in sorted(paths):
        if "__pycache__" in path.parts or not path.is_file():
            continue
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def fetch(entry: dict) -> Path:
    """Accept only the exact bytes in the checked-in source/tool lock."""
    destination = BUILD / "downloads" / entry["filename"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected = entry["sha256"]
    if len(expected) != 64:
        raise RuntimeError(f"Missing SHA-256 pin for {entry['filename']}")
    if destination.exists() and sha256(destination) == expected:
        return destination
    partial = destination.with_name(destination.name + ".partial")
    run(
        [
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--retry", "3", "--proto", "=https", "--tlsv1.2",
            "--output", partial, entry["url"],
        ],
        label=f"fetch-{entry['filename']}",
    )
    actual = sha256(partial)
    if actual != expected:
        partial.unlink()
        raise RuntimeError(f"Checksum mismatch for {entry['filename']}: expected {expected}, got {actual}")
    partial.replace(destination)
    return destination


def extract(archive: Path, destination: Path) -> Path:
    """Extract trusted checksum-pinned sources without allowing path traversal."""
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / ".anydown-extracted"
    digest = sha256(archive)
    if marker.exists():
        if marker.read_text().strip() != digest:
            raise RuntimeError(f"Different source already extracted at {destination}")
        children = [path for path in destination.iterdir() if path.name != marker.name]
        return children[0] if len(children) == 1 and children[0].is_dir() else destination
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                target = (destination / member.filename).resolve()
                if not target.is_relative_to(destination.resolve()):
                    raise RuntimeError(f"Unsafe archive member: {member.filename}")
            zipped.extractall(destination)
    else:
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")
    marker.write_text(digest + "\n")
    children = [path for path in destination.iterdir() if path.name != marker.name]
    return children[0] if len(children) == 1 and children[0].is_dir() else destination


def copy_tree(source: Path, destination: Path) -> None:
    """Replace a generated bundle tree; stale and read-only files must not survive.

    Callers only pass build/staging output directories. A completed new copy is
    published before removing the previous generated tree, so failed copying
    cannot corrupt the last successful bundle.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_name(f".{destination.name}.next-{uuid4().hex}")
    previous = destination.with_name(f".{destination.name}.previous-{uuid4().hex}")
    try:
        shutil.copytree(source, pending, symlinks=True)
        if destination.exists():
            destination.rename(previous)
        try:
            pending.rename(destination)
        except OSError:
            if previous.exists():
                previous.rename(destination)
            raise
    finally:
        if pending.exists():
            shutil.rmtree(pending)
    if previous.exists():
        shutil.rmtree(previous)


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | 0o111)


def native_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["MACOSX_DEPLOYMENT_TARGET"] = "13.0"
    environment["SOURCE_DATE_EPOCH"] = "1788998400"
    environment["ZERO_AR_DATE"] = "1"
    environment["LC_ALL"] = "C"
    # Avoid local pkg-config/header overrides silently changing redistributed code.
    for key in ("CPATH", "LIBRARY_PATH", "CPLUS_INCLUDE_PATH", "PKG_CONFIG_PATH"):
        environment.pop(key, None)
    return environment
