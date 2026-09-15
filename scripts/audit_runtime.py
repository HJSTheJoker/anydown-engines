#!/usr/bin/env python3
"""Reject bundled native binaries that still link to developer-installed libraries."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from build_common import SUPPORTED_TARGETS, host_target


def linux_loader_environment(path: Path, root: Path) -> dict[str, str]:
    """Model the JVM's private loader context only for libraries inside that JRE.

    The Java launcher opens lib/server/libjvm.so before it loads libjava/libawt
    and their peers. Running ldd on those peers outside a JVM otherwise reports
    libjvm.so missing even though relocated headless execution succeeds. Supply
    only that bundled server directory; executables and unrelated libraries
    retain their normal loader search, and inherited developer paths cannot
    mask missing dependencies. Native smoke tests still run without this env.
    """
    environment = {key: value for key, value in os.environ.items() if not key.startswith("LD_")}
    boundary = root.resolve()
    for directory in path.resolve().parents:
        if not directory.is_relative_to(boundary):
            break
        if directory.name != "lib":
            continue
        java_home = directory.parent
        jvm = directory / "server/libjvm.so"
        launcher = java_home / "bin/java"
        if launcher.is_file() and jvm.is_file() and jvm.resolve().is_relative_to(boundary):
            environment["LD_LIBRARY_PATH"] = str(jvm.resolve().parent)
            break
    return environment


def audit(root: Path, target: str | None = None) -> dict:
    if target is None:
        for candidate in (root / "manifest.json", root / "runtime/manifest.json", root / "Contents/Resources/runtime/manifest.json"):
            if candidate.is_file():
                target = json.loads(candidate.read_text()).get("target")
                break
    target = target or host_target()
    expected_arch = "arm64" if target.startswith("aarch64-") else "x86_64"
    checked = []
    failures = []
    target_os = "darwin" if target.endswith("apple-darwin") else "linux"
    if not sys.platform.startswith(target_os):
        failures.append({"error": "Native runtime audit must run on the target operating system", "host": sys.platform, "target": target})
    minimum_versions = set()
    macho = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if sys.platform == "darwin" and magic in macho:
            architectures = subprocess.run(["lipo", "-archs", path], capture_output=True, text=True, check=True).stdout.split()
            if expected_arch not in architectures:
                failures.append({"binary": str(path.relative_to(root)), "architectures": architectures, "expected": expected_arch})
            result = subprocess.run(["otool", "-L", path], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines()[1:]:
                dependency = line.strip().split(" (", 1)[0]
                if dependency.startswith("/") and not dependency.startswith(("/usr/lib/", "/System/Library/")):
                    failures.append({"binary": str(path.relative_to(root)), "dependency": dependency})
            loads = subprocess.run(["otool", "-l", path], capture_output=True, text=True, check=True).stdout
            versions = re.findall(r"\bminos\s+(\d+(?:\.\d+)*)", loads)
            versions += re.findall(r"cmd LC_VERSION_MIN_MACOSX\s+cmdsize \d+\s+version (\d+(?:\.\d+)*)", loads)
            for version in versions:
                minimum_versions.add(version)
                if tuple(map(int, version.split("."))) > (13, 0, 0)[:len(version.split("."))]:
                    failures.append({"binary": str(path.relative_to(root)), "macos_minimum": version, "maximum_allowed": "13.0"})
            checked.append(str(path.relative_to(root)))
        elif sys.platform.startswith("linux") and magic == b"\x7fELF":
            with path.open("rb") as stream:
                header = stream.read(20)
            byte_order = "little" if header[5] == 1 else "big"
            machine = int.from_bytes(header[18:20], byte_order)
            if target == "x86_64-unknown-linux-gnu" and machine != 62:
                failures.append({"binary": str(path.relative_to(root)), "elf_machine": machine, "expected": "EM_X86_64 (62)"})
            loader_env = linux_loader_environment(path, root)
            result = subprocess.run(["ldd", path], capture_output=True, text=True, env=loader_env)
            if "not found" in result.stdout:
                failures.append({"binary": str(path.relative_to(root)), "error": result.stdout})
            for line in result.stdout.splitlines():
                if "=> /" in line and not any(prefix in line for prefix in ("=> /lib", "=> /usr/lib", str(root))):
                    failures.append({"binary": str(path.relative_to(root)), "dependency": line.strip()})
            versions = subprocess.run(["readelf", "--version-info", path], capture_output=True, text=True, check=True, env=loader_env).stdout
            for version in set(re.findall(r"Name: GLIBC_(\d+\.\d+)", versions)):
                minimum_versions.add(version)
                if tuple(map(int, version.split("."))) > (2, 35):
                    failures.append({"binary": str(path.relative_to(root)), "glibc_requirement": version, "maximum_allowed": "2.35 (Ubuntu 22.04)"})
            checked.append(str(path.relative_to(root)))
    return {"ok": not failures, "target": target, "binaries_checked": len(checked), "declared_platform_versions": sorted(minimum_versions), "failures": failures}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--target", choices=SUPPORTED_TARGETS)
    args = parser.parse_args()
    result = audit(args.runtime.resolve(), args.target)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
