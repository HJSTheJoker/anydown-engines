#!/usr/bin/env python3
"""Prepare checksum-pinned Java and Maven under .build, never using system Java."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from build_common import BUILD, ROOT, SUPPORTED_TARGETS, extract, fetch, host_target

LOCK = ROOT / "scripts/mega-runtime.lock.json"


def pins() -> dict:
    return json.loads(LOCK.read_text())


def prepare_java(target: str | None = None, kind: str = "jdk") -> Path:
    target = target or host_target()
    entry = pins()["platforms"][target][kind]
    tree = extract(fetch(entry), BUILD / "mega-tools" / target / kind / entry["sha256"][:16])
    home = tree / "Contents/Home" if (tree / "Contents/Home").is_dir() else tree
    if not (home / "bin/java").is_file():
        raise RuntimeError(f"Pinned Java archive has no executable: {home}")
    return home


def prepare_maven() -> Path:
    entry = pins()["maven"]
    return extract(fetch(entry), BUILD / "mega-tools/maven" / entry["sha256"][:16]) / "bin/mvn"


def build_environment() -> tuple[Path, dict[str, str]]:
    home = prepare_java()
    env = dict(os.environ)
    for key in (
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "MAVEN_OPTS",
        "MAVEN_ARGS",
    ):
        env.pop(key, None)
    env.update(
        JAVA_HOME=str(home), PATH=str(home / "bin") + os.pathsep + env.get("PATH", "/usr/bin:/bin")
    )
    return prepare_maven(), env


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=SUPPORTED_TARGETS, default=host_target())
    parser.add_argument("--runtime-only", action="store_true")
    args = parser.parse_args()
    home = prepare_java(args.target, "jre" if args.runtime_only else "jdk")
    result = {"java_home": str(home), "java": str(home / "bin/java")}
    if not args.runtime_only:
        result["maven"] = str(prepare_maven())
    print(json.dumps(result, indent=2))
