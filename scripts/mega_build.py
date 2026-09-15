#!/usr/bin/env python3
"""Build and package the isolated headless MegaBasterd engine with pinned Java 21."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from build_common import BUILD, ROOT, SUPPORTED_TARGETS, copy_tree, fetch, host_target, run, sha256
from collect_notices import archive_tree
from mega_bootstrap import LOCK, build_environment, pins, prepare_java

ENGINE = ROOT if (ROOT / "pom.xml").is_file() else ROOT / "engines/megabasterd"


def source_digest(source: Path = ENGINE) -> str:
    digest = hashlib.sha256()
    paths = [
        source / "pom.xml",
        source / "upstream.lock.json",
        source / "maven-dependencies.lock.json",
        *sorted((source / "src").rglob("*")),
    ]
    for path in paths:
        if path.is_file():
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def dependency_inventory(
    engine: Path, destination: Path, env: dict, maven: Path, write_lock: bool = False
) -> list[dict]:
    """Record byte-level inputs and retain their available licence files and sources."""
    listing = engine / "target/anydown-dependencies.txt"
    run(
        [
            maven,
            "-B",
            "-ntp",
            "org.apache.maven.plugins:maven-dependency-plugin:3.7.0:sources",
            "org.apache.maven.plugins:maven-dependency-plugin:3.7.0:list",
            "-DincludeScope=runtime",
            "-DoutputAbsoluteArtifactFilename=true",
            f"-DoutputFile={listing}",
        ],
        cwd=engine,
        env=env,
        label="mega-dependency-inventory",
    )
    inventory = []
    for line in listing.read_text().splitlines():
        fields = line.strip().split(":")
        if len(fields) < 6 or fields[2] != "jar":
            continue
        # Maven may suffix the absolute path with a JPMS module description.
        path = Path(fields[-1].split(" -- module ", 1)[0].strip())
        if not path.is_file():
            continue
        group, artifact, _, version, scope = fields[:5]
        entry = {
            "group": group,
            "artifact": artifact,
            "version": version,
            "scope": scope,
            "sha256": sha256(path),
        }
        target = destination / "licenses/dependencies" / f"{group}.{artifact}-{version}"
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path) as jar:
            for name in jar.namelist():
                if (
                    name.upper().startswith("META-INF/")
                    and any(
                        word in Path(name).name.upper() for word in ("LICENSE", "NOTICE", "COPYING")
                    )
                    and not name.endswith("/")
                ):
                    (target / Path(name).name).write_bytes(jar.read(name))
        pom = path.with_suffix(".pom")
        if pom.is_file():
            shutil.copy2(pom, target / "pom.xml")
        source = path.with_name(path.stem + "-sources.jar")
        if not source.is_file():
            raise RuntimeError(
                f"Missing corresponding dependency sources: {group}:{artifact}:{version}"
            )
        entry["sources_included"] = True
        entry["sources_sha256"] = sha256(source)
        if source.is_file():
            (destination / "sources/dependencies").mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination / "sources/dependencies" / source.name)
        inventory.append(entry)
    if not inventory:
        raise RuntimeError("Maven returned no runtime dependency inventory")
    inventory.sort(key=lambda entry: (entry["group"], entry["artifact"]))
    lock_path = engine / "maven-dependencies.lock.json"
    expected = {"format": 1, "dependencies": inventory}
    if write_lock:
        lock_path.write_text(json.dumps(expected, indent=2) + "\n")
    elif not lock_path.is_file() or json.loads(lock_path.read_text()) != expected:
        raise RuntimeError(
            "MEGA dependencies differ from maven-dependencies.lock.json; review source/binary checksums before refreshing the lock"
        )
    shutil.copy2(lock_path, destination / "sources/maven-dependencies.lock.json")
    return inventory


def build(runtime: Path, target: str, skip_build: bool = False) -> dict:
    maven, env = build_environment()
    expected_source = source_digest()
    if not skip_build:
        run(
            [maven, "-B", "-ntp", "verify"],
            cwd=ENGINE,
            env=env,
            label="mega-engine-build",
            timeout=3600,
        )
    pom_version = ET.parse(ENGINE / "pom.xml").findtext(
        "{http://maven.apache.org/POM/4.0.0}version"
    )
    jar = ENGINE / f"target/MegaBasterd-{pom_version}-jar-with-dependencies.jar"
    if not jar.is_file():
        raise RuntimeError(f"Headless engine was not built: {jar}")
    stamp = ENGINE / "target/anydown-source.sha256"
    if skip_build:
        if not stamp.is_file() or stamp.read_text().strip() != expected_source:
            raise RuntimeError(
                "Cannot reuse an engine jar without a matching build source stamp; run mega_build.py without --skip-build"
            )
    else:
        if source_digest() != expected_source:
            raise RuntimeError(
                "MEGA sources changed during compilation; retry after source edits finish"
            )
        stamp.write_text(expected_source + "\n")
    home = prepare_java(target, "jre")
    with tempfile.TemporaryDirectory(prefix="anydown-mega-package-") as temporary:
        mega = Path(temporary) / "mega"
        mega.mkdir()
        # Dereference runtime legal-file symlinks: update extraction rejects links.
        shutil.copytree(home, mega / "java", symlinks=False)
        shutil.copy2(jar, mega / "engine.jar")
        (mega / "sources").mkdir()
        (mega / "licenses").mkdir()
        archive_tree(ENGINE, mega / "sources/megabasterd-source.tar.gz", "megabasterd")
        for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
            for source in ENGINE.glob(pattern):
                if source.is_file():
                    shutil.copy2(source, mega / "licenses" / source.name)
        if (home / "legal").exists():
            shutil.copytree(home / "legal", mega / "licenses/java", symlinks=False)
        shutil.copy2(LOCK, mega / "sources/mega-runtime.lock.json")
        java_source = fetch(pins()["java_source"])
        shutil.copy2(java_source, mega / "sources" / java_source.name)
        for filename in (
            "mega_build.py",
            "mega_bootstrap.py",
            "mega_sign.py",
            "mega_smoke.py",
            "build_common.py",
            "collect_notices.py",
        ):
            shutil.copy2(ROOT / "scripts" / filename, mega / "sources" / filename)
        inventory = dependency_inventory(ENGINE, mega, env, maven)
        (mega / "licenses/dependency-index.json").write_text(json.dumps(inventory, indent=2) + "\n")
        upstream = json.loads((ENGINE / "upstream.lock.json").read_text())
        metadata = {
            "format": 1,
            "engine": "megabasterd",
            "version": upstream["engineVersion"],
            "sequence": 1,
            "protocol_version": 1,
            "data_format_version": 1,
            "upstream_revision": upstream["commit"],
            "platform": target,
            "runtime_version": pins()["platforms"][target]["jre"]["version"],
            "jar_sha256": sha256(jar),
            "source_sha256": source_digest(),
            "runtime_lock_sha256": sha256(LOCK),
        }
        (mega / "engine.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if source_digest() != expected_source:
            raise RuntimeError(
                "MEGA sources changed during packaging; retry after source edits finish"
            )
        copy_tree(mega, runtime / "mega")
    return metadata


def package(mega: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", dereference=True) as archive,
    ):

        def stable(info):
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            return info

        archive.add(mega, arcname="mega", filter=stable)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target", choices=SUPPORTED_TARGETS, default=host_target())
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--archive", type=Path)
    parser.add_argument(
        "--refresh-dependency-lock",
        action="store_true",
        help="After reviewing dependency changes, record exact binary/source checksums",
    )
    args = parser.parse_args()
    if args.refresh_dependency_lock:
        maven, env = build_environment()
        with tempfile.TemporaryDirectory(prefix="anydown-mega-lock-") as temporary:
            directory = Path(temporary)
            (directory / "sources").mkdir()
            dependency_inventory(ENGINE, directory, env, maven, write_lock=True)
        raise SystemExit(0)
    runtime = (args.output or BUILD / "runtime" / args.target / "runtime").resolve()
    metadata = build(runtime, args.target, args.skip_build)
    if args.archive:
        package(runtime / "mega", args.archive)
    print(json.dumps(metadata, indent=2))
