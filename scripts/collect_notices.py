#!/usr/bin/env python3
"""Collect exact engine sources and dependency notices using the build interpreter."""

from __future__ import annotations

import argparse
import gzip
import importlib.metadata as metadata
import json
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tomllib
from pathlib import Path

from build_common import ROOT, capture, fetch


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def archive_tree(directory: Path, destination: Path, prefix: str, paths: list[Path] | None = None) -> None:
    """Stable timestamps make source archive changes meaningful in release review."""
    excluded = {".git", ".venv", "node_modules", "__pycache__", "target", ".build", "dist", ".pytest_cache", ".ruff_cache"}
    with destination.open("wb") as output, gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
        for source in sorted(paths if paths is not None else directory.rglob("*")):
            relative = source.relative_to(directory)
            if excluded.intersection(relative.parts) or not source.is_file() or source.is_symlink():
                continue
            if source.name == ".env" or source.name.startswith(".env."):
                continue
            # Standalone CoomerDL profiles are user data, even when they live
            # beside source resources. Never include them in source bundles.
            if relative.parts[:2] == ("resources", "config") and (
                source.name in {"downloads.db", "downloads.db-wal", "downloads.db-shm", "settings.json"}
                or (len(relative.parts) > 2 and relative.parts[2] == "cookies")
            ):
                continue
            info = archive.gettarinfo(str(source), arcname=f"{prefix}/{relative.as_posix()}")
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            with source.open("rb") as data:
                archive.addfile(info, data)


def engine_sources(runtime: Path) -> None:
    source_dir = runtime / "sources/engines"
    source_dir.mkdir(parents=True, exist_ok=True)
    pins = json.loads((ROOT / "engines/sources.lock.json").read_text())
    for name in ("gallery-dl", "yt-dlp"):
        pin = pins[name]
        tree = ROOT / pin["path"]
        actual = capture(["git", "rev-parse", "HEAD"], cwd=tree)
        dirty = capture(["git", "status", "--porcelain"], cwd=tree)
        if actual != pin["commit"] or dirty:
            raise RuntimeError(f"Cannot package {name}: checkout is dirty or does not match sources.lock.json")
        destination = source_dir / f"{name}-{actual}.tar.gz"
        with destination.open("wb") as output, gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            process = subprocess.Popen(["git", "archive", "--format=tar", f"--prefix={name}/", actual], cwd=tree, stdout=subprocess.PIPE)
            assert process.stdout is not None
            shutil.copyfileobj(process.stdout, compressed)
            process.stdout.close()
            if process.wait():
                raise RuntimeError(f"Failed to archive {name}")
        notices = runtime / "licenses/engines" / name
        notices.mkdir(parents=True, exist_ok=True)
        for pattern in ("LICENSE*", "COPYING*", "NOTICE*"):
            for source in tree.glob(pattern):
                if source.is_file():
                    shutil.copy2(source, notices / source.name)
    shutil.copy2(ROOT / "engines/sources.lock.json", source_dir / "sources.lock.json")
    shutil.copy2(ROOT / "engines/uv.lock", source_dir / "uv.lock")
    # Archive the source actually being built, including authorized uncommitted
    # changes, without capturing arbitrary files from the user's workspace.
    allowed = {".github", "scripts", "crates", "engines", "desktop", "downloader", "utils", "app", "docs", "resources"}
    top_files = {"Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "main.py", "requirements.txt"}
    paths = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if relative.parts[0] in allowed or relative.as_posix() in top_files:
            if not {".git", ".venv", "node_modules", "target", ".build", "dist"}.intersection(relative.parts):
                paths.append(path)
    archive_tree(ROOT, source_dir / "anydown-source.tar.gz", "anydown", paths)


def python_notices(runtime: Path) -> list[dict]:
    index = []
    packages = {canonical(package["name"]): package for package in tomllib.loads((ROOT / "engines/uv.lock").read_text())["package"]}
    source_dir = runtime / "sources/python"
    source_dir.mkdir(parents=True, exist_ok=True)
    for distribution in sorted(metadata.distributions(), key=lambda dist: canonical(dist.metadata["Name"])):
        name = distribution.metadata["Name"]
        version = distribution.version
        destination = runtime / "licenses/python" / f"{canonical(name)}-{version}"
        destination.mkdir(parents=True, exist_ok=True)
        license_text = distribution.metadata.get("License-Expression") or distribution.metadata.get("License")
        classifiers = [value for value in distribution.metadata.get_all("Classifier", []) if value.startswith("License ::")]
        record = {"name": name, "version": version, "license": license_text, "license_classifiers": classifiers, "files": []}
        for path in distribution.files or []:
            if re.search(r"(?i)(^|/)(licen[sc]e[^/]*|copying[^/]*|notice[^/]*|authors[^/]*)$", str(path)):
                source = Path(distribution.locate_file(path))
                if source.is_file():
                    filename = str(path).replace("/", "__")
                    shutil.copy2(source, destination / filename)
                    record["files"].append(filename)
        # Preserve the upstream metadata bytes; serializing email.Message can
        # reject multiline descriptions under newer Python email policies.
        (destination / "METADATA.txt").write_text(distribution.read_text("METADATA") or "")
        pinned = packages.get(canonical(name))
        if pinned and (sdist := pinned.get("sdist")):
            extension = ".tar.gz" if ".tar.gz" in sdist["url"] else ".zip"
            archive = fetch({
                "filename": f"python-{canonical(name)}-{version}{extension}",
                "url": sdist["url"], "sha256": sdist["hash"].removeprefix("sha256:"),
            })
            shutil.copy2(archive, source_dir / archive.name)
            record["source_archive"] = archive.name
        index.append(record)
    python_license = Path(sysconfig.get_path("stdlib")) / "LICENSE.txt"
    if not python_license.exists():
        python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if not python_license.exists():
        raise RuntimeError("Python LICENSE.txt was not found; use an official Python/uv runtime for bundling")
    destination = runtime / "licenses/python/CPython"
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(python_license, destination / "LICENSE.txt")
    (destination / "build.json").write_text(json.dumps({
        "version": sys.version, "build_config": sysconfig.get_config_var("CONFIG_ARGS"),
        "source": f"https://www.python.org/downloads/release/python-{sys.version_info.major}{sys.version_info.minor}{sys.version_info.micro}/",
    }, indent=2))
    return index


def frontend_notices(runtime: Path) -> list[dict]:
    lock = ROOT / "desktop/package-lock.json"
    if not lock.exists():
        return []
    packages = json.loads(lock.read_text()).get("packages", {})
    index = []
    for location, package in packages.items():
        if not location:
            continue
        directory = ROOT / "desktop" / location
        if not directory.exists():
            continue
        name = package.get("name", location.rsplit("node_modules/", 1)[-1])
        destination = runtime / "licenses/npm" / name.replace("/", "__")
        destination.mkdir(parents=True, exist_ok=True)
        for pattern in ("LICENSE*", "LICENCE*", "license*", "COPYING*", "NOTICE*"):
            for source in directory.glob(pattern):
                if source.is_file():
                    shutil.copy2(source, destination / source.name)
        index.append({"name": name, "version": package.get("version"), "license": package.get("license"), "integrity": package.get("integrity")})
    return index


def rust_notices(runtime: Path) -> list[dict]:
    if not (ROOT / "Cargo.lock").exists():
        return []
    manifest = json.loads(capture(["cargo", "metadata", "--locked", "--format-version", "1"]))
    index = []
    for package in manifest["packages"]:
        if package["source"] is None:
            continue
        source_dir = Path(package["manifest_path"]).parent
        destination = runtime / "licenses/rust" / f"{package['name']}-{package['version']}"
        destination.mkdir(parents=True, exist_ok=True)
        for pattern in ("LICENSE*", "LICENCE*", "license*", "COPYING*", "NOTICE*"):
            for source in source_dir.glob(pattern):
                if source.is_file():
                    shutil.copy2(source, destination / source.name)
        if package.get("license_file"):
            source = source_dir / package["license_file"]
            if source.is_file():
                shutil.copy2(source, destination / source.name)
        index.append({"name": package["name"], "version": package["version"], "license": package["license"], "source": package["source"]})
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--include-app", action="store_true", help="Collect npm and Rust notices after building both clients")
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    (runtime / "licenses").mkdir(parents=True, exist_ok=True)
    engine_sources(runtime)
    index = {"python": python_notices(runtime)}
    if args.include_app:
        index["npm"] = frontend_notices(runtime)
        index["rust"] = rust_notices(runtime)
    (runtime / "licenses/dependency-index.json").write_text(json.dumps(index, indent=2) + "\n")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        source = ROOT / name
        if source.exists():
            shutil.copy2(source, runtime / "licenses" / name)
    print(f"Preserved source archives and notices: {runtime}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(f"collect_notices: {error}", file=sys.stderr)
        raise SystemExit(1)
