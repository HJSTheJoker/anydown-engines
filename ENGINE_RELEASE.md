# Headless engine build and release

AnyDown bundles the maintained Java engine and its runtime. Upstream MegaBasterd releases are reviewed and qualified before becoming AnyDown engine releases. The original Swing application is retained in the corresponding source, while the jar entry point runs the headless protocol.

## Build locally

Run `python3 scripts/mega_build.py --output .build/qualified/runtime`, then `python3 scripts/mega_smoke.py .build/qualified/runtime/mega`. Java and Maven are downloaded into `.build` from checksum-pinned official distributions. No global Java installation is used. On a machine with an unaccepted Xcode licence and installed Command Line Tools, set `DEVELOPER_DIR=/Library/Developer/CommandLineTools` for native audits.

`mega-runtime.lock.json` pins Java 21 JDK/JRE archives for all three supported platforms, Maven, and the OpenJDK corresponding-source archive. `maven-dependencies.lock.json` pins runtime dependency binary and source bytes. A changed dependency fails packaging until its provenance and checksums are reviewed and the lock is explicitly refreshed with `python3 scripts/mega_build.py --refresh-dependency-lock`.

The build runs Java tests and creates a source stamp. `--skip-build` accepts only a jar produced by this build script with an unchanged source stamp. Source changes during compilation or packaging fail the build. Packaging retains engine sources, runtime/dependency sources, licences, Maven inputs and build recipes.

Upstream Xuggler is an exact timestamp-pinned, provided-scope compile dependency. It is excluded from the headless runtime because its native binaries do not support Apple Silicon macOS. Headless thumbnail creation uses ImageIO and the AnyDown-provided FFmpeg executable.

## Release contract

Each platform archive contains `mega/engine.jar`, `mega/java/bin/java`, `mega/engine.json`, `mega/licenses/`, and `mega/sources/`. Archives contain regular files and directories, retaining Java executable permissions. Legal-file symlinks are dereferenced before packaging.

The public update files are `megabasterd-<Rust-target>.json` on the latest GitHub release. Each is an envelope with `payload` (base64 of the exact UTF-8 JSON bytes) and `signature` (base64 Ed25519 signature of those bytes). Payload fields are `format`, `engine`, `version`, strictly increasing `sequence`, `protocol_version`, `data_format_version`, `upstream_revision`, `platform`, `runtime_version`, `resume_compatible`, and `archive` (`url`, `sha256`, `bytes`). Protocol/data format are currently 1. Paused-transfer migration is not enabled by current release tooling: `resume_compatible` is false.

AnyDown verifies the signature, platform, protocol, data format, source hash shape, monotonically increasing sequence, size and archive checksum. It downloads only GitHub assets belonging to this engine repository over HTTPS. Extraction rejects traversal, links, special files, oversized expansion and mismatched archive metadata. Candidates live in each library's writable `mega-updates/versions` directory; installed application resources stay unchanged.

The service activates only while transfers, streams and utilities are inactive. The supervisor owns profile backups, candidate handshake and rollback. A durable active pointer records the sequence, so a crash between activation and status persistence cannot permit an older release.

## CI configuration

1. Configure repository environment **engine-release** with required human reviewers. Require platform qualification and review before approving it.
2. Store the existing private Ed25519 PEM in the environment secret **ENGINE_SIGNING_KEY**. Its public key must match `scripts/mega-update-public-key.hex` embedded in AnyDown. The release script checks this match before producing a manifest. Keep the private key backed up outside the repository; never commit it or place it in release artifacts.
3. Enable GitHub Actions permission to create pull requests for the daily upstream proposal workflow.
4. Create an immutable reviewed version tag and manually dispatch **Release verified engine**, supplying that tag and a new positive sequence greater than every earlier published sequence.

The release workflow builds and tests macOS ARM64, macOS x86-64 and Linux x86-64, runs relocated Java and native audits, and preserves executable permissions across artifact handoff using tar archives. After environment approval it signs all three platform assets and creates the release. It does not overwrite existing releases.

Before approving the release environment, record authorized live download/upload/streaming acceptance and migration/rollback results. Synthetic tests and a handshake alone do not qualify live account behavior, quota handling, video seeking or webview codec support. Dedicated account secrets and private links must never enter public test output.

A daily upstream check opens a proposal PR containing `UPSTREAM_UPDATE.json`. It intentionally does not change the maintained fork or its qualified pin automatically. Port changes, update `upstream.lock.json`, review dependencies and run qualification before release.
