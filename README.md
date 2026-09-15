# AnyDown headless MegaBasterd engine

A maintained GPL-3.0 fork of [MegaBasterd](https://github.com/tonikelope/megabasterd)
for AnyDown's native desktop interface. The pinned baseline is recorded in
[upstream.lock.json](upstream.lock.json). Original upstream documentation is
preserved in [UPSTREAM_README.md](UPSTREAM_README.md).

The Java process exposes versioned JSON-RPC over stdin/stdout and runs with
`java.awt.headless=true`. AnyDown controls downloads, uploads, accounts, streaming,
settings and utilities without opening a Swing window. Upstream MEGA transport,
cryptography and proxy code remain separate from the headless controllers.

## Build and test

```sh
python3 scripts/mega_build.py --output .build/qualified/runtime
python3 scripts/mega_smoke.py .build/qualified/runtime/mega
```

The scripts fetch checksum-pinned Java 21 and Maven locally, execute headless
JUnit tests, verify dependency hashes and package a relocatable engine/runtime
with corresponding sources and licences. No system Java installation is required.
Build each supported target natively: Apple Silicon macOS, Intel macOS and Linux
x86-64. Binary and source dependency pins are in the committed lock files.

## Releases

See [ENGINE_RELEASE.md](ENGINE_RELEASE.md) for qualification, signing and release
procedures. The updater consumes signed AnyDown-qualified engine packages, never
unreviewed upstream JARs. Release manifests pin the platform, protocol, data format,
source revision and artifact hash. Private signing keys and user profiles must
never be committed. The daily upstream workflow prepares upgrade proposals.

## Compatibility and acceptance

Maintaining the headless integration requires reviewing upstream changes. Future
upstream releases are not automatically compatible until qualified. Account and
transfer fixtures are separate from live authentication/upload acceptance; do not
claim live account coverage from synthetic tests. The engine retains upstream
source attribution and GPL-3.0 licensing; Java and dependencies retain their own
licences in the packaged legal inventory.
