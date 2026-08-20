# Safe Android Reverser sandbox

This image is the execution boundary for the `safe-android-reverser` MCP plugin. Reverse-engineering tools and semantic analyzers run in the container rather than being installed or executed on the host.

## Runtime security model

The wrapper starts the image with:

- no normal network access (`--network=none`)
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges`
- CPU, memory, PID and tmpfs limits
- project mounted read-only at `/workspace`
- plugin-owned analysis state mounted read-write at `/data`
- non-root execution; rootless Podman is preferred
- an allow-listed MCP tool surface; no generic shell/exec MCP operation

Dynamic analysis, ADB, Frida, emulator/device access and proxying belong in a separate privilege profile rather than weakening this static sandbox.

## Static image 0.2.0

The runtime contains:

```text
Java 21
Python 3
JADX 1.5.6
Vineflower 1.12.0
Androguard 4.1.4
file / libmagic
binutils: strings, readelf, objdump, nm
Safe Android Reverser MCP + semantic index modules
```

It does **not** retain `curl`, `wget`, pip, compilers or the Python build toolchain used during image construction.

Androguard runtime dependencies are assembled into `/opt/python-site`. The image performs a deep import check of the DEX and `Analysis` modules used by the MCP, and records the resolved package versions in:

```text
/opt/python-site/installed-requirements.txt
```

The top-level Androguard wheel is SHA-256 verified. Fully hash-locking every transitive Python wheel remains a supply-chain hardening item.

## Semantic storage

Program-understanding jobs use an indexed SQLite graph under the writable job directory:

```text
/data/jobs/<job_id>/program-index.sqlite3
```

The database stores normalized methods and call edges with indexes for symbol identity, callers and callees. A small `program-index.json` summary is also emitted for diagnostics; the full graph is not serialized back through MCP by default.

## Build

```bash
set -a
source sandbox/tools.lock.env
set +a

docker build \
  -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  ${VINEFLOWER_SHA256:+--build-arg VINEFLOWER_SHA256="$VINEFLOWER_SHA256"} \
  --build-arg ANDROGUARD_VERSION="$ANDROGUARD_VERSION" \
  --build-arg ANDROGUARD_WHEEL_SHA256="$ANDROGUARD_WHEEL_SHA256" \
  -t safe-android-reverser:dev .
```

## Validation

The CI path does more than build the image. The final runtime image must execute a real DEX fixture and pass:

```text
build_program_index -> dex-xref
find_symbols
find_xrefs
get_cfg
```

CI then starts the actual MCP entrypoint over JSON-RPC and verifies that `health` reports Androguard, CFG support and SQLite semantic storage as available.

## Local MCP smoke test

```bash
mkdir -p .safe-reverser-data

docker run --rm -i \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs=/tmp:rw,nosuid,nodev,size=1g \
  --tmpfs=/work:rw,nosuid,nodev,size=1g \
  --user="$(id -u):$(id -g)" \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.safe-reverser-data:/data:rw" \
  safe-android-reverser:dev
```

In normal use Claude Code manages the stdio session automatically through the plugin's `.mcp.json` and wrapper.
