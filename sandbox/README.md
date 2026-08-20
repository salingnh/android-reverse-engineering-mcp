# Safe Android Reverser sandbox

This image is the execution boundary for the `safe-android-reverser` Claude Code plugin.
The plugin itself does not install Java, JADX, Vineflower, or package-manager dependencies
on the host. It starts this image as an MCP stdio server.

## Runtime security model

The host wrapper starts the image with:

- no network (`--network=none`)
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges`
- CPU, memory, PID and tmpfs limits
- project directory mounted read-only at `/workspace`
- plugin-owned state mounted read-write at `/data`
- non-root execution; rootless Podman is preferred
- a fixed MCP tool allowlist; the server never calls `shell=True`

The image intentionally contains only Java, Python, JADX and Vineflower. It does **not**
contain `curl`, `wget`, ADB, Frida or a package installer at runtime. Network and dynamic
analysis should live in a separate image/profile rather than weakening this static-analysis
sandbox.

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
  -t safe-android-reverser:dev .
```

JADX is pinned to 1.5.6 and its release ZIP is SHA-256 verified. Vineflower is version-pinned;
record an independently verified `VINEFLOWER_SHA256` before treating the build as fully
artifact-pinned. GHCR builds also request BuildKit SBOM and provenance metadata.

## Local MCP smoke test

```bash
docker run --rm -i \
  --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g \
  --tmpfs /work:rw,nosuid,nodev,size=1g \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/.safe-reverser-data:/data" \
  safe-android-reverser:dev
```

Then send MCP JSON-RPC messages on stdin. In normal use Claude Code manages the stdio
session automatically through the plugin's `.mcp.json`.
