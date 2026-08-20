# Install and use Safe Android Reverser MCP

This is the recommended installation path for `safe-android-reverser` 0.2.1.

The normal user flow is intentionally short:

```text
install Podman or Docker
        ↓
add marketplace
        ↓
install plugin
        ↓
/reload-plugins
        ↓
/mcp
        ↓
use the MCP tools
```

You do **not** need to run `podman pull`, `podman run`, `docker pull`, `docker run`, or `claude mcp add` during normal installation.

The plugin wrapper automatically detects Podman/Docker, creates its data directory, pulls the pinned image when missing, and starts an ephemeral MCP container.

## How automatic startup works

```text
Claude Code
    │ starts bundled MCP command
    ▼
safe-reverser-mcp wrapper
    ├─ prefer rootless Podman, otherwise Docker
    ├─ create plugin data directory
    ├─ check ghcr.io/salingnh/safe-android-reverser:0.2.1
    ├─ pull the pinned image on first use
    ├─ map host UID/GID for writable /data
    └─ launch a locked-down ephemeral container
              │
              ▼
       Safe Android Reverser MCP
       ├─ JADX / Vineflower
       ├─ Androguard
       ├─ file / binutils
       └─ semantic program-understanding layer
```

The container is **not** a background daemon. MCP uses stdio, so its lifetime is tied to the MCP session and `--rm` removes it when the session ends.

## 1. Prerequisites

You need:

- Claude Code with plugin/marketplace support;
- Podman or Docker;
- an APK/XAPK/APKS/APKM/JAR/AAR that you are authorized to analyze.

Rootless Podman is recommended:

```bash
podman --version
podman info
```

Do not run Claude Code or this plugin with `sudo`.

Docker is also supported:

```bash
docker --version
docker info
```

If both are installed, the wrapper prefers Podman.

## 2. Install the plugin

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

No separate MCP registration is required because the plugin bundles `.mcp.json`.

On first startup the wrapper automatically pulls:

```text
ghcr.io/salingnh/safe-android-reverser:0.2.1
```

Subsequent sessions reuse the local image.

## 3. Verify the MCP

Inside Claude Code:

```text
/mcp
```

Verify that `safe-android-reverser` is connected, then run:

```text
Use only the safe-android-reverser MCP server.
Call health and report:
- server version
- JADX, Java and Vineflower availability
- Androguard availability
- program-understanding capabilities
- call_path availability
Do not analyze any artifact yet.
```

For the standard 0.2.1 image, `health` should report Androguard, SQLite semantic indexing, XREF/CFG and call-path traversal as available. APKiD protector detection is an optional external analyzer in this phase and may report unavailable.

## 4. Put an artifact under the project root

The project is mounted read-only into the sandbox. Keep artifacts under the Claude project root and pass only relative paths.

```bash
mkdir -p artifacts
cp /path/to/app.xapk artifacts/app.xapk
```

Do not pass arbitrary absolute host paths.

## 5. Cheap first smoke test

```text
Use only the safe-android-reverser MCP server.
1. Call health.
2. Fingerprint artifacts/app.xapk.
3. Report framework, APK members, HTTP stack, obfuscation level, native libraries, notable SDKs and the recommended analyzer route.
Do not decompile yet.
```

## 6. Full semantic analysis prompt

For native Android/Java/Kotlin applications, use this workflow:

```text
Analyze artifacts/app.xapk using only the safe-android-reverser MCP server.

Required workflow:
1. Call health. Stop and report the setup error if MCP/sandbox is unavailable.
2. Fingerprint the artifact and identify its APK members/framework.
3. If protector detection is available, call identify_protector and use the result to adjust the analysis route.
4. If native Android/Java/Kotlin analysis is appropriate, decompile with JADX and keep the returned job_id.
5. Call build_program_index(job_id).
6. Call extract_network_model(job_id).
7. Use find_symbols/find_xrefs for localization and one-hop call evidence.
8. When both source and target anchors are known, use trace_call_path for bounded shortest multi-hop call paths.
9. Treat any trace_call_path result with truncated=true as incomplete; do not infer that no path exists from a truncated negative.
10. Use get_cfg only when branch/control-flow detail is required.
11. Use search_source/read_source_file only for high-signal evidence that verifies the graph-based conclusion.
12. Report graph/traversal truncation and unresolved questions explicitly.

Do not use host JADX/Java/Androguard, host shell commands, sudo, install-dep.sh, or any non-MCP reverse-engineering path.
Do not describe XREF/call-path adjacency as proven data-flow.
```

The key 0.2.1 semantic MCP operations are:

```text
build_program_index
find_symbols
find_xrefs
trace_call_path
get_cfg
identify_protector
extract_network_model
```

The older `extract_api` remains available for cheap endpoint inventory, while `extract_network_model` is preferred when you need to understand how an endpoint is used.

## Runtime defaults

Normal users do not need to configure environment variables.

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.2.1
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

The wrapper, not `.mcp.json`, owns these defaults. Advanced users may override them in the environment before launching Claude Code.

To force the runtime:

```bash
export SAFE_REVERSER_RUNTIME=podman
# or
export SAFE_REVERSER_RUNTIME=docker
```

To disable automatic downloads:

```bash
export SAFE_REVERSER_AUTO_PULL=0
```

## What Podman starts automatically

The wrapper effectively launches:

```bash
podman run \
  --rm \
  -i \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=256 \
  --memory=4g \
  --cpus=2 \
  --tmpfs=/tmp:rw,nosuid,nodev,size=1g \
  --tmpfs=/work:rw,nosuid,nodev,size=2g \
  --userns=keep-id \
  --user="$(id -u):$(id -g)" \
  --volume="$PWD:/workspace:ro,z" \
  --volume="<plugin-data>:/data:rw,z" \
  ghcr.io/salingnh/safe-android-reverser:0.2.1
```

The explicit host UID/GID keeps `/data` writable while the process remains non-root.

## Troubleshooting

### `CONNECTION_CLOSED`

Check the container runtime first:

```bash
podman info
```

Then check the image:

```bash
podman image inspect ghcr.io/salingnh/safe-android-reverser:0.2.1
```

Normal plugin startup pulls it automatically if missing. For diagnosis only:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.2.1
```

### Manual MCP smoke test

Manual `podman run` is only needed for troubleshooting:

```bash
mkdir -p "$HOME/.local/share/safe-android-reverser"

printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"podman-smoke-test","version":"1.0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health","arguments":{}}}' \
| podman run \
    --rm -i \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --pids-limit=256 \
    --memory=4g \
    --cpus=2 \
    --tmpfs=/tmp:rw,nosuid,nodev,size=1g \
    --tmpfs=/work:rw,nosuid,nodev,size=2g \
    --userns=keep-id \
    --user="$(id -u):$(id -g)" \
    --volume="$PWD:/workspace:ro,z" \
    --volume="$HOME/.local/share/safe-android-reverser:/data:rw,z" \
    ghcr.io/salingnh/safe-android-reverser:0.2.1
```

A successful test returns JSON-RPC responses for initialize and health.

### `/data/jobs` permission error

Verify the data mount independently:

```bash
podman run \
  --rm \
  --userns=keep-id \
  --user="$(id -u):$(id -g)" \
  --volume="$HOME/.local/share/safe-android-reverser:/data:rw,z" \
  --entrypoint /bin/sh \
  ghcr.io/salingnh/safe-android-reverser:0.2.1 \
  -lc 'id; mkdir -p /data/jobs; touch /data/jobs/write-test; ls -l /data/jobs/write-test'
```

### MCP not listed

Run:

```text
/reload-plugins
```

If still absent, restart Claude Code and verify that the plugin is installed/enabled.

## Security boundary

Automatic startup does not expose Podman, Docker or a shell as MCP tools.

```text
Agent
  -> allow-listed semantic MCP tools
      -> wrapper-controlled ephemeral container
          -> non-root process
          -> read-only project input
          -> isolated writable analysis data
          -> no normal runtime network
```

If this path fails, the plugin reports the setup error rather than falling back to legacy host-executed reverse-engineering scripts.
