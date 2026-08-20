# Install and use Safe Android Reverser MCP

This is the recommended installation path for `safe-android-reverser`.

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

You do **not** need to run `podman pull`, `podman run`, `docker pull`, `docker run`, or `claude mcp add` during the normal installation flow.

The plugin starts the container automatically when Claude Code starts/reconnects the bundled MCP server.

## How automatic startup works

```text
Claude Code
    │
    │ starts plugin MCP command
    ▼
safe-reverser-mcp wrapper
    │
    ├─ detect Podman first, otherwise Docker
    ├─ create the plugin data directory
    ├─ check for ghcr.io/salingnh/safe-android-reverser:0.1.0
    ├─ pull the pinned image automatically if it is missing
    ├─ map the current host UID/GID for writable /data
    └─ run an ephemeral locked-down container
              │
              ▼
       Python MCP server
       JADX / Vineflower
```

The container is intentionally **not** a background daemon. MCP uses stdio, so the container lifetime is tied to the Claude Code MCP session. The wrapper launches it with `podman run --rm -i` (or Docker equivalent) and it is removed automatically when the MCP session ends.

## 1. Prerequisites

You need:

- Claude Code with plugin/marketplace support;
- either Podman or Docker;
- an APK/JAR/AAR that you are authorized to analyze.

### Recommended: rootless Podman

Check that Podman works as your normal user:

```bash
podman --version
podman info
```

Do not run Claude Code or this MCP plugin with `sudo`.

Docker is also supported:

```bash
docker --version
docker info
```

If both Podman and Docker are installed, the wrapper prefers Podman.

## 2. Add the marketplace

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
```

## 3. Install the plugin

Inside Claude Code:

```text
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

That is the complete normal installation.

No additional MCP registration command is required because the plugin already contains `.mcp.json`.

On the first MCP startup, if the sandbox image is not present locally, the wrapper automatically pulls:

```text
ghcr.io/salingnh/safe-android-reverser:0.1.0
```

Subsequent starts reuse the local image.

## 4. Verify that the MCP is up

Inside Claude Code:

```text
/mcp
```

Verify that `safe-android-reverser` is listed as connected/healthy.

Then run:

```text
Use only the safe-android-reverser MCP server.
Call the health tool and report the server version and whether JADX, Java, and Vineflower are available.
Do not analyze any artifact yet.
```

A successful response confirms this complete path:

```text
Claude Code
  -> plugin
      -> MCP wrapper
          -> Podman/Docker
              -> sandbox container
                  -> MCP server
```

## 5. Put an APK under the Claude project root

The project is mounted read-only into the sandbox. Put artifacts under the project directory and use paths relative to that root.

Example:

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

Do not pass arbitrary absolute host paths to the MCP tools.

## 6. First smoke-test prompt

Use this first because it is cheap and easy to diagnose:

```text
Use only the safe-android-reverser MCP server.
1. Call health.
2. Fingerprint artifacts/app.apk.
3. Report framework, HTTP stack, obfuscation level, native libraries, notable SDKs, and the recommended next analyzer.
Do not decompile yet.
```

## 7. Full analysis prompt

```text
Analyze artifacts/app.apk using only the safe-android-reverser MCP server.

Required workflow:
1. Call health first. If the MCP or sandbox is unavailable, stop and report the setup error.
2. Call fingerprint on artifacts/app.apk.
3. Report the detected framework, HTTP stack, obfuscation level, native libraries, and notable SDK signals.
4. If it is a native Android/JVM application, decompile it with JADX.
5. Run extract_api on the resulting analysis job.
6. Summarize likely first-party hosts, endpoint paths, HTTP/authentication signals, and the strongest source evidence.
7. Use search_source/read_source_file only for high-signal findings.
8. Do not use host JADX/Java, install-dep.sh, sudo, or any non-MCP reverse-engineering path.
```

The bundled slash command is also available:

```text
/safe-decompile artifacts/app.apk
```

## Runtime defaults

For normal use you do not need to set any environment variables.

Defaults:

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

`SAFE_REVERSER_RUNTIME=auto` means:

```text
Podman available -> use Podman
otherwise Docker available -> use Docker
otherwise -> fail with a setup error
```

To force a runtime:

```bash
export SAFE_REVERSER_RUNTIME=podman
# or
export SAFE_REVERSER_RUNTIME=docker
```

To prevent automatic image downloads:

```bash
export SAFE_REVERSER_AUTO_PULL=0
```

If you override these variables, start/restart Claude Code from a shell that has the variables set so the bundled MCP process inherits them.

## What Podman is started automatically

The wrapper effectively launches an ephemeral container equivalent to:

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
  ghcr.io/salingnh/safe-android-reverser:0.1.0
```

The explicit `--user="$(id -u):$(id -g)"` is important for rootless Podman. It keeps the bind-mounted `/data` directory writable by the same host user while the container still runs non-root.

This fixes the failure mode:

```text
PermissionError: [Errno 13] Permission denied: '/data/jobs'
```

## Troubleshooting

### `CONNECTION_CLOSED`

`CONNECTION_CLOSED` normally means the MCP wrapper or container exited before/during the MCP handshake.

First check Podman/Docker itself:

```bash
podman info
```

Then check whether the image exists locally:

```bash
podman image inspect ghcr.io/salingnh/safe-android-reverser:0.1.0
```

If it is missing, normal plugin startup should pull it automatically. You can also pull it manually for diagnosis:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

### Manual Podman MCP smoke test

Manual `podman run` is only needed for troubleshooting. From the project root:

```bash
mkdir -p "$HOME/.local/share/safe-android-reverser"

printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"podman-smoke-test","version":"1.0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"health","arguments":{}}}' \
| podman run \
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
    --volume="$HOME/.local/share/safe-android-reverser:/data:rw,z" \
    ghcr.io/salingnh/safe-android-reverser:0.1.0
```

A successful test returns JSON-RPC responses for `id: 1` and `id: 2`, with the `health` result showing the reverse-engineering tool availability.

### Verify `/data` permission separately

```bash
podman run \
  --rm \
  --userns=keep-id \
  --user="$(id -u):$(id -g)" \
  --volume="$HOME/.local/share/safe-android-reverser:/data:rw,z" \
  --entrypoint /bin/sh \
  ghcr.io/salingnh/safe-android-reverser:0.1.0 \
  -lc 'id; mkdir -p /data/jobs; touch /data/jobs/write-test; ls -l /data/jobs/write-test'
```

### MCP is not listed in `/mcp`

Run:

```text
/reload-plugins
```

If it is still absent, restart Claude Code and verify the plugin is installed/enabled.

### Artifact path is rejected

Move the artifact under the project root, for example:

```text
<project>/artifacts/app.apk
```

and call the MCP with:

```text
artifacts/app.apk
```

## Security boundary

Automatic startup does not mean the agent receives Podman or shell access as an MCP tool.

The boundary remains:

```text
Agent
  -> allow-listed MCP tools
      -> wrapper-controlled ephemeral container
          -> non-root process
          -> read-only project input
          -> isolated writable analysis data
          -> no normal runtime network
```

If this path fails, the plugin must report the setup error rather than falling back to the legacy host-executed reverse-engineering scripts.
