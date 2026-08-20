# Safe Android Reverser plugin

A Claude Code plugin that exposes Android static reverse engineering through the `safe-android-reverser` MCP server running inside a constrained Podman/Docker sandbox.

The intended execution path is:

```text
Claude Code
  -> plugin
      -> MCP stdio
          -> safe-reverser-mcp wrapper
              -> rootless Podman / Docker
                  -> MCP server + JADX / Vineflower
```

The plugin does not require the agent to install JADX/Java on the host and does not expose a generic shell MCP tool.

## Quick start

For the complete installation and troubleshooting guide, see [`../../docs/INSTALL_MCP.md`](../../docs/INSTALL_MCP.md).

### 1. Prepare the sandbox image

After the production image is published, rootless Podman is recommended:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
podman image inspect ghcr.io/salingnh/safe-android-reverser:0.1.0 >/dev/null \
  && echo "safe-android-reverser image is ready"
```

Docker is also supported:

```bash
docker pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

For the current feature branch, build a local image instead:

```bash
git clone --branch feat/safe-sandbox-plugin \
  https://github.com/salingnh/android-reverse-engineering-mcp.git
cd android-reverse-engineering-mcp

set -a
source sandbox/tools.lock.env
set +a

podman build \
  -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .
```

### 2. Start Claude Code with the runtime configuration

Released image:

```bash
export SAFE_REVERSER_RUNTIME=podman
export SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
claude
```

Feature-branch image:

```bash
export SAFE_REVERSER_RUNTIME=podman
export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
claude
```

Use `docker` instead of `podman` when required.

Set these variables **before** starting Claude Code so the MCP process inherits them.

### 3. Add the marketplace and install the plugin

Released/master:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Current feature branch:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp@feat/safe-sandbox-plugin
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

The plugin includes `.mcp.json`; no separate `claude mcp add` command is required.

## Verify that the MCP is up

Inside Claude Code run:

```text
/mcp
```

Confirm that `safe-android-reverser` is listed and connected/healthy.

Then use this prompt:

```text
Use only the safe-android-reverser MCP server.
Call the health tool and report whether the sandbox is ready and which reverse-engineering tools are available.
Do not decompile or analyze any artifact yet.
```

If `health` succeeds without an MCP/container error, the end-to-end path is working:

```text
Claude -> plugin -> MCP wrapper -> container -> MCP server
```

## First APK smoke test

Place the APK under the Claude project root because the project is mounted read-only into the sandbox:

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

Then prompt Claude:

```text
Analyze artifacts/app.apk using only the safe-android-reverser MCP server.

Required workflow:
1. Call health first. If the MCP or sandbox is unavailable, stop and report the setup error.
2. Call fingerprint on artifacts/app.apk.
3. Report framework, HTTP stack, obfuscation level, native libraries, and notable SDK signals.
4. If it is a native Android/JVM application, decompile it with JADX.
5. Run extract_api on the resulting job.
6. Summarize likely first-party hosts, endpoint paths, HTTP/auth signals, and the strongest source evidence.
7. Use search_source/read_source_file only for high-signal findings.
8. Do not use host shell commands, host JADX/Java, install-dep.sh, sudo, or a non-MCP reverse-engineering path.
```

A lighter fingerprint-only test:

```text
Use only safe-android-reverser MCP.
Run health and then fingerprint artifacts/app.apk.
Return only the fingerprint summary and recommended next analyzer. Do not decompile yet.
```

The bundled slash command can also run the workflow:

```text
/safe-decompile artifacts/app.apk
```

## MCP tools

The current static MCP exposes:

- `health`
- `fingerprint`
- `decompile`
- `extract_api`
- `search_source`
- `read_source_file`
- `recover_kotlin_names`
- `list_jobs`

All artifact paths are relative to the Claude project root. Analysis output is written under `${CLAUDE_PLUGIN_DATA}` and accessed through bounded MCP read/search operations.

## Runtime defaults

The wrapper supports:

```text
SAFE_REVERSER_RUNTIME=auto|podman|docker
SAFE_REVERSER_IMAGE=<image>
SAFE_REVERSER_AUTO_PULL=0|1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

`SAFE_REVERSER_AUTO_PULL` defaults to `0`. This prevents merely enabling the plugin from silently downloading executable artifacts.

## Current static profile

Included in the sandbox image:

- Java 21 runtime
- JADX 1.5.6 with pinned SHA-256 verification
- Vineflower 1.12.0
- Python standard-library MCP server implementation

Not included in this static profile:

- ADB / emulator access
- Frida / Objection
- normal runtime network access
- curl/wget in the runtime image
- generic shell/exec MCP tools

Dynamic analysis should use a separate MCP server/image with a different privilege and network model.

## Security behavior

If the sandbox cannot start, the safe plugin should report the setup problem and stop. It must not silently fall back to the legacy host-executed scripts.

The intended boundary is:

```text
Agent
  -> allow-listed MCP tools
      -> non-root sandbox
          -> project mounted read-only
          -> analysis output isolated
          -> network disabled
```

## Attribution

This repository retains substantial work from the original Apache-2.0 project by Simone Avogadro. The MCP-first sandbox architecture and `safe-android-reverser` plugin are maintained in this fork.
