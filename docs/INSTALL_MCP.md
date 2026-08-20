# Install and verify Safe Android Reverser MCP

This guide installs the `safe-android-reverser` Claude Code plugin, starts its bundled MCP server through the sandbox wrapper, verifies that the MCP is healthy, and runs a first Android reverse-engineering prompt.

The runtime model is:

```text
Claude Code
    │
    │ MCP stdio
    ▼
safe-android-reverser plugin
    │
    ▼
safe-reverser-mcp wrapper
    │
    ▼
rootless Podman / Docker
    │
    ▼
MCP server + JADX / Vineflower
```

The analyzed project is mounted read-only. Reverse-engineering output is written to the plugin data directory. The static sandbox has no normal network access and does not expose an arbitrary shell tool.

## 1. Prerequisites

You need:

- Claude Code with plugin support;
- Git;
- either rootless Podman (recommended on Linux/Fedora) or Docker;
- an APK/JAR/AAR file you are authorized to analyze.

### Podman

Check that Podman is available:

```bash
podman --version
podman info
```

Rootless Podman is preferred because the container runtime itself does not require the user to belong to a root-equivalent Docker group.

### Docker

Alternatively:

```bash
docker --version
docker info
```

## 2. Choose the installation path

There are two supported paths.

### A. Released/master installation

Use this after `safe-android-reverser` has been merged and the GHCR image has been published.

Podman:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
podman image inspect ghcr.io/salingnh/safe-android-reverser:0.1.0 >/dev/null \
  && echo "safe-android-reverser image is ready"
```

Docker:

```bash
docker pull ghcr.io/salingnh/safe-android-reverser:0.1.0
docker image inspect ghcr.io/salingnh/safe-android-reverser:0.1.0 >/dev/null \
  && echo "safe-android-reverser image is ready"
```

The plugin intentionally does not auto-pull executable images by default.

### B. Current feature-branch installation

Use this while testing `feat/safe-sandbox-plugin` before the production image is published.

```bash
git clone \
  --branch feat/safe-sandbox-plugin \
  https://github.com/salingnh/android-reverse-engineering-mcp.git

cd android-reverse-engineering-mcp

set -a
source sandbox/tools.lock.env
set +a
```

Build with Podman:

```bash
podman build \
  -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .

podman image inspect safe-android-reverser:dev >/dev/null \
  && echo "development image is ready"
```

Or Docker:

```bash
docker build \
  -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .

docker image inspect safe-android-reverser:dev >/dev/null \
  && echo "development image is ready"
```

## 3. Start Claude Code with the runtime configuration

Environment variables must be visible to the Claude Code process because the plugin MCP wrapper inherits them when the MCP server starts.

For a released image with Podman:

```bash
export SAFE_REVERSER_RUNTIME=podman
export SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
claude
```

For a released image with Docker:

```bash
export SAFE_REVERSER_RUNTIME=docker
export SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
claude
```

For the locally built feature-branch image:

```bash
export SAFE_REVERSER_RUNTIME=podman
export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
claude
```

Replace `podman` with `docker` if required.

If Claude Code was already running before these variables were exported, restart it so the plugin MCP process receives the new environment.

## 4. Add the marketplace

### Released/master

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
```

### Current feature branch

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp@feat/safe-sandbox-plugin
```

## 5. Install the plugin

Inside Claude Code:

```text
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

The plugin contains `.mcp.json`, so the `safe-android-reverser` MCP server is started automatically when the plugin is enabled.

You do not need to run a separate `claude mcp add` command.

## 6. Verify that the MCP server is up

First open the MCP status view:

```text
/mcp
```

Verify that `safe-android-reverser` is listed and is connected/healthy. Exact status wording may vary by Claude Code version.

Then test the actual MCP tool surface with this prompt:

```text
Use only the safe-android-reverser MCP server.
Call the health tool and report whether the sandbox is ready and which reverse-engineering tools are available.
Do not decompile or analyze any artifact yet.
```

A successful test means:

1. Claude can see the `safe-android-reverser` MCP server;
2. the `health` tool returns without an MCP transport/runtime error;
3. the sandbox can see its installed reverse-engineering toolchain.

At this point the MCP path is working end to end:

```text
Claude -> plugin -> MCP wrapper -> container -> MCP server
```

## 7. Prepare a test APK

The MCP server only accepts artifact paths under the Claude project root because the project is mounted into the sandbox read-only.

From your project directory:

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

Start Claude Code from that project root, or ensure `CLAUDE_PROJECT_DIR` resolves to it.

Do not place the APK only in an unrelated host directory and pass an absolute host path; the sandbox intentionally restricts path access.

## 8. First test prompt

Use this prompt for a full safe static-analysis smoke test:

```text
Analyze artifacts/app.apk using only the safe-android-reverser MCP server.

Required workflow:
1. Call health first. If the MCP or sandbox is unavailable, stop and report the setup error.
2. Call fingerprint on artifacts/app.apk.
3. Report the detected framework, HTTP stack, obfuscation level, native libraries, and notable SDK signals.
4. If it is a native Android/JVM application, decompile it with JADX.
5. Run extract_api on the resulting analysis job.
6. Summarize likely first-party hosts, endpoint paths, HTTP/authentication signals, and the strongest source evidence.
7. Use search_source/read_source_file only for the highest-signal findings.
8. Do not execute host shell commands, host JADX/Java, install-dep.sh, sudo, or any non-MCP reverse-engineering path.
```

For a lighter first test that stops before decompilation:

```text
Use only safe-android-reverser MCP.
Run health and then fingerprint artifacts/app.apk.
Return only the fingerprint summary and recommended next analyzer. Do not decompile yet.
```

## 9. Slash command

The plugin also includes the safe workflow command:

```text
/safe-decompile artifacts/app.apk
```

The natural-language prompt above is preferable for the first smoke test because it makes each MCP step explicit and easier to diagnose.

## 10. Expected MCP tools

The current static MCP exposes:

```text
health
fingerprint
decompile
extract_api
search_source
read_source_file
recover_kotlin_names
list_jobs
```

It deliberately does not expose generic `shell`, `exec`, `bash`, `docker`, or `podman` tools.

## 11. Troubleshooting

### MCP server is not listed in `/mcp`

Run:

```text
/reload-plugins
```

If it is still absent, confirm the plugin is installed and enabled, then restart Claude Code.

### MCP starts but reports that the image is missing

Check the exact image configured in the shell that launches Claude Code:

```bash
echo "$SAFE_REVERSER_IMAGE"
echo "$SAFE_REVERSER_RUNTIME"
```

Then inspect it with the selected runtime:

```bash
podman image inspect "$SAFE_REVERSER_IMAGE"
```

or:

```bash
docker image inspect "$SAFE_REVERSER_IMAGE"
```

### Want the wrapper to pull automatically

Explicitly opt in before starting Claude Code:

```bash
export SAFE_REVERSER_AUTO_PULL=1
```

The default is `0` so enabling a plugin does not silently download executable images.

### Artifact path is rejected

Move the artifact under the project root, for example:

```text
<project>/artifacts/app.apk
```

and call MCP with the relative path:

```text
artifacts/app.apk
```

### Docker permission error

Use rootless Podman where possible. If Docker is required, configure Docker access according to your operating system's security policy rather than running the plugin with `sudo`.

## 12. Security boundary reminder

A healthy MCP session does not mean the agent receives unrestricted container access. The intended boundary remains:

```text
Agent
  -> allow-listed MCP tools
      -> non-root sandbox
          -> read-only project input
          -> isolated writable analysis data
          -> no normal runtime network
```

If the MCP path fails, the safe plugin should report the error. It must not silently fall back to the legacy host-executed reverse-engineering scripts.
