# Safe Android Reverser

A Claude Code plugin that exposes Android static reverse-engineering as a sandboxed MCP server.
It is derived from ideas in the original `android-reverse-engineering` plugin while moving
execution out of the host environment.

## Why this plugin exists

The original workflow can install dependencies and run decompilers directly on the host.
This variant keeps the LLM-facing workflow but moves binary parsing/decompilation into an
isolated container with an allow-listed MCP API.

## Install from the marketplace after merge

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Claude Code plugins can bundle MCP servers; when the plugin is enabled, its `.mcp.json` server
starts automatically.

## Test the feature branch before merge

The marketplace can be pinned to the feature branch:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill@feat/safe-sandbox-plugin
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

The feature branch CI builds the image but deliberately does not publish a production tag.
Build a local image from the branch and point the plugin at it:

```bash
git clone --branch feat/safe-sandbox-plugin https://github.com/salingnh/android-reverse-engineering-skill.git
cd android-reverse-engineering-skill
set -a
source sandbox/tools.lock.env
set +a
docker build -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .
export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
```

## Install the released sandbox image

After the safe plugin is merged to `master`, the workflow publishes:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

or:

```bash
docker pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

The plugin intentionally does **not** auto-pull by default. To opt in:

```bash
export SAFE_REVERSER_AUTO_PULL=1
```

To use a locally built image:

```bash
export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
```

To force a runtime:

```bash
export SAFE_REVERSER_RUNTIME=podman
# or
export SAFE_REVERSER_RUNTIME=docker
```

## MCP tools

- `health`
- `fingerprint`
- `decompile`
- `extract_api`
- `search_source`
- `read_source_file`
- `recover_kotlin_names`
- `list_jobs`

All artifact paths are relative to the Claude project root. The project is mounted read-only;
outputs are stored under `${CLAUDE_PLUGIN_DATA}` and exposed back through bounded MCP read/search
tools rather than giving the model unrestricted filesystem execution inside the container.

## Current static profile

Included in the image:

- Java 21 runtime
- JADX 1.5.6 with a pinned SHA-256 release ZIP
- Vineflower 1.12.0 (version-pinned; checksum hardening remains to be completed)
- Python stdlib MCP server implementation

Not included in this profile:

- ADB / emulator access
- Frida / Objection
- network access
- curl/wget in the runtime image
- dex2jar APK conversion

Dynamic analysis should be a separate image and MCP server with an explicitly different threat
model.

## Attribution

This fork retains the repository's Apache-2.0 license and preserves the original plugin. The
safe plugin is a new execution architecture maintained in this fork.
