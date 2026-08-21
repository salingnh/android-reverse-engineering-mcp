# Install, update and use Safe Android Reverser MCP

This is the supported installation and update path for `safe-android-reverser` 0.2.1 and later.

The distribution model is intentionally simple:

```text
Claude plugin version
        =
bundled wrapper version
        =
GHCR sandbox image version
        =
MCP server version
```

Normal users should not clone this repository, manually pull container images, or register the MCP separately.

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

Docker is also supported:

```bash
docker --version
docker info
```

Do not run Claude Code or the plugin with `sudo`.

## 2. Install once

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Then verify:

```text
/mcp
```

The plugin bundles `.mcp.json`; no `claude mcp add` command is required.

On first use, the wrapper reads its bundled `VERSION` file and automatically starts the matching immutable sandbox image. For release 0.2.1 that image is:

```text
ghcr.io/salingnh/safe-android-reverser:0.2.1
```

The wrapper prefers rootless Podman, falls back to Docker, creates writable plugin data, maps the host UID/GID, and runs the MCP over stdio in an ephemeral locked-down container.

## 3. Update the plugin

When a new release is available, update the marketplace and plugin inside Claude Code:

```text
/plugin marketplace update salingnh-reverse-tools
/plugin update safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

If your Claude Code build manages updates through the `/plugin` UI, use the equivalent **Marketplace refresh** and **Update** actions there.

You do not need to run `podman pull` or remove the old image. A new plugin release references a new semver image tag, so the wrapper pulls it automatically when it is missing.

Example:

```text
installed plugin 0.2.0
        ↓ update
installed plugin 0.2.1
        ↓ wrapper reads VERSION=0.2.1
checks image :0.2.1
        ↓ missing
pulls image :0.2.1
        ↓
starts MCP 0.2.1
```

Old Claude plugin cache directories and old container images may remain on disk. That is expected; they are not selected by the active plugin release.

## 4. Verify release consistency with `health`

After install or update, run:

```text
Use only the safe-android-reverser MCP server.
Call health and report the release metadata and analyzer availability.
Do not analyze an artifact yet.
```

A healthy release returns a `release` block similar to:

```json
{
  "server_version": "0.2.1",
  "plugin_version": "0.2.1",
  "image_version": "0.2.1",
  "image_ref": "ghcr.io/salingnh/safe-android-reverser:0.2.1",
  "image_id": "...",
  "build_commit": "...",
  "version_consistent": true
}
```

If the default image label does not match the bundled plugin version, the wrapper fails before starting MCP instead of silently running a mismatched image.

## 5. Put an artifact under the project root

The Claude project is mounted read-only at `/workspace`. Keep artifacts under the project root and pass relative paths only:

```bash
mkdir -p artifacts
cp /path/to/app.xapk artifacts/app.xapk
```

Do not pass arbitrary absolute host paths.

## 6. Cheap first smoke test

```text
Use only the safe-android-reverser MCP server.
1. Call health and require release.version_consistent=true.
2. Fingerprint artifacts/app.xapk.
3. Report framework, APK members, HTTP stack, obfuscation level, native libraries, notable SDKs and the recommended analyzer route.
Do not decompile yet.
```

## 7. Full semantic analysis prompt

For native Android/Java/Kotlin applications:

```text
Analyze artifacts/app.xapk using only the safe-android-reverser MCP server.

Required workflow:
1. Call health. Stop if MCP/sandbox is unavailable or release.version_consistent is false.
2. Fingerprint the artifact and identify its APK members/framework.
3. If protector detection is available, call identify_protector and use the result to adjust the analysis route.
4. If native Android/Java/Kotlin analysis is appropriate, decompile with JADX and keep the returned job_id.
5. Call build_program_index(job_id).
6. Call extract_network_model(job_id).
7. Use find_symbols and find_xrefs to trace important features/endpoints through their callers and callees.
8. Use get_cfg only when branch/control-flow detail is required.
9. Use search_source/read_source_file only for high-signal evidence that verifies the graph-based conclusion.
10. Report application/framework summary, first-party hosts/endpoints, declaring methods, caller/callee evidence, model hints, auth/signature signals, strongest evidence with confidence, and unresolved questions.

Do not use host JADX/Java/Androguard, host shell commands, sudo, install-dep.sh, or non-MCP reverse-engineering paths.
Do not describe XREF adjacency as proven data-flow.
```

Key semantic operations are:

```text
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
```

`extract_api` remains useful for a cheap endpoint inventory; prefer `extract_network_model` when you need usage context.

## Runtime defaults

Normal users should not set these manually:

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

The default image is derived from the bundled plugin `VERSION`; it is not independently hard-coded in the installation instructions.

Advanced users may force a runtime before launching Claude Code:

```bash
export SAFE_REVERSER_RUNTIME=podman
# or
export SAFE_REVERSER_RUNTIME=docker
```

A custom development image can be supplied with `SAFE_REVERSER_IMAGE`. Version-label enforcement is skipped only for this explicit override; release metadata still exposes the plugin version and selected image reference.

## What the wrapper starts

For Podman the effective security profile is equivalent to:

```bash
podman run \
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
  --volume="<project>:/workspace:ro,z" \
  --volume="<plugin-data>:/data:rw,z" \
  ghcr.io/salingnh/safe-android-reverser:<plugin-version>
```

Before launching the container, the wrapper also verifies that the data directory and `jobs` directory are writable by the current host UID/GID.

## Troubleshooting

### MCP is not listed or not connected

Run:

```text
/reload-plugins
/mcp
```

If the plugin was just updated, restart Claude Code if your client does not reload the MCP process cleanly.

### `/data/jobs` permission error

Release 0.2.1 performs a host-side writability check before container startup. If you still see a permission error, verify the exact active wrapper and data directory rather than changing permissions globally.

For Podman, a direct mount check is:

```bash
DATA_DIR="$HOME/.local/share/safe-android-reverser-test"
mkdir -p "$DATA_DIR"

podman run --rm \
  --userns=keep-id \
  --user="$(id -u):$(id -g)" \
  --volume="$DATA_DIR:/data:rw,z" \
  --entrypoint /bin/sh \
  ghcr.io/salingnh/safe-android-reverser:0.2.1 \
  -lc 'id; mkdir -p /data/jobs; touch /data/jobs/write-test; ls -lnZ /data/jobs/write-test'
```

Do not use `chmod 777` as a workaround.

### Test with MCP Inspector

Claude can keep historical plugin versions in `~/.claude/plugins/cache`. Do not choose an arbitrary result with `find ... | head -n1`; that can launch an old wrapper.

List all cached wrapper versions first:

```bash
find ~/.claude/plugins/cache \
  -type f \
  -name safe-reverser-mcp \
  -print
```

Select the path belonging to the active plugin version shown by `/plugin` or `/mcp`, then launch Inspector with that exact path:

```bash
MCP_WRAPPER="/exact/path/to/the/active/0.2.1/bin/safe-reverser-mcp"

SAFE_REVERSER_PROJECT_DIR="$PWD" \
SAFE_REVERSER_DATA_DIR="$HOME/.local/share/safe-android-reverser-inspector" \
npx @modelcontextprotocol/inspector "$MCP_WRAPPER"
```

In Inspector, connect and call:

```text
Tools -> health -> Run Tool
```

A successful `initialize`, `tools/list`, and `health` call proves the MCP transport and sandbox work independently of the agent's tool-safety/classification layer.

### Diagnose the exact wrapper command

For troubleshooting only:

```bash
SAFE_REVERSER_PROJECT_DIR="$PWD" \
SAFE_REVERSER_DATA_DIR="$HOME/.local/share/safe-android-reverser-inspector" \
SAFE_REVERSER_RUNTIME=podman \
timeout 5 bash -x "$MCP_WRAPPER" </dev/null 2>/tmp/safe-reverser-wrapper.trace

cat /tmp/safe-reverser-wrapper.trace
```

Confirm the trace uses the expected semver image and includes `--user=<host uid>:<host gid>`.

## Security boundary

Automatic startup does not expose Podman, Docker, a generic shell, or arbitrary command execution as MCP tools.

```text
Agent
  -> allow-listed semantic MCP tools
      -> version-checked wrapper
          -> ephemeral non-root container
              -> read-only project input
              -> isolated writable analysis data
              -> no normal runtime network
```

If this path fails, the plugin reports the setup error instead of falling back to legacy host-executed reverse-engineering scripts.
