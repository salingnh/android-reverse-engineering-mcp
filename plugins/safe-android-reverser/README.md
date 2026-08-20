# Safe Android Reverser plugin

A Claude Code plugin that exposes Android static reverse engineering through a sandboxed MCP server.

Normal installation is intentionally simple: install Podman/Docker, install the plugin, reload it, and use MCP. The plugin wrapper automatically starts the container and pulls the pinned sandbox image on first use if it is missing.

## Quick start

### 1. Verify Podman or Docker

Rootless Podman is recommended:

```bash
podman --version
podman info
```

Docker is also supported.

### 2. Install from the marketplace

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

No manual `podman pull`, `podman run`, environment variables, or `claude mcp add` command are required for the default path.

### 3. Verify MCP

```text
/mcp
```

Then:

```text
Use only the safe-android-reverser MCP server.
Call health and report the server version and whether JADX, Java, and Vineflower are available.
Do not analyze any artifact yet.
```

### 4. Analyze a test APK

Put the APK under the Claude project root:

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

Then:

```text
Use only the safe-android-reverser MCP server.
Run health and then fingerprint artifacts/app.apk.
Return the framework, HTTP stack, obfuscation level, native libraries, notable SDKs, and recommended next analyzer.
Do not decompile yet.
```

For the full workflow:

```text
/safe-decompile artifacts/app.apk
```

or ask Claude to fingerprint, decompile, run `extract_api`, and inspect high-signal source evidence using only the MCP tools.

## Automatic container lifecycle

The plugin bundles `.mcp.json`. When Claude Code starts or reconnects this MCP server, it launches:

```text
Claude Code
  -> safe-reverser-mcp wrapper
      -> detect Podman/Docker
      -> create plugin data directory
      -> auto-pull pinned image when missing
      -> podman/docker run --rm -i
          -> MCP server + JADX / Vineflower
```

The container is ephemeral and tied to the MCP stdio session. It is not a persistent daemon and does not need `podman run -d` or `podman compose up`.

For rootless Podman the wrapper combines:

```text
--userns=keep-id
--user=<current-host-uid>:<current-host-gid>
```

so the bind-mounted `/data` directory remains writable without running the container as root or changing host ownership.

## Runtime defaults

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

Normally you do not need to set any of them.

If both runtimes exist, `auto` prefers Podman. To opt out of automatic image pulls:

```bash
export SAFE_REVERSER_AUTO_PULL=0
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

All artifact paths are relative to the Claude project root. Analysis output is stored under the plugin data directory and accessed through bounded MCP operations.

## Security behavior

The sandbox uses a read-only root filesystem and read-only project mount, drops Linux capabilities, disables privilege escalation and normal network access, limits CPU/memory/PIDs, and runs non-root.

The MCP API deliberately does not expose generic `shell`, `exec`, `bash`, `docker`, or `podman` tools.

If the sandbox cannot start, the plugin reports the setup problem instead of falling back to host-executed reverse-engineering scripts.

## Troubleshooting

For manual Podman commands, MCP JSON-RPC smoke tests, `/data` permission checks, and `CONNECTION_CLOSED` diagnosis, see [`../../docs/INSTALL_MCP.md`](../../docs/INSTALL_MCP.md).

## Attribution

This repository retains substantial work from the original Apache-2.0 project by Simone Avogadro. The MCP-first sandbox architecture and `safe-android-reverser` plugin are maintained in this fork.
