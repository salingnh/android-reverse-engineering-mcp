# Safe Android Reverser plugin

A Claude Code plugin that exposes sandboxed Android reverse engineering and semantic program understanding through the `safe-android-reverser` MCP server.

The normal user path remains simple: install Podman/Docker, install the plugin, reload it, and use MCP. The wrapper automatically detects the runtime, pulls the pinned image when missing, maps writable plugin data correctly for rootless containers, and ties the ephemeral container lifetime to the MCP stdio session.

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

### 3. Verify MCP 0.2.1

```text
/mcp
```

Then:

```text
Use only the safe-android-reverser MCP server.
Call health and report:
- server version
- JADX, Java and Vineflower availability
- Androguard availability
- semantic program-understanding capabilities
- program-index storage type
- call-path capability
Do not analyze an artifact yet.
```

The standard 0.2.1 image should report Androguard, XREF/CFG support, bounded call-path traversal and SQLite program-index storage as available. APKiD may be unavailable because it remains an optional external analyzer in this profile.

### 4. Analyze an APK/XAPK

Keep the artifact under the Claude project root:

```bash
mkdir -p artifacts
cp /path/to/app.xapk artifacts/app.xapk
```

A cheap first test:

```text
Use only safe-android-reverser MCP.
Run health and fingerprint artifacts/app.xapk.
Report the framework, APK members, HTTP stack, obfuscation level, native libraries, notable SDKs and recommended next analyzer.
Do not decompile yet.
```

For native Android/Java/Kotlin analysis, the preferred semantic workflow is:

```text
health
  -> fingerprint
  -> identify_protector (when available)
  -> decompile
  -> build_program_index
  -> extract_network_model
  -> find_symbols / find_xrefs
  -> trace_call_path when source and target anchors are known
  -> get_cfg only where control-flow detail is useful
  -> targeted search_source / read_source_file for evidence verification
```

Do not describe XREF or call-path adjacency as proven data-flow.

## Automatic container lifecycle

The plugin bundles `.mcp.json`. When Claude Code starts or reconnects the MCP server:

```text
Claude Code
  -> safe-reverser-mcp wrapper
      -> detect Podman/Docker
      -> create plugin data directory
      -> pull ghcr.io/salingnh/safe-android-reverser:0.2.1 when missing
      -> podman/docker run --rm -i
          -> MCP 0.2.1
              -> JADX / Vineflower
              -> Androguard DEX/XREF/CFG
              -> indexed SQLite program graph
              -> bounded shortest call-path traversal
              -> structured network evidence
```

The container is ephemeral, not a background daemon. For rootless Podman the wrapper combines:

```text
--userns=keep-id
--user=<current-host-uid>:<current-host-gid>
```

so `/data` remains writable without root or recursive ownership changes on the host.

## Runtime defaults

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.2.1
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

If both runtimes are available, `auto` prefers Podman. To prevent first-use image downloads:

```bash
export SAFE_REVERSER_AUTO_PULL=0
```

## MCP tools

Baseline:

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

Semantic 0.2.1 layer:

```text
build_program_index
find_symbols
find_xrefs
trace_call_path
get_cfg
identify_protector
extract_network_model
```

`build_program_index` uses one cross-split DEX analysis graph for APK bundles when Androguard succeeds and stores the canonical method/call-edge index in SQLite. A lower-confidence source declaration fallback is retained for malformed/protected artifacts.

`trace_call_path` performs deterministic bounded breadth-first traversal over the indexed XREF graph. It returns shortest paths with exact method IDs, keeps broad query matches as explicit candidate sets, supports forward/reverse traversal, and reports index/search truncation rather than presenting incomplete negatives as conclusive.

`extract_network_model` resolves Retrofit endpoints conservatively against class + method + parameter count. Ambiguous symbols are reported as ambiguous and do not receive a union of unrelated callers.

All artifact paths are relative to the Claude project root. Analysis output remains under the plugin data directory and is accessed through bounded MCP operations.

## Security behavior

The static sandbox uses a read-only root filesystem and project mount, drops Linux capabilities, disables privilege escalation and normal network access, limits CPU/memory/PIDs, and runs non-root.

The MCP API deliberately does not expose generic `shell`, `exec`, `bash`, Docker, Podman or raw analyzer consoles. Dynamic analysis remains a separate future privilege profile.

If the sandbox cannot start, the plugin reports the setup problem instead of falling back to host-executed reverse-engineering scripts.

## Documentation

- Installation and troubleshooting: [`../../docs/INSTALL_MCP.md`](../../docs/INSTALL_MCP.md)
- Phase 1 implementation: [`../../docs/PROGRAM_UNDERSTANDING_PHASE1.md`](../../docs/PROGRAM_UNDERSTANDING_PHASE1.md)
- M1 call-path traversal: [`../../docs/TRACE_CALL_PATH.md`](../../docs/TRACE_CALL_PATH.md)
- Roadmap: [`../../docs/ROADMAP.md`](../../docs/ROADMAP.md)
- Research: [`../../docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md`](../../docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md)

## Attribution

This repository retains substantial work from the original Apache-2.0 project by Simone Avogadro. The MCP-first sandbox architecture and `safe-android-reverser` plugin are maintained in this fork.
