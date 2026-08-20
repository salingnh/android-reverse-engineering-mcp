# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering for AI coding agents.**

Safe Android Reverser turns Android reverse-engineering into a controlled MCP service instead of running decompilers and installation scripts directly on the host.

> **The agent reasons. The MCP server controls. The sandbox executes.**

---

## Quick start

Full guide: **[`docs/INSTALL_MCP.md`](docs/INSTALL_MCP.md)**.

The default installation path is now:

```text
1. Install Podman or Docker
2. Add the marketplace
3. Install safe-android-reverser
4. /reload-plugins
5. /mcp
6. Call health
7. Analyze an APK
```

You do **not** need to manually run `podman pull`, `podman run`, export runtime variables, or register a separate MCP server for the normal path.

### 1. Verify the container runtime

Rootless Podman is recommended:

```bash
podman --version
podman info
```

Docker is also supported. If both are installed, the wrapper prefers Podman.

### 2. Install the plugin

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

The plugin bundles `.mcp.json`. On first MCP startup the wrapper automatically:

```text
detects Podman/Docker
→ creates the plugin data directory
→ pulls ghcr.io/salingnh/safe-android-reverser:0.1.0 if missing
→ starts an ephemeral locked-down container
→ connects MCP over stdio
```

The container is tied to the MCP session and is removed automatically when that session ends. It is not a persistent daemon.

### 3. Verify the MCP

```text
/mcp
```

Then:

```text
Use only the safe-android-reverser MCP server.
Call health and report the server version and whether JADX, Java, and Vineflower are available.
Do not analyze any artifact yet.
```

### 4. Put a test APK under the project root

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

### 5. First smoke test

```text
Use only the safe-android-reverser MCP server.
Run health and then fingerprint artifacts/app.apk.
Return the framework, HTTP stack, obfuscation level, native libraries, notable SDKs, and recommended next analyzer.
Do not decompile yet.
```

For a full workflow:

```text
Analyze artifacts/app.apk using only the safe-android-reverser MCP server.
Fingerprint it first, decompile native Android/JVM code with JADX when appropriate, run extract_api, then inspect only high-signal source evidence using search_source/read_source_file.
Do not use host reverse-engineering tools or legacy host scripts.
```

The plugin also includes:

```text
/safe-decompile artifacts/app.apk
```

---

## Automatic Podman/Docker lifecycle

The plugin is designed so users do not manage the sandbox container manually:

```text
Claude Code
    │
    │ bundled MCP config
    ▼
safe-reverser-mcp wrapper
    │
    ├─ runtime auto-detection
    ├─ first-use image pull
    ├─ host UID/GID mapping
    ├─ read-only project mount
    ├─ writable isolated data mount
    └─ resource/security limits
              │
              ▼
       ephemeral container
              │
              ▼
       MCP server + analyzers
```

For rootless Podman the wrapper runs with both `--userns=keep-id` and the current host UID/GID. This keeps `/data` writable without changing host file ownership and fixes the previous `/data/jobs` permission failure.

Manual `podman run` commands are documented only for troubleshooting in [`docs/INSTALL_MCP.md`](docs/INSTALL_MCP.md).

---

## Architecture

```text
AI Agent
Claude Code / Codex / other MCP clients
                │
                │ MCP
                ▼
       Reverse Engineering MCP
                │
        allow-listed operations
                │
                ▼
      Sandboxed execution runtime
       rootless Podman / Docker
                │
       ┌────────┼─────────┐
       ▼        ▼         ▼
     JADX   Vineflower   analyzers
                │
                ▼
        structured evidence
                │
                ▼
             AI Agent
```

Responsibilities are separated deliberately:

- **Skill/plugin** — workflow, reasoning instructions, and user-facing commands.
- **MCP server** — stable tool API, path validation, job management, and bounded access to results.
- **Sandbox image** — decompilers and binary-analysis tools with restricted host/network access.

The MCP layer is the primary integration surface. Claude Code is the first client, not the only possible client.

---

## Current MCP API

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

### `health`

Checks MCP/sandbox readiness and the reverse-engineering toolchain.

### `fingerprint`

Performs cheap pre-decompilation triage:

- native Android vs Flutter / React Native / Cordova / Xamarin markers;
- HTTP stack hints;
- DI / serialization libraries;
- obfuscation estimate;
- native libraries;
- notable SDKs.

### `decompile`

Current engine strategy:

```text
APK / XAPK / APKS / APKM  -> JADX
JAR                        -> Vineflower or JADX
AAR                        -> classes.jar + libs/*.jar -> Vineflower
```

### `extract_api`

Extracts high-signal network evidence such as Retrofit annotations, URLs, endpoint-shaped paths, authentication/signing indicators, and likely first-party vs third-party hosts.

### `search_source` / `read_source_file`

Retrieves bounded decompiled evidence without giving the agent unrestricted shell/filesystem access to analysis output.

### `recover_kotlin_names`

Produces candidate original Kotlin names from surviving metadata/debug evidence with confidence rather than treating them as guaranteed truth.

---

## Security model

The sandbox launcher applies:

```text
network              none
root filesystem      read-only
Linux capabilities   dropped
privilege escalation disabled
project directory    read-only
analysis output       isolated writable directory
CPU                   limited
memory                limited
PID count             limited
container user        non-root
```

Runtime layout:

```text
/workspace   read-only project input
/data        persistent analysis output
/work        ephemeral working area
/tmp         ephemeral temporary area
```

The safe path does not:

- run `install-dep.sh`;
- call `sudo`;
- install host packages;
- modify shell profiles or host `PATH`;
- fall back to host-installed JADX/Vineflower;
- expose ADB, Frida, or a device to the static sandbox;
- give the static analyzer normal network access.

If the MCP path fails, the plugin reports the setup error instead of falling back to legacy host execution.

---

## Runtime defaults

Normal users do not need to set these manually:

```text
SAFE_REVERSER_RUNTIME=auto
SAFE_REVERSER_IMAGE=ghcr.io/salingnh/safe-android-reverser:0.1.0
SAFE_REVERSER_AUTO_PULL=1
SAFE_REVERSER_MEMORY=4g
SAFE_REVERSER_CPUS=2
SAFE_REVERSER_PIDS_LIMIT=256
```

Advanced users can override them before starting Claude Code. Set `SAFE_REVERSER_AUTO_PULL=0` to disable first-use image pulling.

---

## Toolchain policy

Current static image:

```text
Java        21
JADX        1.5.6
Vineflower  1.12.0
Python      standard-library MCP implementation
```

JADX is version-pinned and SHA-256 verified during image build. Runtime containers do not contain `curl`/`wget` and do not resolve `latest` releases during analysis.

---

## Repository layout

```text
android-reverse-engineering-mcp/
├── .claude-plugin/
│   └── marketplace.json
├── .github/workflows/
│   └── build-safe-sandbox.yml
├── docs/
│   └── INSTALL_MCP.md
├── plugins/
│   ├── safe-android-reverser/
│   │   ├── .claude-plugin/plugin.json
│   │   ├── .mcp.json
│   │   ├── bin/safe-reverser-mcp
│   │   ├── commands/safe-decompile.md
│   │   └── skills/safe-android-reverser/SKILL.md
│   └── android-reverse-engineering/    # legacy/upstream-compatible
├── sandbox/
│   ├── Dockerfile
│   ├── mcp_server.py
│   ├── tests.py
│   ├── test_wrapper.sh
│   └── tools.lock.env
├── LICENSE
└── README.md
```

---

## Legacy upstream plugin

The original `android-reverse-engineering` plugin and its shell/PowerShell workflow remain for compatibility and attribution, but they are not the preferred execution path.

New analyzer functionality should normally be implemented behind MCP rather than as another host-executed script/install path.

---

## Roadmap

The longer-term goal is a general reverse-engineering MCP platform, including normalized evidence output, Flutter/React Native profiles, native `.so` analysis, semantic call/data-flow analysis, and a separate dynamic-analysis MCP for controlled ADB/Frida use.

Static analysis will not automatically gain dynamic-analysis privileges.

---

## CI and image publishing

`.github/workflows/build-safe-sandbox.yml` validates:

- MCP tests;
- automatic runtime-wrapper behavior;
- shell syntax;
- plugin/marketplace JSON;
- sandbox image build.

The release path publishes:

```text
ghcr.io/salingnh/safe-android-reverser:<version>
```

with BuildKit SBOM/provenance metadata from controlled `master`/release-tag workflows.

---

## Legal use

Use this project only for lawful reverse engineering, interoperability work, authorized security research, malware analysis, incident response, education, or systems you are authorized to inspect.

---

## License and attribution

Apache-2.0 — see [LICENSE](LICENSE).

This repository originated from and still contains substantial work from:

[SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill)

The MCP-first sandbox architecture and `safe-android-reverser` plugin are maintained in this fork.
