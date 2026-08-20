# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering for AI coding agents.**

Safe Android Reverser is evolving this repository from host-executed reverse-engineering scripts into a **controlled reverse-engineering service** that AI agents access through MCP.

> **The agent reasons. The MCP server controls. The sandbox executes.**

The primary path no longer requires the agent to install JADX/Java on the host, call `sudo`, modify shell profiles, or execute arbitrary reverse-engineering commands directly on the workstation.

---

## Quick start

The full step-by-step guide is in **[`docs/INSTALL_MCP.md`](docs/INSTALL_MCP.md)**.

The intended first-run sequence is:

```text
1. Install Podman/Docker
2. Prepare the sandbox image
3. Start Claude Code with SAFE_REVERSER_* variables
4. Add the marketplace
5. Install safe-android-reverser
6. /reload-plugins
7. /mcp
8. Call health
9. Fingerprint an APK
10. Run a full safe analysis prompt
```

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

For the current `feat/safe-sandbox-plugin` branch, build the image locally instead:

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

Set these variables **before starting Claude Code**. The bundled MCP server inherits them when the plugin starts.

### 3. Add the marketplace and plugin

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

The plugin bundles `.mcp.json`, so you do **not** need a separate `claude mcp add` command.

### 4. Verify the MCP is up

Inside Claude Code:

```text
/mcp
```

Verify that `safe-android-reverser` is listed and connected/healthy.

Then run this prompt:

```text
Use only the safe-android-reverser MCP server.
Call the health tool and report whether the sandbox is ready and which reverse-engineering tools are available.
Do not decompile or analyze any artifact yet.
```

If `health` succeeds, the end-to-end MCP path is working:

```text
Claude -> plugin -> MCP wrapper -> container -> MCP server
```

### 5. Put a test APK under the project root

```bash
mkdir -p artifacts
cp /path/to/app.apk artifacts/app.apk
```

The project is mounted read-only into the sandbox, so artifact paths passed to MCP should be relative to the Claude project root.

### 6. First test prompt

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
8. Do not execute host shell commands, host JADX/Java, install-dep.sh, sudo, or a non-MCP reverse-engineering path.
```

For a cheaper fingerprint-only smoke test:

```text
Use only safe-android-reverser MCP.
Run health and then fingerprint artifacts/app.apk.
Return only the fingerprint summary and recommended next analyzer. Do not decompile yet.
```

The plugin also includes:

```text
/safe-decompile artifacts/app.apk
```

For first-time validation, the explicit prompt above is easier to diagnose because every MCP step is visible.

---

## Architecture

The target architecture is a reusable reverse-engineering platform rather than a skill that simply knows how to call JADX:

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

The MCP layer is intended to become the primary integration surface. Claude Code is the first client, not the only possible client.

---

## Current MCP API

The static MCP currently exposes:

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

- artifact type;
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

Extracts high-signal network evidence:

- Retrofit annotations;
- OkHttp/Ktor-style calls;
- hard-coded URLs;
- endpoint-shaped path literals;
- auth/header/signing indicators;
- likely first-party vs third-party hosts.

### `search_source` / `read_source_file`

Lets the agent retrieve only relevant decompiled evidence instead of receiving unrestricted shell access to the analysis directory.

### `recover_kotlin_names`

Produces candidate original Kotlin names from surviving metadata/debug evidence with confidence rather than treating them as guaranteed truth.

---

## Security model

The primary threat model is analyzing **untrusted mobile artifacts** without giving the artifact or reverse-engineering toolchain normal workstation access.

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

The safe path does not automatically:

- run `install-dep.sh`;
- call `sudo`;
- install host packages;
- modify `.bashrc`, `.zshrc`, or host `PATH`;
- fall back to host-installed JADX/Vineflower;
- expose ADB, Frida, or a device to the static sandbox;
- give the static analyzer normal network access.

If the MCP path fails, the safe plugin should report the setup error and stop instead of silently falling back to legacy host execution.

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

Further supply-chain hardening will pin and verify every downloaded build artifact and strengthen image provenance/release controls.

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
│   ├── safe-android-reverser/          # primary direction
│   │   ├── .claude-plugin/plugin.json
│   │   ├── .mcp.json
│   │   ├── bin/safe-reverser-mcp
│   │   ├── commands/safe-decompile.md
│   │   └── skills/safe-android-reverser/SKILL.md
│   └── android-reverse-engineering/    # legacy/upstream-compatible plugin
├── sandbox/
│   ├── Dockerfile
│   ├── mcp_server.py
│   ├── tests.py
│   ├── tools.lock.env
│   └── README.md
├── LICENSE
└── README.md
```

---

## Legacy upstream plugin

The original `android-reverse-engineering` plugin and its shell/PowerShell workflow remain for compatibility and attribution, but they are **not** the preferred execution architecture for new development.

If intentionally required:

```text
/plugin install android-reverse-engineering@salingnh-reverse-tools
```

New analyzer functionality should normally be implemented behind MCP rather than as another host-executed script/install path.

---

## Roadmap

The longer-term goal is a general reverse-engineering MCP platform.

Planned directions include:

- normalized JSON/evidence output;
- Flutter and React Native analyzer profiles;
- native `.so` analysis;
- call graph and AST/data-flow analysis;
- request/response model extraction;
- gRPC/protobuf, WebSocket/SSE/MQTT discovery;
- a **separate** dynamic-analysis MCP/profile for ADB, Frida/Objection, controlled proxying, and scoped network access.

Static analysis will not automatically gain dynamic-analysis privileges.

---

## CI and image publishing

`.github/workflows/build-safe-sandbox.yml` validates:

- MCP tests;
- shell wrapper syntax;
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

You are responsible for compliance with applicable laws, licenses, and software terms.

---

## License and attribution

Apache-2.0 — see [LICENSE](LICENSE).

This repository originated from and still contains substantial work from:

[SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill)

The MCP-first sandbox architecture and `safe-android-reverser` plugin are the direction maintained by this fork.
