# Safe Android Reverser

**MCP-first, sandboxed Android reverse engineering for AI coding agents.**

Safe Android Reverser is evolving this repository from a collection of host-executed reverse-engineering scripts into a **controlled reverse-engineering service** that AI agents access through MCP.

The core design principle is:

> **The agent reasons. The MCP server controls. The sandbox executes.**

APK/JAR/AAR parsing and decompilation should not require an AI agent to install packages, invoke arbitrary shell commands, or run untrusted artifacts directly on the host.

---

## Project direction

The target architecture is not “a Claude skill that knows how to call JADX”.

It is a reusable reverse-engineering platform with three separate layers:

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

This separation is intentional:

- **Skill/plugin** — workflow, reasoning instructions, and user-facing commands.
- **MCP server** — stable tool API, path validation, job management, and controlled access to analysis results.
- **Sandbox image** — decompilers and binary-analysis tooling with restricted host/network access.

The MCP layer is intended to become the primary integration surface. Claude Code is the first client, not the only possible client.

---

## Current status

The new implementation lives in the `safe-android-reverser` plugin.

| Component | Status |
|---|---|
| Claude Code plugin | ✅ |
| Bundled MCP server | ✅ |
| Rootless Podman runtime | ✅ recommended |
| Docker runtime | ✅ |
| APK/XAPK/APKS/APKM fingerprinting | ✅ |
| JADX decompilation | ✅ |
| JAR/AAR Vineflower decompilation | ✅ |
| API / URL / auth signal extraction | ✅ |
| Source search/read through MCP | ✅ |
| Kotlin name-recovery candidates | ✅ |
| GHCR image build workflow | ✅ |
| Dynamic Android analysis | ⏳ separate future profile |
| Flutter / React Native analyzers | ⏳ planned |
| Native `.so` analysis | ⏳ planned |

The original `android-reverse-engineering` plugin is retained for upstream compatibility, but it is considered the **legacy host-execution path**. New development should target `safe-android-reverser` and the MCP/sandbox architecture.

---

## Security model

The main threat model is analyzing **untrusted mobile artifacts** without giving the artifact or reverse-engineering toolchain normal access to the developer workstation.

The sandbox launcher currently applies:

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

The MCP server does **not** expose arbitrary `shell`, `exec`, `bash`, `docker`, or `podman` tools.

Reverse-engineering subprocesses are invoked using fixed argument arrays rather than shell command strings.

### What the safe plugin does not do

The safe execution path does not:

- run `install-dep.sh`;
- call `sudo`;
- install apt/dnf/pacman/brew packages on the host;
- modify `.bashrc`, `.zshrc`, or host `PATH`;
- run host-installed JADX/Vineflower as an automatic fallback;
- give the static analyzer normal network access;
- expose ADB, Frida, or an Android device to the static-analysis container.

If the sandbox cannot start, the correct behavior is to report the setup problem — **not to silently fall back to host execution**.

---

## MCP API

The current MCP server exposes a deliberately small tool surface:

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

### `health`

Checks the sandbox and toolchain versions.

### `fingerprint`

Performs cheap pre-decompilation triage:

- artifact type;
- Android framework signals;
- Flutter / React Native / Cordova / Xamarin markers;
- HTTP stack hints;
- DI / serialization libraries;
- obfuscation estimate;
- native libraries;
- notable SDKs.

Fingerprinting happens before expensive decompilation so the system can choose the correct analyzer instead of blindly applying JADX to every mobile artifact.

### `decompile`

Creates an isolated analysis job.

Current engine strategy:

```text
APK / XAPK / APKS / APKM  -> JADX
JAR                        -> Vineflower or JADX
AAR                        -> classes.jar + libs/*.jar -> Vineflower
```

### `extract_api`

Extracts high-signal network evidence including:

- Retrofit annotations;
- OkHttp/Ktor-style calls;
- hard-coded URLs;
- endpoint-shaped path literals;
- auth/header/signing indicators;
- likely first-party vs third-party hosts.

### `search_source` / `read_source_file`

The agent should retrieve only relevant pieces of decompiled code through MCP instead of receiving unrestricted shell access to the analysis directory.

### `recover_kotlin_names`

Produces **candidate** original Kotlin names from surviving metadata/debug evidence.

Recovered names are treated as evidence with confidence, not guaranteed truth. R8/shrinker configurations can remove metadata and annotations.

---

## Claude Code plugin

The repository marketplace is:

```text
salingnh-reverse-tools
```

The recommended plugin is:

```text
safe-android-reverser
```

Plugin structure:

```text
plugins/safe-android-reverser/
├── .claude-plugin/
│   └── plugin.json
├── .mcp.json
├── bin/
│   └── safe-reverser-mcp
├── commands/
│   └── safe-decompile.md
└── skills/
    └── safe-android-reverser/
        └── SKILL.md
```

The plugin bundles its MCP configuration, so enabling the plugin starts the MCP server through the sandbox wrapper.

---

## Installation

### 1. Add the marketplace

After the implementation is merged to `master`:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill
```

### 2. Install the safe plugin

```text
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

### 3. Install the sandbox image

Rootless Podman is recommended on Linux/Fedora:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

Docker is also supported:

```bash
docker pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

The plugin intentionally does **not** auto-pull executable images by default.

To explicitly enable auto-pull:

```bash
export SAFE_REVERSER_AUTO_PULL=1
```

Runtime selection can be forced when required:

```bash
export SAFE_REVERSER_RUNTIME=podman
# or
export SAFE_REVERSER_RUNTIME=docker
```

---

## Development / feature branch

Current implementation branch:

```text
feat/safe-sandbox-plugin
```

The marketplace can be tested directly from that branch:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill@feat/safe-sandbox-plugin
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Build a local image:

```bash
git clone \
  --branch feat/safe-sandbox-plugin \
  https://github.com/salingnh/android-reverse-engineering-skill.git

cd android-reverse-engineering-skill

set -a
source sandbox/tools.lock.env
set +a

podman build \
  -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .

export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
export SAFE_REVERSER_RUNTIME=podman
```

Use `docker build` instead of `podman build` if required.

---

## Toolchain policy

Tool versions are selected when the sandbox image is built, not dynamically at analysis time.

Current static profile:

```text
Java        21
JADX        1.5.6
Vineflower  1.12.0
Python      standard-library MCP implementation
```

JADX is version-pinned and SHA-256 verified during the image build.

Runtime containers do not contain download utilities such as `curl` or `wget` and do not resolve `latest` releases.

Further supply-chain hardening will include checksum verification for every downloaded build artifact and stronger image provenance/release controls.

---

## Analysis workflow

The intended agent workflow is:

```text
artifact
   │
   ▼
fingerprint
   │
   ├── Flutter / RN / hybrid / .NET
   │        └── choose specialized analyzer
   │
   └── native Android / JVM
             │
             ▼
          decompile
             │
             ▼
         extract_api
             │
             ▼
      search/read evidence
             │
             ▼
    optional Kotlin recovery
             │
             ▼
       structured findings
```

The LLM is responsible for interpretation and call-flow reasoning. Binary processing and filesystem access remain behind MCP.

---

## Roadmap

The longer-term goal is a **general reverse-engineering MCP platform**, not an Android-only shell skill.

### Phase 1 — Safe Android static analysis

Current focus:

- sandboxed JADX/Vineflower;
- robust APK/AAB-family handling;
- network/API extraction;
- Kotlin/R8 evidence recovery;
- structured results;
- reproducible container builds.

### Phase 2 — Structured analysis model

Move analyzer output toward normalized JSON/evidence objects:

```json
{
  "artifact": {},
  "framework": {},
  "obfuscation": {},
  "network": {},
  "symbols": [],
  "endpoints": [],
  "name_candidates": [],
  "evidence": []
}
```

This reduces dependence on grep-style text dumps and makes the same analyzers usable from different AI clients.

### Phase 3 — Framework-specific analyzers

Planned analyzer profiles:

```text
Android JVM        JADX / resources / DEX
Flutter            libapp.so / Dart-specific analysis
React Native       Hermes / JS bundle analysis
Native libraries   ELF / strings / symbols / disassembly
```

Each analyzer should remain behind the same MCP abstraction.

### Phase 4 — Semantic program analysis

Potential additions:

- call graph generation;
- AST-based endpoint detection;
- data-flow tracing;
- request/response model extraction;
- gRPC/protobuf discovery;
- WebSocket/SSE/MQTT detection;
- confidence-scored cross-reference evidence.

### Phase 5 — Separate dynamic-analysis MCP

Dynamic analysis will use a **different sandbox/profile and threat model**.

Possible capabilities:

```text
ADB / emulator
Frida / Objection
controlled interception proxy
runtime network tracing
certificate-pinning diagnostics
```

Static analysis will not automatically gain these privileges.

---

## Repository layout

```text
android-reverse-engineering-skill/
├── .claude-plugin/
│   └── marketplace.json
├── .github/workflows/
│   └── build-safe-sandbox.yml
├── plugins/
│   ├── safe-android-reverser/          # primary direction
│   │   ├── .claude-plugin/plugin.json
│   │   ├── .mcp.json
│   │   ├── bin/safe-reverser-mcp
│   │   ├── commands/safe-decompile.md
│   │   └── skills/safe-android-reverser/SKILL.md
│   │
│   └── android-reverse-engineering/    # legacy/upstream-compatible plugin
│
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

The original `android-reverse-engineering` plugin and shell/PowerShell workflow remain in this repository for compatibility and attribution.

They are **not** the preferred execution architecture for new development.

If intentionally required:

```text
/plugin install android-reverse-engineering@salingnh-reverse-tools
```

New analyzer functionality should normally be implemented behind the MCP server rather than added as another host-executed installation/script path.

---

## CI and image publishing

`.github/workflows/build-safe-sandbox.yml` validates:

- MCP tests;
- shell wrapper syntax;
- plugin/marketplace JSON;
- sandbox image build.

The release path is intended to publish:

```text
ghcr.io/salingnh/safe-android-reverser:<version>
```

with BuildKit SBOM/provenance metadata.

Production image publication should happen from controlled `master`/release-tag workflows rather than arbitrary feature branches.

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
