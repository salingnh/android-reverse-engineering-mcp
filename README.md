# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering with semantic program understanding for AI agents.**

Safe Android Reverser is evolving from a safe wrapper around decompilers into an **AI-native reverse code-intelligence platform**. The agent should not need to read an entire JADX tree to understand an application. MCP provides bounded semantic operations over symbols, XREFs, control flow, endpoints, authentication signals and evidence provenance.

> **The agent reasons. The MCP server controls. The sandbox executes.**

## Quick start

Documentation:

- **[Install / update / troubleshoot](docs/INSTALL_MCP.md)**
- **[Release procedure](docs/RELEASING.md)**
- **[Program-understanding implementation](docs/PROGRAM_UNDERSTANDING_PHASE1.md)**
- **[Roadmap](docs/ROADMAP.md)**
- **[Research: AI-agent program understanding](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md)**

Normal installation is deliberately short:

```text
1. Install Podman or Docker
2. /plugin marketplace add salingnh/android-reverse-engineering-mcp
3. /plugin install safe-android-reverser@salingnh-reverse-tools
4. /reload-plugins
5. /mcp
6. Call health
7. Analyze an APK/XAPK
```

No manual `podman pull`, `podman run`, runtime exports, repository clone, or separate `claude mcp add` command is required for the normal path.

For updates:

```text
/plugin marketplace update salingnh-reverse-tools
/plugin update safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

The active plugin wrapper reads its bundled `VERSION`, starts the matching sandbox image, and rejects a default image whose OCI version metadata does not match the plugin release.

```text
plugin VERSION
      =
wrapper default image tag
      =
OCI image version
      =
MCP server version
```

Current release: **0.2.1**.

## Current development focus

**In development: framework-aware routing with Flutter AOT analysis as the first priority.**

The current semantic DEX pipeline works well for native Android Java/Kotlin applications, but a Flutter release moves most Dart business logic into AOT-compiled native code, typically `libapp.so`. Continuing to run JADX after Flutter has already been detected only analyzes the Android host shell and misses the main application logic.

The current development track therefore changes the analysis pipeline from "decompile every APK with the same tools" to **detect → route → analyze the representation that actually contains the business logic**:

```text
artifact
   ↓
fingerprint / framework router
   ├─ Native Android      → DEX / JADX / Androguard semantics
   ├─ Flutter             → Dart AOT-aware analysis of libapp.so + flutter assets
   ├─ React Native/Hermes → Hermes / JavaScript bytecode analysis
   ├─ Unity IL2CPP        → metadata + native analysis
   └─ .NET MAUI/Xamarin   → managed assembly analysis
```

The immediate Flutter work is:

- identify `libapp.so`, `libflutter.so`, Flutter assets, ABI, and Dart/Flutter runtime metadata;
- add a dedicated `framework-flutter` capability profile rather than treating Flutter as generic ELF only;
- integrate a Dart AOT-aware analyzer such as **Blutter** behind bounded semantic MCP operations;
- normalize recovered Dart strings, object-pool data, classes/functions, code offsets, endpoints, auth/crypto signals and evidence into the common Program Evidence Graph;
- map important Dart-level findings back to native offsets so Rizin/Ghidra can be used only when deeper native CFG/XREF analysis is required;
- keep runtime patching, reFlutter, Frida, proxying and device access in the separate explicit-opt-in dynamic trust boundary.

Generic native reverse engineering remains an important substrate, but for Flutter the key requirement is **Dart AOT-aware native analysis**, not merely disassembling `libapp.so` as an ordinary stripped ELF.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the prioritized implementation plan.

## Why semantic program understanding

The 0.1.x baseline could answer questions such as:

```text
Which URLs exist?
Which HTTP stack is present?
Which source file contains "Authorization"?
```

The semantic layer adds primitives closer to how coding agents understand a source repository:

```text
Which method declares this endpoint?
Who calls it?
What call-flow neighborhood reaches it?
Which request/response models are nearby?
Where are auth/signature signals introduced?
What CFG branches exist inside this method?
Which evidence supports the conclusion?
```

The design deliberately distinguishes **call/XREF evidence** from future true interprocedural **data-flow evidence**. XREF adjacency must not be presented as proof that a value flows between two methods.

## Architecture

```text
                     AI Agent
                        │
                 semantic MCP API
                        │
                        ▼
             Safe Android Reverser MCP
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
   fingerprint       decompile       program index
                       │                │
                  JADX/Vineflower       ├─ symbols
                                        ├─ DEX XREFs
                                        ├─ CFG
                                        └─ evidence
                                             │
                                             ▼
                                   structured network model
                                             │
                                             ▼
                                      targeted source reads
```

Execution is separated from the agent:

```text
Claude Code
    │
    ▼
plugin-bundled wrapper
    │
    ├─ reads VERSION
    ├─ verifies writable data directory
    ├─ selects Podman/Docker
    ├─ validates image version metadata
    └─ launches isolated stdio MCP container
             │
             ▼
       allow-listed analyzers
```

The long-term architecture separates execution profiles:

```text
safe-android-reverser
├── static-core      APK / DEX / Java / Kotlin / resources
├── native           ELF / JNI / native decompilation
├── framework        Flutter / Hermes / Unity / protocols
└── dynamic          ADB / Frida / runtime observation (separate trust boundary)
```

Dynamic analysis will not silently gain the privileges of the static profile.

## Current MCP API

Baseline operations:

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

Semantic operations:

```text
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
```

`build_program_index` prefers Androguard DEX semantics and persists a bounded normalized method/call-edge index. If DEX semantic analysis cannot run, it may fall back to a lower-confidence source symbol index instead of failing the whole MCP session.

`find_symbols` localizes classes/methods without scanning the entire decompiled tree.

`find_xrefs` returns bounded incoming/outgoing method XREFs. DEX XREF edges preserve analyzer provenance and bytecode offsets when available.

`get_cfg` returns bounded basic-block control-flow graphs for selected methods.

`identify_protector` is an adapter for an optional external APKiD analyzer. APKiD is intentionally not bundled in the default static image yet while redistribution/license policy is finalized separately.

`extract_network_model` extends endpoint extraction by correlating Retrofit declarations with declaring methods, caller XREFs, model hints, auth/signature signals and evidence locations.

## Recommended investigation workflow

```text
health
  ↓
fingerprint
  ↓
route by detected framework
  ├─ Java/Kotlin → decompile + program index
  └─ framework-specific representation → specialized analyzer
  ↓
identify_protector (if available)
  ↓
semantic localization / XREF / network model
  ↓
CFG or native/framework-specific analysis only where needed
  ↓
read only high-signal evidence for verification
```

Example prompt:

```text
Analyze artifacts/app.xapk using only safe-android-reverser MCP.

1. Call health and require release.version_consistent=true.
2. Fingerprint the artifact and route analysis according to the detected framework.
3. Use Java/Kotlin decompilation only when it contains the relevant business logic.
4. Build the available semantic program/framework index.
5. Build the network model.
6. For important first-party endpoints, trace their declaring functions and incoming/outgoing references.
7. Inspect CFG/native code only where branch behavior or framework-specific AOT logic is relevant.
8. Read only high-signal source/binary evidence needed to verify graph evidence.
9. Report call-flow evidence, model hints, auth/signature signals, evidence locations and confidence state.
10. Do not describe XREF adjacency as proven data-flow.
```

## Static image 0.2.1

Primary tooling:

```text
Java 21
JADX 1.5.6
Vineflower 1.12.0
Androguard 4.1.4
file
binutils: strings / readelf / objdump / nm
Python MCP implementation
```

The image embeds:

- `org.opencontainers.image.version`;
- `org.opencontainers.image.revision`;
- runtime build/version metadata returned by `health`.

The wrapper passes the active plugin version and image identity into the MCP runtime. A normal `health` call reports:

```json
{
  "release": {
    "server_version": "0.2.1",
    "plugin_version": "0.2.1",
    "image_version": "0.2.1",
    "image_ref": "ghcr.io/salingnh/safe-android-reverser:0.2.1",
    "image_id": "...",
    "build_commit": "...",
    "version_consistent": true
  }
}
```

JADX and the top-level Androguard wheel are version-pinned and digest-verified. Fully locking the transitive Python dependency set remains a documented supply-chain hardening item.

## Security model

The static launcher applies:

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
container user        host UID/GID mapped, non-root
```

Runtime layout:

```text
/workspace   read-only project input
/data        persistent analysis output
/work        ephemeral working area
/tmp         ephemeral temporary area
```

The MCP deliberately does **not** expose generic `shell`, `exec`, `bash`, raw analyzer consoles, Docker, or Podman tools. Analyzer backends remain implementation details behind allow-listed semantic operations.

## Release and update model

`plugins/safe-android-reverser/VERSION` is the canonical semver source for the safe plugin release.

CI verifies that the marketplace and plugin manifests match it. Docker builds receive the same version as a required build argument and verify it against the copied `VERSION` file.

Publishing is intentionally split:

```text
pull request
  -> test/build only

master
  -> :master
  -> :sha-<commit>

safe-vX.Y.Z tag
  -> verify tag == VERSION
  -> refuse existing :X.Y.Z
  -> publish immutable :X.Y.Z
  -> publish :sha-<commit>
```

A `master` push no longer overwrites a semver image tag. Broken releases are fixed by issuing a new patch version rather than mutating an existing image.

See [docs/RELEASING.md](docs/RELEASING.md) for the exact maintainer workflow.

## Repository layout

```text
android-reverse-engineering-mcp/
├── .claude-plugin/marketplace.json
├── .github/workflows/build-safe-sandbox.yml
├── docs/
│   ├── INSTALL_MCP.md
│   ├── RELEASING.md
│   ├── PROGRAM_UNDERSTANDING_PHASE1.md
│   ├── ROADMAP.md
│   └── research/AI_AGENT_PROGRAM_UNDERSTANDING.md
├── plugins/
│   ├── safe-android-reverser/
│   │   ├── VERSION
│   │   ├── .claude-plugin/plugin.json
│   │   ├── .mcp.json
│   │   ├── bin/safe-reverser-mcp
│   │   └── skills/safe-android-reverser/SKILL.md
│   └── android-reverse-engineering/    # legacy/upstream-compatible
├── sandbox/
│   ├── Dockerfile
│   ├── mcp_server.py                   # baseline core
│   ├── mcp_server_v2.py                # semantic extension
│   ├── mcp_entrypoint.py               # release metadata/version binding
│   ├── program_understanding.py
│   ├── tests.py
│   ├── tests_program_understanding.py
│   ├── test_wrapper.sh
│   └── tools.lock.env
├── scripts/
│   └── check_release_consistency.py
├── LICENSE
└── README.md
```

## Roadmap

The next high-value capabilities are framework-aware and semantic code-intelligence primitives rather than simply more reverse-engineering CLIs:

```text
Framework Router
Flutter Dart AOT analysis
trace_value
find_auth_flow
find_signing_logic
Android lifecycle/component graph
feature/module summaries
JNI cross-language mapping
native evidence graph
Hermes / IL2CPP / managed-runtime analyzers
static ↔ dynamic evidence correlation
```

See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md`](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md).

## CI and image publishing

CI validates:

- release consistency across manifests/wrapper/image/tag;
- baseline and semantic MCP behavior;
- source-scope/cache regressions;
- wrapper auto-start and UID/GID mapping;
- Python/shell/JSON syntax;
- complete sandbox image build;
- real DEX semantic analysis inside the image;
- MCP `health` and release metadata inside the final image.

BuildKit SBOM/provenance metadata is published with released images.

## Legal use

Use this project only for lawful reverse engineering, interoperability work, authorized security research, malware analysis, incident response, education, or systems you are authorized to inspect.

## License and attribution

Apache-2.0 — see [LICENSE](LICENSE).

This repository originated from and still contains substantial work from:

[SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill)

The MCP-first sandbox and semantic program-understanding architecture are maintained in this fork.
