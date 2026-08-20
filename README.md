# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering with semantic program understanding for AI agents.**

Safe Android Reverser is evolving from a safe wrapper around decompilers into an **AI-native reverse code-intelligence platform**. The agent should not need to read an entire JADX tree to understand an application. MCP provides bounded semantic operations over symbols, XREFs, control flow, endpoints, authentication signals and evidence provenance.

> **The agent reasons. The MCP server controls. The sandbox executes.**

## Quick start

Full installation guide: **[`docs/INSTALL_MCP.md`](docs/INSTALL_MCP.md)**  
Implementation notes: **[`docs/PROGRAM_UNDERSTANDING_PHASE1.md`](docs/PROGRAM_UNDERSTANDING_PHASE1.md)**  
Roadmap: **[`docs/ROADMAP.md`](docs/ROADMAP.md)**  
Research: **[`docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md`](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md)**

Normal installation remains deliberately simple:

```text
1. Install Podman or Docker
2. /plugin marketplace add salingnh/android-reverse-engineering-mcp
3. /plugin install safe-android-reverser@salingnh-reverse-tools
4. /reload-plugins
5. /mcp
6. Call health
7. Analyze an APK/XAPK
```

No manual `podman pull`, `podman run`, runtime exports, or separate `claude mcp add` command is required for the default path.

The wrapper automatically:

```text
detects Podman/Docker
→ creates isolated plugin data
→ pulls ghcr.io/salingnh/safe-android-reverser:0.2.0 if missing
→ starts a locked-down ephemeral container
→ connects MCP over stdio
```

## Why semantic program understanding

The 0.1.x baseline could answer questions such as:

```text
Which URLs exist?
Which HTTP stack is present?
Which source file contains "Authorization"?
```

The 0.2.0 direction adds the foundation for questions closer to how coding agents understand a source repository:

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

### Existing baseline

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

### Semantic 0.2.0 layer

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
identify_protector (if available)
  ↓
decompile
  ↓
build_program_index
  ↓
find_symbols / find_xrefs
  ↓
extract_network_model
  ↓
get_cfg only for ambiguous control flow
  ↓
search_source / read_source_file for evidence verification
```

Example prompt:

```text
Analyze artifacts/app.xapk using only safe-android-reverser MCP.

1. Call health and fingerprint first.
2. Decompile when the detected framework makes Java/Kotlin analysis appropriate.
3. Build the program index.
4. Build the network model.
5. For important first-party endpoints, trace their declaring methods and incoming/outgoing XREFs.
6. Inspect CFG only where branch behavior is relevant.
7. Read only high-signal source ranges needed to verify the graph evidence.
8. Report call-flow evidence, request/response model hints, auth/signature signals, evidence locations and confidence.
9. Do not describe XREF adjacency as proven data-flow.
```

## Static image 0.2.0

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

JADX and the top-level Androguard wheel are version-pinned and digest-verified. Fully locking the transitive Python dependency set is a documented supply-chain hardening item.

Large/native/dynamic analyzers are intentionally not all placed in the default image.

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
container user        non-root
```

Runtime layout:

```text
/workspace   read-only project input
/data        persistent analysis output
/work        ephemeral working area
/tmp         ephemeral temporary area
```

The MCP deliberately does **not** expose generic `shell`, `exec`, `bash`, raw analyzer consoles, Docker, or Podman tools. Analyzer backends remain implementation details behind allow-listed semantic operations.

## Repository layout

```text
android-reverse-engineering-mcp/
├── .claude-plugin/marketplace.json
├── .github/workflows/build-safe-sandbox.yml
├── docs/
│   ├── INSTALL_MCP.md
│   ├── PROGRAM_UNDERSTANDING_PHASE1.md
│   ├── ROADMAP.md
│   └── research/AI_AGENT_PROGRAM_UNDERSTANDING.md
├── plugins/
│   ├── safe-android-reverser/
│   │   ├── .claude-plugin/plugin.json
│   │   ├── .mcp.json
│   │   ├── bin/safe-reverser-mcp
│   │   └── skills/safe-android-reverser/SKILL.md
│   └── android-reverse-engineering/    # legacy/upstream-compatible
├── sandbox/
│   ├── Dockerfile
│   ├── mcp_server.py                   # 0.1.x core
│   ├── mcp_server_v2.py                # semantic MCP extension
│   ├── program_understanding.py
│   ├── tests.py
│   ├── tests_program_understanding.py
│   ├── test_wrapper.sh
│   └── tools.lock.env
├── LICENSE
└── README.md
```

## Roadmap

The next high-value capabilities are not simply more reverse-engineering CLIs. They are semantic code-intelligence primitives:

```text
trace_value
find_auth_flow
find_signing_logic
Android lifecycle/component graph
feature/module summaries
JNI cross-language mapping
native evidence graph
framework-specific analyzers
static ↔ dynamic evidence correlation
```

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the tool/profile roadmap and [`docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md`](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md) for the broader codebase-understanding architecture.

## CI and image publishing

CI validates the legacy MCP core, semantic program-understanding tests, MCP v2 tool registration, wrapper behavior, Python/shell syntax, JSON manifests and the complete sandbox image build.

Controlled `master`/release-tag workflows publish:

```text
ghcr.io/salingnh/safe-android-reverser:<version>
```

with BuildKit SBOM/provenance metadata.

## Legal use

Use this project only for lawful reverse engineering, interoperability work, authorized security research, malware analysis, incident response, education, or systems you are authorized to inspect.

## License and attribution

Apache-2.0 — see [LICENSE](LICENSE).

This repository originated from and still contains substantial work from:

[SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill)

The MCP-first sandbox and semantic program-understanding architecture are maintained in this fork.
