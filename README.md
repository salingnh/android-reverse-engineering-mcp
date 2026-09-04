# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering with semantic program understanding for AI agents.**

Safe Android Reverser is an AI-native reverse code-intelligence platform. The agent asks semantic questions; one host control plane selects and verifies isolated capability workers; analyzers return bounded evidence with provenance.

> **The agent reasons. The MCP control plane controls. Capability workers execute.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

## Documentation

- **[Install / update / troubleshoot](docs/INSTALL_MCP.md)**
- **[Project direction](docs/PROJECT_DIRECTION.md)**
- **[Roadmap](docs/ROADMAP.md)**
- **[Capability SPI v1](docs/CAPABILITY_SPI.md)**
- **[Development and review rules](docs/DEVELOPMENT.md)**
- **[Release procedure](docs/RELEASING.md)**
- **[Program-understanding phase 1](docs/PROGRAM_UNDERSTANDING_PHASE1.md)**
- **[Research: AI-agent program understanding](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md)**

Coding agents must also follow [`AGENTS.md`](AGENTS.md).

## Release status

Current published release: **0.4.0**.

Release metadata reaches `master` only after exact-head CI, immutable capability-image verification, and GitHub Release creation.

## Quick start

```text
1. Install rootless Podman or Docker
2. /plugin marketplace add salingnh/android-reverse-engineering-mcp
3. /plugin install safe-android-reverser@salingnh-reverse-tools
4. /reload-plugins
5. /mcp
6. Call health
7. Call fingerprint on APK/XAPK/APKS/APKM
8. Follow analysis_route.primary_capability_id
```

Normal users do not manually clone the repository, register multiple MCP servers, or run analyzer containers themselves.

## 0.3 architecture

```text
                         AI Agent
                            |
                            v
              safe-android-reverser MCP
                 Host Control Plane
                            |
          +-----------------+------------------+
          |                 |                  |
   Capability/Adapter    Runtime/Path       Evidence/PEG
      Registries          Job services        Contracts
          |
     +----+----------------------+-------------------+
     |                           |                   |
     v                           v                   v
 static-core              framework-flutter     future capabilities
 worker                    worker                native / Hermes /
                                                  IL2CPP / .NET /
                                                  security / dynamic
```

There is exactly **one public MCP server**.

Only the host control plane invokes Docker/Podman. Workers never receive runtime sockets.

Static/framework/native-static workers preserve:

```text
network=none
read-only root
cap-drop=ALL
no-new-privileges
non-root UID/GID
bounded CPU / memory / PIDs / tmpfs / traversal / output
```

Future dynamic analysis uses a separate `dynamic-opt-in` trust boundary and explicit enablement; static workers are not weakened to support it.

## Capability platform

0.3 establishes:

```text
Capability API       v1
Worker ABI           v1
EvidenceEnvelope     v1
PEG schema           v2
Flutter cache schema v2
```

A capability manifest declares:

```text
id
representations
trust_boundary
activation
adapter
protocol
image repository/role
public operations
sandbox policy
```

Activation semantics are:

```text
required
optional
opt-in
```

`dynamic-opt-in` must use `opt-in`. Opt-in modules are inactive until explicitly listed in `SAFE_REVERSER_ENABLE_CAPABILITIES`.

Public operation ownership is manifest-driven and unique. The control plane resolves operation -> capability -> adapter rather than maintaining framework-specific dispatch branches.

## Runtime identity

The host verifies required OCI labels and executes the verified immutable image ID:

```text
requested tag
   ↓
inspect / pull
   ↓
verify version + capability id + Capability API + Worker ABI
   ↓
resolve sha256 image ID
   ↓
run immutable image ID
```

This prevents mutable-tag drift between image verification and execution.

## Framework-aware routing

```text
artifact
   ↓
fingerprint / route_analysis
   ├─ Native Android      -> static-core / DEX / Java / Kotlin
   ├─ Flutter             -> framework-flutter / Dart AOT / libapp.so
   ├─ React Native/Hermes -> Hermes/JS capability when positively detected
   ├─ Unity IL2CPP        -> IL2CPP metadata + native capability
   └─ Xamarin/.NET MAUI   -> managed-code capability
```

JADX is not a universal business-logic analyzer. A missing framework analyzer is reported as unavailable/unsupported rather than silently replaced by semantically wrong Java/Kotlin analysis.

## Capability responsibilities

### `static-core`

Owns generic Android package/DEX/JVM/resource triage and semantics, framework-routing preflight, and fast generic native triage.

Current public operations include:

```text
fingerprint
route_analysis
inspect_flutter
identify_dart_runtime
extract_flutter_assets
decompile
extract_api
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
search_source
read_source_file
recover_kotlin_names
list_jobs
```

Framework-specific deep semantics must not accumulate in `static-core`.

### `framework-flutter`

Owns Flutter/Dart AOT business-logic analysis:

```text
analyze_flutter_aot
find_dart_symbols
find_dart_strings
find_dart_xrefs
map_dart_to_native
extract_flutter_network_model
list_flutter_jobs
```

Pipeline:

```text
APK/XAPK/APKS/APKM
   ↓
bounded extraction of libapp.so + libflutter.so
   ↓
local Dart/snapshot/runtime identity
   ↓
registry-independent runtime cache tag
   ↓
host selects and verifies exact immutable runtime image
   ↓
offline Blutter
   ↓
bounded persistent Flutter semantic index
   ↓
semantic evidence queries
```

A runtime-cache miss never triggers a hidden build/download in the analysis worker.

The cache identity binds cache schema, Capability API, Worker ABI, Dart version, snapshot hash, architecture, OS, compressed-pointer mode, and full Blutter commit.

## Evidence model

Capability-private optimized storage remains implementation detail:

```text
DEX SQLite
Flutter SQLite
future data-flow/native/Hermes/IL2CPP caches
```

Public results carry a common compatibility descriptor. Valid material provenance is normalized into `EvidenceEnvelope`.

Evidence state is strictly:

```text
observed
derived
hypothesized
```

The platform never invents numeric confidence.

CALLS/XREFS are not proven value flow. True `FLOWS_TO`/source/sink/sanitizer semantics are a 0.4 data-flow capability.

## Recommended investigation flow

```text
health
  ↓
list_capabilities when readiness needs inspection
  ↓
fingerprint
  ↓
follow primary_capability_id
  ├─ static-core          -> DEX/JVM semantic analysis
  └─ framework-flutter   -> Dart AOT semantic analysis
  ↓
network/auth/crypto localization
  ↓
CFG/native/framework escalation only where needed
  ↓
bounded evidence verification
```

Example prompt:

```text
Analyze artifacts/app.xapk using only safe-android-reverser MCP.

1. Call health and inspect capability readiness.
2. Fingerprint the artifact and follow primary_capability_id.
3. Do not use Java/Kotlin decompilation as primary Flutter business-logic evidence.
4. For Flutter, call analyze_flutter_aot and retain job_id.
5. Query Dart symbols, strings, XREFs, native mappings, and Flutter network model.
6. For native Android, use decompile + build_program_index + semantic queries.
7. Read only bounded high-signal evidence needed to verify conclusions.
8. Preserve provenance and evidence state.
9. Never describe CALLS/XREFS as proven data flow.
10. Report unavailable/unsupported capability boundaries explicitly.
```

## Roadmap

```text
0.3 Platform Foundation + Flutter AOT
0.4 Data-flow Intelligence
0.5 Security Intelligence
0.6 Dynamic Correlation
0.7 Native/JNI Intelligence
0.8 Framework Coverage
0.9 Pattern Discovery + Independent Verification
1.0 Stable Platform Contracts
```

0.3 is intentionally the last planned orchestration-foundation milestone. After acceptance, normal development should focus on analysis intelligence and evidence quality rather than repeated MCP/runtime restructuring.

## Development gate

Non-trivial work follows:

```text
feature/integration branch
   ↓
implementation + deterministic tests
   ↓
architecture/security review
   ↓
fix Blocker/High findings
   ↓
dead-reference/code sweep
   ↓
exact-head GitHub Actions
   ↓
senior acceptance for milestone/platform changes
   ↓
merge
```

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for mandatory engineering, capability-boundary, CI, documentation, and release rules.
