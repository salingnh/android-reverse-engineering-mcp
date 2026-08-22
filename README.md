# Safe Android Reverser MCP

**MCP-first, sandboxed Android reverse engineering with semantic program understanding for AI agents.**

Safe Android Reverser is an AI-native reverse code-intelligence platform. The agent asks semantic questions; a host control plane selects and verifies isolated capability workers; analyzers return bounded evidence with provenance.

> **The agent reasons. The MCP control plane controls. Capability workers execute.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

## Documentation

- **[Install / update / troubleshoot](docs/INSTALL_MCP.md)**
- **[Capability SPI v1](docs/CAPABILITY_SPI.md)**
- **[Project direction](docs/PROJECT_DIRECTION.md)**
- **[Roadmap](docs/ROADMAP.md)**
- **[Release procedure](docs/RELEASING.md)**
- **[Program-understanding implementation](docs/PROGRAM_UNDERSTANDING_PHASE1.md)**
- **[Research: AI-agent program understanding](docs/research/AI_AGENT_PROGRAM_UNDERSTANDING.md)**

## Quick start

```text
1. Install Podman or Docker
2. /plugin marketplace add salingnh/android-reverse-engineering-mcp
3. /plugin install safe-android-reverser@salingnh-reverse-tools
4. /reload-plugins
5. /mcp
6. Call health
7. Call fingerprint on an APK/XAPK/APKS/APKM
8. Follow the returned framework/capability route
```

Normal installation does not require a manual repository clone, `podman run`, or separate `claude mcp add` command.

For updates:

```text
/plugin marketplace update salingnh-reverse-tools
/plugin update safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Current published release: **0.2.1**.

**0.3.0 is in development and is not released until its architecture/security milestone gate passes.**

## 0.3.0 architecture

0.3.0 establishes the platform architecture intended to remain in place through later roadmap milestones:

```text
                         AI Agent
                            │
                            ▼
              ┌────────────────────────┐
              │ safe-android-reverser  │
              │ host MCP control plane │
              └───────────┬────────────┘
                          │
         ┌────────────────┼──────────────────┐
         │                │                  │
         ▼                ▼                  ▼
 Capability Registry   Runtime Driver   shared contracts
         │             Docker/Podman     paths / jobs /
         │                                evidence / PEG
         │
         ├───────────────────────┐
         ▼                       ▼
   static-core worker     framework-flutter worker
 APK/DEX/JVM/resources       Dart AOT/libapp.so
```

There is **one public MCP server**. Frameworks are capability modules, not separate public MCP control planes.

Only the host control plane invokes Docker/Podman. Workers do not receive runtime sockets.

Static/framework-static workers preserve the default trust boundary:

```text
network=none
read-only root filesystem
drop all Linux capabilities
no-new-privileges
non-root user
bounded CPU / memory / PID / tmpfs
explicit read-only/read-write mounts
```

## Capability SPI

Capability modules declare a versioned manifest:

```text
capability id
Capability API version
Worker ABI version
business-logic representations
trust boundary
worker protocol
image repository/role
public semantic operations
sandbox policy
```

Release 0.3 introduces:

```text
Capability API v1
Worker ABI v1
EvidenceEnvelope v1
```

The host control plane verifies worker OCI labels before execution.

Runtime readiness is separate from framework topology. `fingerprint` can identify Flutter and return:

```text
primary_capability_id = framework-flutter
```

while the host independently reports whether that capability is:

```text
declared / installed / ready / degraded / unavailable / unsupported
```

This prevents routing code from falsely claiming that an analyzer image/runtime is ready.

See [`docs/CAPABILITY_SPI.md`](docs/CAPABILITY_SPI.md).

## Framework-aware routing

```text
artifact
   ↓
fingerprint / router
   ├─ Native Android      → static-core / DEX / Java / Kotlin
   ├─ Flutter             → framework-flutter / Dart AOT / libapp.so
   ├─ React Native/Hermes → JavaScript/Hermes capability
   ├─ Unity IL2CPP        → metadata + native capability
   └─ .NET MAUI/Xamarin   → managed-code capability
```

JADX is not a universal business-logic analyzer. For Flutter release builds it mainly exposes the Android host shell and plugin bridges; the main Dart logic is usually AOT-compiled into `libapp.so`.

## Flutter AOT capability

The Flutter pipeline is:

```text
APK/XAPK/APKS/APKM
       ↓
bounded extraction of arm64-v8a libapp.so + libflutter.so
       ↓
local Dart runtime/snapshot identity
       ↓
registry-independent immutable cache_tag
       ↓
host selects exact runtime-cache image
       ↓
verify Capability API / Worker ABI / Dart / snapshot / Blutter provenance
       ↓
offline Blutter execution
       ↓
bounded Flutter semantic index
       ↓
semantic evidence queries
```

The analyzer worker never silently downloads or builds a missing Dart runtime. Cache miss is an explicit state. Exact runtime images are produced through the controlled build workflow.

Merged Flutter semantic capabilities include:

```text
find_dart_symbols
find_dart_strings
find_dart_xrefs
map_dart_to_native
extract_flutter_network_model
```

The final 0.3 control-plane slice exposes these through the same public MCP using `analyze_flutter_aot` and a returned `job_id`.

`extract_flutter_network_model` reconstructs bounded endpoint/host, HTTP-client, header, auth/token, signing/crypto, owning Dart function and native-offset evidence. It does **not** claim XREF adjacency is true value flow.

## Static-core capability

The static-core worker currently includes:

```text
Java 21
JADX 1.5.6
Vineflower 1.12.0
Androguard 4.1.4
file
binutils: strings / readelf / objdump / nm
Python MCP worker
```

Current static semantic operations include:

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

`build_program_index` prefers Androguard DEX semantics and persists a bounded method/call-edge index. Decompiled source is a presentation/localization layer, not canonical truth.

## Public control-plane operations

The 0.3 control plane adds:

```text
health
list_capabilities
```

`health` reports actual capability readiness and the architecture/contract versions.

`list_capabilities` exposes manifest topology and runtime readiness without analyzing an artifact.

The public tool surface deliberately does **not** expose generic shell, exec, bash, Docker, Podman, raw Blutter/Rizin/Ghidra consoles, or unrestricted Frida JavaScript.

## Evidence model

Capability-specific optimized indexes remain private implementation details:

```text
DEX semantic SQLite
Flutter semantic SQLite
future native/IR/Hermes caches
```

The control plane adds a stable compatibility descriptor to public results:

```text
safe_reverser_contract
  capability_id
  capability_api
  worker_abi
  operation
  evidence_envelope_version
```

When a producer supplies valid material provenance, results also receive a common `evidence_envelope`.

Evidence states are strictly:

```text
observed
derived
hypothesized
```

No numeric confidence is invented by the platform.

The Program Evidence Graph remains the cross-capability semantic model. Future data-flow/native/dynamic/security engines add evidence and graph relations rather than replacing the 0.3 orchestration architecture.

## Recommended investigation workflow

```text
health
  ↓
list_capabilities if readiness needs inspection
  ↓
fingerprint
  ↓
route by primary_capability_id
  ├─ static-core → decompile/index/query DEX/JVM evidence
  └─ framework-flutter → analyze_flutter_aot/query Dart evidence
  ↓
network/auth/crypto localization
  ↓
CFG/native/framework escalation only where needed
  ↓
read bounded high-signal evidence for verification
```

Example prompt:

```text
Analyze artifacts/app.xapk using only safe-android-reverser MCP.

1. Call health and verify the control-plane/capability states.
2. Fingerprint the artifact and follow primary_capability_id.
3. Never use Java/Kotlin decompilation as primary Flutter business-logic evidence.
4. For Flutter, call analyze_flutter_aot and retain its job_id.
5. Query Dart symbols, strings, XREFs, native mappings and the Flutter network model.
6. For native Android, use decompile + build_program_index + semantic queries.
7. Read only bounded high-signal evidence needed to verify conclusions.
8. Preserve analyzer/provenance/evidence states.
9. Do not describe CALLS/XREFS as proven data flow.
10. Report unsupported or unavailable capability boundaries explicitly.
```

## Roadmap invariant

0.3.0 is the foundation, not a temporary bridge. Later milestones extend the same contracts:

```text
0.3  platform foundation + Flutter AOT
0.4  true data-flow intelligence
0.5  security intelligence
0.6  dynamic correlation capability
0.7  native/JNI capability
0.8  Hermes / IL2CPP / .NET capabilities
0.9  pattern discovery + independent verification
1.0  stable compatibility contracts
```

A later milestone must not introduce a mechanism already known to replace the previous milestone's control plane, capability, job/runtime, or evidence architecture. Breaking contract changes require an explicit architecture decision, migration path, compatibility tests, and senior review.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for acceptance criteria and current status.

## Development process

Code changes follow:

```text
feature branch
  ↓
implementation
  ↓
unit / integration / static checks
  ↓
mandatory code review
  ↓
fix Blocker / High findings
  ↓
rerun tests
  ↓
review gate PASS
  ↓
create PR
  ↓
PR CI
  ↓
merge only after explicit approval
```

Milestones require a senior acceptance review before development moves to the next milestone.
