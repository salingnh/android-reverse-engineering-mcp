# Project Direction

This document is the canonical long-term product and architecture direction for Safe Android Reverser MCP. Significant architecture, security, analyzer-routing, trust-boundary, or product-priority decisions must be recorded here.

## Product vision

Safe Android Reverser is an **AI-native Android security and program-understanding platform**, not a collection of reverse-engineering CLI wrappers.

The stable product abstractions are:

- one public MCP control plane;
- framework-aware representation routing;
- versioned Capability SPI and Worker ABI;
- isolated capability workers;
- shared runtime, artifact/path, job, and evidence contracts;
- Program Evidence Graph (PEG) semantics;
- reproducible provenance;
- deterministic verification of agent hypotheses;
- explicit trust boundaries.

Underlying analyzers such as JADX, Androguard, Blutter, Rizin, Ghidra, Frida, Apktool, FlowDroid, or future replacements are implementation details and evidence producers.

## Core principles

### 1. The agent reasons. The MCP control plane controls. Capability workers execute.

The AI agent selects semantic questions and reasons over bounded evidence. It does not receive generic shell, Docker/Podman, raw analyzer console, or unrestricted instrumentation primitives.

The host-side MCP control plane owns:

- capability discovery;
- framework/capability dispatch;
- worker image selection and verification;
- Docker/Podman lifecycle;
- analysis job lifecycle;
- shared compatibility and evidence contracts.

Untrusted application parsing and analyzer execution happen inside constrained workers.

### 2. Exactly one public MCP control plane

The plugin exposes one public server:

```text
safe-android-reverser
```

Frameworks and backends are capability modules, not additional public MCP control planes.

Target topology:

```text
AI agent
   |
   v
safe-android-reverser MCP
host control plane
   |
   +-- Capability Registry
   +-- Runtime Driver
   +-- Artifact/Path SDK
   +-- Analysis Job Store
   +-- Evidence/PEG contracts
   |
   +-- static-core worker
   +-- framework-flutter worker
   +-- native worker
   +-- framework-hermes worker
   +-- framework-il2cpp worker
   +-- dynamic worker
```

Only the host control plane may call the container runtime. No worker receives a Docker/Podman socket.

### 3. Detect the framework before selecting the analyzer

Do not assume APK means Java/Kotlin.

```text
artifact
   ↓
fingerprint / framework router
   ├─ Native Android      → static-core / DEX / Java / Kotlin
   ├─ Flutter             → framework-flutter / Dart AOT / libapp.so
   ├─ React Native/Hermes → JavaScript/Hermes representation
   ├─ Unity IL2CPP        → metadata + native representation
   └─ Xamarin/.NET MAUI   → managed assemblies
```

The router declares deterministic topology: representation and `primary_capability_id`. Runtime readiness is discovered separately by the host control plane.

A missing capability never silently authorizes JADX as the application's primary business-logic analyzer.

### 4. Capability SPI is the extension mechanism

Release 0.3.0 establishes **Capability SPI v1** and **Worker ABI v1** as the extension mechanism for later roadmap milestones.

A capability manifest defines:

```text
id
capability_api
worker_abi
representations
trust_boundary
worker protocol
image repository/role
operations
sandbox policy
```

The registry rejects duplicate operation ownership and incompatible contract versions.

See [`CAPABILITY_SPI.md`](CAPABILITY_SPI.md).

### 5. Do not intentionally build temporary architecture

From 0.3.0 onward, a roadmap milestone must not introduce a mechanism that is already known to be replaced in the next milestone.

Later milestones extend implementation behind the stable contracts:

- Capability SPI;
- Worker ABI;
- Runtime Driver;
- analysis/job lifecycle;
- artifact/path safety primitives;
- evidence/PEG contract.

A breaking change to one of those contracts requires an architecture decision, migration path, compatibility tests, and senior review. It must not appear as a silent milestone-to-milestone rewrite.

Internal optimizations are allowed when contracts remain compatible. For example, one-container-per-worker-call can later become a bounded worker pool without changing the public MCP surface or Capability SPI.

### 6. Decompilation is a presentation layer, not canonical truth

JADX/Vineflower source is useful for explanation and localization. Important facts should retain provenance to DEX, IR, native addresses, framework metadata, analyzer outputs, or runtime observations wherever possible.

### 7. Native analysis is a substrate, not a universal framework analyzer

Flutter release business logic is commonly AOT-compiled into `libapp.so`, but generic ELF disassembly loses Dart semantics. Flutter therefore uses a Dart AOT-aware capability first and escalates to generic native analysis only after Dart-level localization.

The same representation-first rule applies to Hermes, IL2CPP, and managed runtimes.

### 8. PEG and evidence contracts are the long-lived semantic core

Capability workers may keep optimized private indexes:

```text
DEX SQLite index
Flutter SQLite index
Ghidra project/cache
Hermes index
future data-flow IR
```

Those storage formats are implementation details. They do not become competing platform architectures.

The host control plane attaches a shared compatibility descriptor to capability outputs and emits a common EvidenceEnvelope when valid material provenance is available.

Representative PEG nodes:

```text
Artifact
Component
Class
Method
Field
BasicBlock
Value
String
NativeFunction
FrameworkFunction
DartLibrary
DartFunction
JNIBinding
Endpoint
HttpHeader
CryptoOperation
StorageKey
ProtocolMessage
RuntimeEvent
Trace
Finding
Evidence
```

Representative relations:

```text
CONTAINS
DECLARES
CALLS
XREFS
READS
WRITES
FLOWS_TO
DERIVED_FROM
RETURNS
JNI_BINDS
BUILDS_REQUEST
SENDS_TO
AUTHENTICATES_WITH
ENCODES_WITH
ENCRYPTS_WITH
OBSERVED_CALL
OBSERVED_VALUE
CONFIRMS
CONTRADICTS
```

Evidence states remain strictly:

```text
observed
  direct bytecode / binary / IR / runtime fact

derived
  deterministic analyzer inference

hypothesized
  agent or heuristic interpretation requiring verification
```

The platform does not manufacture numeric confidence values.

### 9. XREF is not data flow

CALLS/XREFS adjacency must never be presented as proof that a value flowed between methods. `trace_value`, taint/slicing, and runtime confirmation are separate later capabilities that add `FLOWS_TO`, `READS`, and `WRITES` evidence.

### 10. Static and dynamic analysis form a feedback loop

Dynamic analysis is a separate explicit opt-in capability and trust boundary.

```text
static evidence
      ↓
unresolved hypothesis
      ↓
targeted runtime observation
      ↓
CONFIRMS / CONTRADICTS
      ↓
updated evidence graph
```

Dynamic privileges must never leak into static workers.

### 11. Security findings require independent verification

Long-term agent topology separates investigation from verification:

```text
Planner
Investigator
Critic
Verifier
Reporter
```

Finding lifecycle:

```text
candidate → probable → verified / refuted / unknown
```

A rule hit or LLM hypothesis is not a verified vulnerability.

### 12. Optimize for useful answers, not installed-tool count

Success is measured by routing accuracy, endpoint recall/precision, data-flow precision, finding precision, runtime confirmation rate, evidence completeness, analysis latency, peak memory, and context/token cost per verified finding.

## Stable platform architecture introduced by 0.3.0

### Host control plane

The public MCP process runs on the host because it must be the only component allowed to invoke Docker/Podman. The control plane itself does not parse untrusted application code.

Shared modules include:

```text
safe_reverser/
├── contracts.py       Capability SPI / sandbox / evidence contracts
├── registry.py        capability manifest registry
├── runtime.py         Docker/Podman Runtime Driver
├── paths.py           host path and metadata safety primitives
├── jobs.py            shared analysis job lifecycle
├── worker.py          generic MCP worker adapter
├── evidence.py        shared result/evidence normalization
├── flutter.py         framework-specific adapter only
└── control_plane.py   single public MCP router/dispatcher
```

This is intended to remain the orchestration model through 1.0.

### Isolated workers

`static-core` contains APK/DEX/JVM/resource analysis and fast native triage.

`framework-flutter` contains Flutter artifact extraction, local runtime identification, Blutter-based Dart AOT analysis, semantic indexing, Dart XREF/native mapping, and Flutter network/auth/crypto reconstruction.

Future workers add capability implementations without duplicating the control plane.

### Runtime-cache ownership

A worker may derive a registry-independent runtime identity and cache key. The host control plane maps that key to an image repository and verifies the exact OCI labels before execution.

Workers must not decide registry/repository policy.

The Flutter exact runtime cache currently binds:

```text
cache schema
Dart version
snapshot hash
architecture
compressed-pointers mode
Blutter commit
Capability API
Worker ABI
```

A contract/cache schema change creates a new immutable identity rather than silently reusing an incompatible runtime image.

## Current development focus: 0.3.0

0.3.0 is not merely a Flutter feature release. It is the **platform foundation + first external framework capability** release.

Already merged into master before the final control-plane slice:

- framework-aware router foundation;
- PEG schema v2;
- bounded Flutter artifact/runtime inspection;
- pinned offline-safe Blutter profile;
- Flutter Dart AOT semantic index;
- Flutter network/auth/crypto evidence reconstruction.

The final 0.3.0 slice establishes:

- single host MCP control plane;
- Capability SPI v1;
- Worker ABI v1;
- manifest-driven capability registry;
- shared Runtime Driver;
- shared host path/artifact safety primitives;
- shared AnalysisJobStore;
- shared result/EvidenceEnvelope contract;
- static-core as an isolated capability worker;
- framework-flutter as the first external capability module;
- modular CI boundaries.

0.3.0 cannot be released until the architecture/security review and pre-PR CI gate pass.

## Strategic priorities after 0.3.0

Later milestones extend the same architecture:

1. **0.4 Data-flow intelligence** — `trace_value`, sources/sinks/sanitizers, auth/signing/crypto flow; emits shared PEG evidence.
2. **0.5 Security intelligence** — machine-readable vulnerability knowledge and independent verification; consumes shared PEG.
3. **0.6 Dynamic correlation** — separate opt-in dynamic capability; same control plane/evidence model.
4. **0.7 Native/JNI** — native capability, JNI mapping, native CFG/IR; same Runtime Driver/SPI.
5. **0.8 Framework coverage** — Hermes/React Native, IL2CPP, .NET; capability modules only.
6. **0.9 Pattern discovery and verifier maturity** — graph motifs, hypothesis generation, regression-backed rule synthesis.
7. **1.0 Contract stability** — compatibility guarantees, operational hardening, supported capability matrix.

No milestone is planned to replace the single-control-plane/capability architecture established in 0.3.0.

## Non-goals / guardrails

The project must not:

- expose generic `shell`, `exec`, Docker/Podman operations, raw Rizin/Ghidra consoles, or unrestricted Frida JavaScript to the agent;
- create one public MCP server per framework;
- duplicate Docker/Podman/job/path lifecycle logic inside each framework adapter;
- make the default static worker privileged or network-enabled;
- mount a container-runtime socket inside an analyzer worker;
- let a worker download/build missing analyzer dependencies during normal offline analysis;
- use JADX as the universal analyzer for every Android package;
- treat XREF adjacency as data flow;
- treat a regex/rule hit as a verified vulnerability;
- let an LLM invent unsupported confidence values or evidence;
- grow one giant privileged image solely to maximize bundled tools.

## Documentation rule

When a substantial architectural, security, product, or process decision changes, update all applicable durable sources in the same change:

1. `docs/PROJECT_DIRECTION.md` — canonical product/architecture direction;
2. `docs/ROADMAP.md` — priorities, implementation state, phases, acceptance;
3. `README.md` — concise current status;
4. `docs/CAPABILITY_SPI.md` or relevant design/research docs for contract changes.

## Decision log

### 2026-08-22 — Single host control plane + Capability SPI v1

**Decision:** Replace the experimental dual-public-MCP Flutter orchestration with one host-side `safe-android-reverser` control plane and versioned capability modules.

**Reason:** A public MCP per framework would force the agent to become the capability orchestrator and would duplicate runtime, path, job, image, and evidence machinery across Flutter, Hermes, native, IL2CPP, and dynamic analysis.

**Consequence:** Capability SPI v1, Worker ABI v1, Runtime Driver, AnalysisJobStore, path safety, and evidence contracts become shared platform foundations. Flutter is the first external capability rather than a special-case architecture.

### 2026-08-22 — Runtime readiness belongs to the host control plane

**Decision:** Framework routing declares `primary_capability_id` but does not claim worker readiness.

**Reason:** Image installation, runtime availability, and cache readiness are deployment facts, not package fingerprint facts.

**Consequence:** `fingerprint`/`route_analysis` topology is enriched by the host control plane with actual `ready/degraded/unavailable` state.

### 2026-08-22 — Worker runtime identity is registry-independent

**Decision:** Analyzer workers return runtime/cache identity only. Repository/image selection is host-owned.

**Reason:** Registry policy is a deployment/control-plane concern and must not be embedded in untrusted-input analyzer workers.

**Consequence:** The Flutter worker returns `cache_tag`; the host derives and verifies the exact immutable runtime image.

### 2026-08-22 — No intentionally temporary roadmap mechanisms

**Decision:** Milestones after 0.3.0 extend stable contracts rather than knowingly replacing the previous milestone's orchestration/evidence mechanism.

**Reason:** Framework and analyzer growth must not cause repeated platform rewrites.

**Consequence:** A breaking Capability SPI/Worker ABI/Runtime/Analysis/Evidence change requires an explicit architecture decision, migration path, compatibility tests, and senior review.

### 2026-08-21 — Promote framework-aware routing and Flutter AOT analysis

**Decision:** Move framework routing and Flutter AOT-aware analysis into the immediate development track.

**Reason:** Real Flutter analysis showed that detecting Flutter without changing analyzer strategy leaves most business logic inaccessible because Dart release code resides in AOT-compiled `libapp.so`.

**Consequence:** Implement a dedicated Flutter capability, normalize Dart evidence, and reserve generic native analysis for deeper localized investigation.

### 2026-08-21 — Repository documentation is durable project memory

**Decision:** Keep project direction explicit and versioned in repository documentation.

**Reason:** Architectural intent must survive individual chats, agents, and maintainers.

**Consequence:** Project direction, roadmap, README, and contract/design docs must be updated when major decisions change.
