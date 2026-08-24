# Project Direction

This document is the canonical long-term product and architecture direction for Safe Android Reverser MCP. Significant architecture, security, analyzer-routing, trust-boundary, compatibility, or product-priority decisions must be recorded here.

Engineering process rules live in [`DEVELOPMENT.md`](DEVELOPMENT.md). Capability/worker contracts live in [`CAPABILITY_SPI.md`](CAPABILITY_SPI.md).

## Product vision

Safe Android Reverser is an **AI-native Android security and program-understanding platform**, not a collection of reverse-engineering CLI wrappers.

The durable product model is:

> **The agent reasons. The MCP control plane controls. Capability workers execute.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

The stable platform abstractions are:

- one public MCP control plane;
- framework-aware representation routing;
- versioned Capability SPI and Worker ABI;
- manifest-defined operation ownership;
- host adapter registry;
- isolated capability workers;
- shared Runtime Driver, Path SDK, AnalysisJobStore, and Evidence contract;
- Program Evidence Graph (PEG) semantics;
- deterministic provenance and immutable image execution;
- independent verification of agent hypotheses;
- explicit trust boundaries and activation semantics.

Underlying analyzers such as JADX, Androguard, Blutter, Rizin, Ghidra, Frida, FlowDroid, Semgrep, Apktool, or later replacements are implementation details and evidence producers.

## Stable topology

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

There is exactly **one public MCP server**. A new analyzer/framework is not allowed to create a parallel public orchestration plane.

Only the host control plane may invoke Docker/Podman. Workers never receive a Docker/Podman socket.

## Core architecture principles

### 1. Framework/representation first

Do not assume APK means Java/Kotlin.

```text
artifact
   ↓
fingerprint / framework router
   ├─ Native Android      → static-core / DEX / Java / Kotlin
   ├─ Flutter             → framework-flutter / Dart AOT / libapp.so
   ├─ React Native/Hermes → Hermes/JS representation when positively detected
   ├─ Unity IL2CPP        → IL2CPP metadata + native representation
   └─ Xamarin/.NET MAUI   → managed assemblies / IL
```

Routing declares topology and representation. Runtime readiness is a separate deployment fact discovered by the host control plane.

A missing framework capability never silently authorizes JADX as the primary business-logic analyzer.

### 2. Capability SPI is the extension mechanism

0.3.0 establishes Capability API v1 and Worker ABI v1.

A manifest defines:

```text
id
capability_api
worker_abi
representations
trust_boundary
activation
adapter
protocol
image repository/role
public operations
sandbox policy
```

The registry rejects incompatible versions, malformed manifests, reserved public operation names, and duplicate operation ownership.

Adding a compatible capability must not require changing generic dispatch, generic health aggregation, shared runtime/path/job/evidence ownership, or public MCP topology.

### 3. Adapter and protocol are separate contracts

`adapter` describes host-side orchestration. `protocol` describes communication with the worker.

Current adapter kinds prove two models:

```text
mcp-container  -> generic MCP-over-stdio worker
flutter-aot    -> framework-specific exact-runtime orchestration + CLI JSON worker
```

Future adapter kinds must register behind the adapter factory/registry. They must not add framework/operation switches to `ControlPlane.call()`, `health()`, or public dispatch.

### 4. Activation is a privilege/readiness contract

```text
required  -> release health depends on capability readiness
optional  -> active when present; failure does not invalidate required platform health
opt-in    -> declared but inactive until explicitly enabled
```

`dynamic-opt-in` capabilities must use `activation=opt-in` and explicit enablement through `SAFE_REVERSER_ENABLE_CAPABILITIES`.

Static Runtime Driver code deliberately refuses `network=controlled`. Dynamic support later extends the Runtime Driver implementation behind the already-defined SPI rather than replacing the SPI.

### 5. Static-core has a bounded responsibility

`static-core` owns generic Android package/DEX/JVM/resource triage and semantics plus generic framework-routing preflight.

It must not grow deep Dart, Hermes, IL2CPP, .NET, or other framework semantics merely because those artifacts are carried by APK files.

Framework-specific business-logic analysis belongs to dedicated capability modules.

This prevents `static-core` from becoming a monolithic universal analyzer as framework coverage grows.

### 6. Generic native analysis is a substrate

Native ELF/JNI analysis is a shared substrate, not a universal framework analyzer.

For Flutter, first recover Dart semantics and native mappings; escalate only the relevant native neighborhood when necessary. Apply the same representation-first rule to Hermes, IL2CPP, and managed runtimes.

### 7. Decompilation is not canonical truth

JADX/Vineflower source is useful for explanation and localization. Important facts should retain provenance to DEX, IR, native addresses, framework metadata, analyzer output, or runtime observation wherever possible.

### 8. PEG and EvidenceEnvelope are the semantic integration layer

Capability implementations may maintain optimized private indexes:

```text
DEX SQLite
Flutter SQLite
future data-flow IR
Ghidra/Rizin caches
Hermes indexes
IL2CPP indexes
```

These are implementation details, not competing platform architectures.

Public material results are normalized through the shared compatibility/evidence contract. Evidence states remain:

```text
observed
  directly observable artifact/IR/runtime fact

derived
  deterministic analyzer inference

hypothesized
  heuristic/agent interpretation requiring verification
```

The platform does not manufacture numeric confidence values.

### 9. XREF/CALLS are not data flow

CALLS/XREFS adjacency must never be presented as proof that a value moved between methods/functions.

True data-flow capability adds explicit source/sink/transformation/sanitizer and `FLOWS_TO`/`READS`/`WRITES` evidence in 0.4 and later.

### 10. Static and dynamic analysis form a controlled feedback loop

```text
static evidence
      ↓
unresolved hypothesis
      ↓
explicit opt-in targeted runtime observation
      ↓
CONFIRMS / CONTRADICTS
      ↓
shared evidence graph
```

Dynamic device/network privileges never leak into static workers.

### 11. Security findings require verification

Long-term investigation separates proposal from verification:

```text
Planner -> Investigator -> Critic -> Verifier -> Reporter
```

Finding lifecycle:

```text
candidate -> probable -> verified / refuted / unknown
```

A regex/rule hit, XREF, or LLM interpretation is never automatically a verified vulnerability.

### 12. Optimize for useful evidence, not tool count

Success is measured by routing accuracy, semantic coverage, endpoint recall/precision, data-flow precision, finding precision, runtime confirmation rate, provenance completeness, resource bounds, latency, and context cost per verified answer.

A larger image or larger raw analyzer surface is not a goal by itself.

## Security architecture

Static/framework/native-static capabilities preserve:

```text
network=none
read-only root filesystem
cap-drop=ALL
no-new-privileges
non-root UID/GID
bounded CPU / memory / PIDs / tmpfs
explicit mounts
bounded stdout/stderr
bounded file/archive/job traversal
```

The analyzer sandbox must not download/build missing analyzer/runtime dependencies during normal analysis.

The host verifies required OCI labels and executes the verified immutable image ID instead of re-running a mutable tag.

Filesystem handling rejects lexical escape, resolved escape, symlink substitution, unsafe metadata/deletion targets, and oversized metadata. Stronger dirfd/openat/openat2-style race resistance may be added later if the same-UID hostile-process threat model becomes in scope; that hardening does not change the capability architecture.

## Stable platform modules introduced by 0.3.0

```text
safe_reverser/
├── contracts.py       Capability SPI / sandbox / evidence contracts
├── registry.py        capability manifest + operation ownership
├── adapters.py        adapter factory/registry boundary
├── runtime.py         Docker/Podman Runtime Driver
├── paths.py           shared host path/metadata policy
├── jobs.py            shared bounded analysis jobs
├── worker.py          generic MCP worker transport
├── evidence.py        common result/evidence normalization
├── flutter.py         Flutter-specific orchestration only
└── control_plane.py   one public MCP dispatcher
```

This is intended to remain the orchestration model through 1.0.

## Runtime-cache ownership

Workers may derive registry-independent runtime/cache identity. Repository and image selection remain host-owned.

Flutter exact runtime-cache identity binds:

```text
cache schema
Capability API
Worker ABI
Dart version
snapshot hash
architecture
OS
compressed-pointer mode
Blutter commit
```

The host maps that identity to a repository, verifies provenance labels, resolves an immutable image ID, and executes the immutable ID.

A cache/ABI change creates a new identity rather than silently reusing incompatible runtime code.

Starting in 0.4 Stage A, cache misses are resolved through a durable host service rather than analyzer-specific orchestration:

```text
Flutter capability
       |
       v
RuntimeCacheResolver
       |-- lookup / exact verification / immutable image selection
       |-- bounded private persistence / restart reconciliation / deduplication
       `-- ControlledBuildProvider
              |-- GitHub Actions provider
              |-- future Jenkins or enterprise provider
              `-- future self-hosted or prebuilt provider
```

GitHub Actions is one transport implementation, not the architecture. Public analysis responses may report only semantic cache state (`READY`, `BUILD_REQUIRED`, `BUILDING`, `FAILED`); workflow names, run IDs, HTTP endpoints, credentials, and provider-specific status values remain behind the provider boundary.

The private Flutter runtime-cache schema moves from 2 to 3 to bind the OS as a verifiable OCI label. Schema-2 images are not mutated. Compatible identities are rebuilt under schema 3, whose changed digest prevents silent reuse. Capability API 1 and Worker ABI 1 are unchanged.

Host modules added by Stage A are durable platform services:

```text
safe_reverser/runtime_cache.py     exact identity, state, persistence, resolver
safe_reverser/controlled_build.py  provider contract and provider implementations
```

## Compatibility direction

Current independently versioned contracts:

```text
Capability API       1
Worker ABI           1
EvidenceEnvelope     1
PEG schema           2
Flutter cache schema 3
```

A breaking contract change requires:

1. decision entry here;
2. migration/compatibility design;
3. explicit version increment;
4. compatibility/regression tests;
5. documentation/update impact;
6. senior architecture/security review.

Before 1.0, public semantic operations must gain a documented schema compatibility policy for input schemas and externally meaningful output fields. Matching only operation names is not considered sufficient for a long-lived plugin ecosystem.

## CI as architecture enforcement

CI must enforce architecture **invariants**, not encode the forever-complete capability list.

A release may define a required baseline subset (for 0.3: `static-core` and `framework-flutter`), but adding another compatible optional capability must not fail merely because a central exact-set assertion was not edited.

CI should validate:

- one public MCP;
- manifest/operation ownership;
- Capability API/Worker ABI compatibility;
- sandbox/trust-boundary rules;
- immutable image/provenance execution;
- path/archive/job bounds;
- worker surface contracts;
- real image builds where appropriate;
- host control-plane integration;
- release consistency.

## Current development focus: 0.3.0

0.3.0 is **Platform Foundation + Flutter AOT**.

Merged before the final platform slice:

- framework-aware routing foundation;
- PEG schema v2;
- bounded Flutter artifact/runtime inspection;
- offline-safe pinned Blutter profile;
- Flutter Dart semantic index;
- Dart symbols/strings/XREF/native mapping;
- Flutter network/auth/signing/crypto reconstruction.

The final 0.3 branch adds:

- single host public MCP;
- Capability SPI v1 / Worker ABI v1;
- activation/trust/network contracts;
- manifest + adapter driven dispatch;
- shared Runtime Driver;
- shared Path SDK;
- shared AnalysisJobStore;
- shared EvidenceEnvelope compatibility layer;
- immutable image-ID execution;
- static-core and Flutter capability workers behind the same control plane;
- cross-worker ABI/cache consistency gates;
- modular architecture CI;
- durable development/release rules.

0.3 is accepted only after exact-head CI, architecture/security review, and senior milestone acceptance.

After acceptance, normal feature work moves to analysis intelligence rather than continuing orchestration refactoring without demonstrated need.

## Strategic roadmap

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

No milestone is planned to replace the single-control-plane/capability architecture established in 0.3.

## Non-goals / guardrails

The project must not:

- expose generic shell/exec or Docker/Podman operations to the agent;
- expose raw unrestricted analyzer consoles as the primary semantic API;
- create a public MCP per framework;
- duplicate generic Runtime Driver, path, job, health, or evidence infrastructure in framework adapters;
- make default static workers privileged or network-enabled;
- mount runtime sockets into analyzer workers;
- perform normal runtime analyzer downloads/builds inside untrusted analysis sandboxes;
- use JADX as a universal primary business-logic analyzer;
- let static-core absorb every framework's deep semantics;
- equate XREF/CALL adjacency with data flow;
- equate a rule hit with a verified vulnerability;
- let an LLM invent unsupported evidence/confidence;
- grow a giant privileged image simply to maximize installed-tool count;
- hard-code central CI to an exact forever list of all capabilities.

## Documentation rule

A durable architecture/security/process decision is incomplete until all applicable repository sources are updated in the same change:

1. `docs/PROJECT_DIRECTION.md` — architecture/product source of truth;
2. `docs/ROADMAP.md` — milestone scope/status/acceptance;
3. `docs/CAPABILITY_SPI.md` — platform extension contract;
4. `docs/DEVELOPMENT.md` — development/review/CI rules;
5. `docs/INSTALL_MCP.md` / `docs/RELEASING.md` — operational changes;
6. `README.md` — concise current status;
7. capability/skill docs — agent-facing behavior.

## Decision log

### 2026-08-22 — Capability platform is the long-term orchestration model

**Decision:** One host MCP control plane + manifest/adapter-driven capabilities is the platform model through 1.0.

**Reason:** Framework/analyzer growth must not cause repeated control-plane/runtime/job/evidence rewrites.

**Consequence:** Later milestones extend analysis intelligence behind Capability SPI/Worker ABI rather than creating parallel orchestration.

### 2026-08-22 — Activation and future dynamic trust semantics are defined in 0.3

**Decision:** `required`, `optional`, and `opt-in` are part of Capability SPI v1. `dynamic-opt-in` requires `opt-in`; network `controlled` is reserved but rejected by the static Runtime Driver.

**Reason:** 0.6 Dynamic should require a new privileged runtime implementation/adapter, not a new public architecture or SPI rewrite.

### 2026-08-22 — CI validates invariants, not an exact forever capability set

**Decision:** Architecture/release gates may require baseline release capabilities but must allow additional compatible capability manifests.

**Reason:** Exact-set assertions contradict the capability-extension model and create unnecessary central edits for every new module.

**Consequence:** Future native/Hermes/IL2CPP/security/dynamic modules can be integrated without weakening central architecture checks.

### 2026-08-22 — static-core boundary is generic Android/DEX/JVM triage and semantics

**Decision:** Deep external-framework semantics belong in framework capabilities; static-core may only provide generic detection/preflight needed for routing.

**Reason:** Prevent static-core from becoming a monolithic analyzer as framework coverage expands.

### 2026-08-22 — Immutable image ID is the execution identity

**Decision:** Verify requested image labels, resolve canonical image ID, then execute the immutable ID.

**Reason:** Close mutable-tag inspect/run TOCTOU and make long-lived control-plane behavior reproducible.

### 2026-08-22 — Runtime readiness belongs to the host control plane

**Decision:** Framework routing declares topology; the host discovers actual capability/runtime readiness.

**Reason:** Image/cache installation is a deployment fact, not an artifact fingerprint fact.

### 2026-08-22 — Worker runtime identity is registry-independent

**Decision:** Workers return runtime/cache identity; repository policy is host-owned.

**Reason:** Deployment registry policy must not live in analyzer workers processing untrusted artifacts.

### 2026-08-22 — No intentionally temporary roadmap mechanisms

**Decision:** A milestone must not knowingly introduce orchestration/evidence machinery expected to be replaced by the next milestone.

**Consequence:** Breaking platform contract changes require explicit decisions, migrations, tests, and senior review.

### 2026-08-21 — Promote framework-aware routing and Flutter AOT analysis

**Decision:** Route by the representation containing business logic and make Flutter AOT a first-class capability.

**Reason:** Real Flutter release applications place main Dart logic in AOT-compiled `libapp.so`; Java/Kotlin host-shell decompilation is insufficient.

### 2026-08-21 — Repository documentation is durable project memory

**Decision:** Architecture intent and development policy must live in versioned repository documentation rather than only chats/agent sessions.
