# Safe Android Reverser Roadmap

## Vision

Safe Android Reverser is an **AI-native Android security and program-understanding platform**. The agent asks semantic questions; one host MCP control plane routes work to isolated capability workers; workers return bounded, provenance-carrying evidence.

Core invariants:

> **The agent reasons. The MCP control plane controls. Capability workers execute.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

The long-term architecture is defined in [`PROJECT_DIRECTION.md`](PROJECT_DIRECTION.md), Capability SPI in [`CAPABILITY_SPI.md`](CAPABILITY_SPI.md), and engineering process in [`DEVELOPMENT.md`](DEVELOPMENT.md).

---

# Release train

```text
0.3.0  Platform Foundation + Flutter AOT
0.4.0  Data-flow Intelligence
0.5.0  Security Intelligence
0.6.0  Dynamic Correlation
0.7.0  Native/JNI Intelligence
0.8.0  Framework Coverage
0.9.0  Pattern Discovery + Independent Verification
1.0.0  Stable Platform Contracts
```

From 0.3 onward, milestones extend the same control-plane/capability/runtime/job/evidence architecture. A milestone must not intentionally ship a mechanism already expected to be replaced in the next milestone.

Breaking platform contract changes require an explicit architecture decision, migration path, compatibility tests, documentation, and senior review.

---

# 0.3.0 — Platform Foundation + Flutter AOT

**Priority:** P0 / active integration and acceptance

0.3 is the architecture-foundation release. Flutter is the first external framework capability proving that new analyzers can be added without creating another public MCP or duplicating generic orchestration.

## Already merged into `master`

- [x] framework-aware routing foundation;
- [x] PEG schema v2 foundation;
- [x] bounded Flutter artifact/runtime inspection;
- [x] pinned offline-safe Blutter profile;
- [x] Flutter Dart AOT semantic index;
- [x] `find_dart_symbols`;
- [x] `find_dart_strings`;
- [x] `find_dart_xrefs`;
- [x] `map_dart_to_native`;
- [x] bounded Flutter network/auth/signing/crypto reconstruction.

## Final 0.3 platform branch

The 0.3 integration branch now contains:

- [x] exactly one public host-side MCP control plane;
- [x] Capability API v1;
- [x] Worker ABI v1;
- [x] EvidenceEnvelope v1 compatibility layer;
- [x] manifest-driven operation ownership;
- [x] generic control-plane dispatch through capability adapters;
- [x] `required` / `optional` / `opt-in` activation semantics;
- [x] `dynamic-opt-in` trust contract reserved for future dynamic analysis;
- [x] explicit `SAFE_REVERSER_ENABLE_CAPABILITIES` opt-in gate;
- [x] shared Docker/Podman Runtime Driver;
- [x] immutable image-ID execution after OCI provenance verification;
- [x] shared Path SDK and metadata safety primitives;
- [x] shared bounded `AnalysisJobStore`;
- [x] static-core converted to an isolated capability worker;
- [x] framework-flutter behind the same public control plane;
- [x] Flutter worker removed from deployment/registry ownership;
- [x] exact Flutter runtime cache bound to cache schema + Capability API + Worker ABI + Dart/snapshot/arch/OS/compressed-pointers + Blutter commit;
- [x] cross-worker ABI/cache regression tests;
- [x] shared route-readiness enrichment;
- [x] modular static/Flutter/control-plane CI;
- [x] architecture release consistency gate;
- [x] durable project/development rules in repository docs.

## Remaining acceptance gate

- [ ] final dead-reference/code sweep on exact branch head;
- [ ] exact-head GitHub Actions green;
- [ ] inspect exact-head Action logs for any failure, not an older green commit;
- [ ] final architecture/security review `PASS`;
- [ ] senior milestone acceptance;
- [ ] merge 0.3 platform PR;
- [ ] release-version/documentation commit;
- [ ] verify at least one controlled exact Flutter runtime-cache build for production release;
- [ ] release CI;
- [ ] publish `safe-v0.3.0` only from the exact tested release commit.

## 0.3 architecture

```text
AI agent
   |
   v
safe-android-reverser MCP
host control plane
   |
   +-- Capability Registry
   +-- Adapter Registry/factory
   +-- Runtime Driver
   +-- Path SDK
   +-- AnalysisJobStore
   +-- Evidence / PEG contracts
   |
   +-- static-core worker
   +-- framework-flutter worker
```

There is one public MCP. Frameworks are capability modules, not public orchestration servers.

## 0.3 capability boundary

### static-core

Owns generic Android package/DEX/JVM/resource analysis, generic routing preflight, and fast native triage.

It must not become the deep semantic implementation for Dart, Hermes, IL2CPP, .NET, or other external frameworks.

### framework-flutter

Owns Dart AOT/Flutter-specific analysis:

```text
analyze_flutter_aot
find_dart_symbols
find_dart_strings
find_dart_xrefs
map_dart_to_native
extract_flutter_network_model
list_flutter_jobs
```

### Future capabilities

New framework/native/security/dynamic modules extend Capability SPI. Central architecture CI validates invariants and required release baselines, not a forever-exact set of capability IDs.

## 0.3 acceptance criteria

### Architecture

- one public MCP control plane;
- no framework-specific public MCP;
- Docker/Podman lifecycle only in shared Runtime Driver;
- no runtime socket mounted into workers;
- capability manifests define operation ownership, activation, adapter, protocol, trust boundary, image role, and sandbox policy;
- duplicate public operations rejected;
- generic dispatch does not branch on framework/operation names;
- static-core and Flutter workers publish compatible Capability API/Worker ABI labels;
- adding a compatible optional capability does not require weakening/replacing generic runtime/job/path/evidence architecture;
- central gates validate invariants/baseline requirements rather than exact forever capability membership.

### Security

- static/framework workers use `network=none`;
- root filesystem read-only;
- Linux capabilities dropped;
- `no-new-privileges`;
- non-root execution;
- bounded CPU, memory, PIDs, tmpfs, archive entries, filesystem scans, generated files, and returned output;
- no arbitrary shell/exec MCP;
- no analyzer/runtime build/download during normal offline analysis;
- path traversal/symlink/archive-bomb/job-scan defenses have regression tests;
- worker/runtime images are provenance checked and executed by immutable image ID;
- `network=controlled` is not executable by the 0.3 static Runtime Driver;
- future dynamic privileges require explicit opt-in.

### Flutter

- bounded APK/XAPK/APKS/APKM preparation;
- exact `arm64-v8a` `libapp.so` + `libflutter.so` handling;
- deterministic local Dart/runtime/snapshot identity;
- runtime cache miss explicit and never invokes in-sandbox builder;
- semantic index persistent and bounded;
- Dart symbols/strings/XREF/native mappings and network/auth/crypto evidence queryable;
- XREF evidence never represented as true data flow;
- worker returns runtime/cache identity, not registry policy;
- host selects/verifies immutable runtime image.

### Evidence

- optimized analyzer indexes remain private implementation details;
- public capability outputs receive stable `safe_reverser_contract` metadata;
- valid material provenance receives common EvidenceEnvelope;
- evidence state remains `observed`, `derived`, or `hypothesized`;
- no invented numeric confidence.

### CI/release

- static worker CI green;
- Flutter worker CI green;
- control-plane contract/integration CI green;
- exact release-consistency gate green;
- exact-head means the exact reviewed/merged commit;
- senior architecture/security milestone review passes;
- required release images are published immutably from the exact tested release commit.

---

# 0.4.0 — Data-flow Intelligence

**Priority:** P0 immediately after 0.3 acceptance

0.4 adds true value/data-flow semantics **without changing the 0.3 orchestration model**.

## Objectives

Move from:

```text
symbol / XREF / call adjacency
```

toward:

```text
source -> transformation -> field/argument/return -> sanitizer -> sink
```

Planned semantic operations:

```text
trace_value
taint_query
find_source_to_sink
find_untrusted_input_paths
trace_constant
trace_field_usage
trace_storage
trace_header_generation
find_auth_flow
find_signing_logic
trace_crypto
```

Candidate backends:

- SootUp / Jimple;
- FlowDroid-family analysis;
- bounded custom DEX slicing/tracing;
- framework-specific IR/data-flow producers;
- later native/framework cross-boundary flow producers.

## Design rule

Do not run expensive whole-app taint analysis by default. Existing symbol/XREF/network models should localize a small subgraph first, then data-flow analysis escalates only where needed.

## 0.4 acceptance

- CALLS/XREFS remain distinct from `FLOWS_TO`;
- sources, sinks, transformations, sanitizers, reads, writes, parameters, returns are explicit;
- auth/token/header/signature paths can cross methods when supported;
- reflection/native/framework gaps are reported rather than guessed;
- evidence uses existing EvidenceEnvelope/PEG contracts;
- no new public MCP, job store, runtime wrapper, or evidence architecture;
- resource budgets and partial/unsupported states are explicit.

---

# 0.5.0 — Security Intelligence

**Priority:** P1

Build a machine-readable security knowledge/verification layer over 0.3/0.4 evidence.

Candidate sources/backends:

```text
Semgrep
mobsfscan
OWASP MASVS
OWASP MASWE
OWASP MASTG
project source/sink/sanitizer registry
```

Planned operations:

```text
scan_security
explain_finding
verify_finding
coverage_report
```

Finding lifecycle:

```text
candidate
   ↓
probable
   ↓
verified / refuted / unknown
```

A rule hit is evidence for review, not automatically a verified vulnerability.

## 0.5 acceptance

- findings retain rule/version, weakness mapping, source locations, analyzer provenance, evidence state, limitations, and flow evidence when available;
- Investigator and Verifier are logically independent;
- security capabilities consume shared PEG/evidence instead of introducing new result architecture;
- false-positive regression corpus exists for promoted rules.

---

# 0.6.0 — Dynamic Correlation

**Priority:** P2

Dynamic analysis is an explicit **opt-in capability** behind the same host control plane.

The contract already exists in 0.3:

```text
trust_boundary = dynamic-opt-in
activation = opt-in
sandbox.network = controlled
SAFE_REVERSER_ENABLE_CAPABILITIES=<explicit id>
```

The 0.3 static Runtime Driver intentionally refuses `controlled`; 0.6 supplies the privileged implementation without changing Capability SPI.

Candidate components:

```text
ADB
approved emulator/device
Frida
Objection where useful
mitmproxy / controlled TLS observation
reFlutter where appropriate
```

Prefer semantic operations:

```text
list_devices
observe_runtime
observe_network
observe_crypto
observe_storage
observe_webview
observe_jni
trace_runtime_method
collect_runtime_coverage
correlate_runtime
```

Avoid unrestricted `run_frida_script(script)` as the primary interface.

Target loop:

```text
static hypothesis
      ↓
targeted runtime observation
      ↓
OBSERVED_* evidence
      ↓
CONFIRMS / CONTRADICTS
      ↓
shared PEG
```

## 0.6 acceptance

- explicit user opt-in;
- separate dynamic trust/runtime boundary;
- static workers remain offline and unprivileged;
- device/network scope is constrained and auditable;
- secret/value redaction controls;
- runtime observations reuse shared analysis/evidence IDs and PEG contracts.

---

# 0.7.0 — Native/JNI Intelligence

**Priority:** P1/P2

Add generic native/JNI analysis as capability modules behind the existing Runtime Driver.

Current fast triage substrate:

```text
file
strings
readelf
objdump
nm
```

Planned semantic operations:

```text
inspect_elf
list_sections
list_imports
list_exports
list_symbols
search_native_strings
find_jni_exports
find_native_xrefs
disassemble_function
analyze_native_function
find_native_callers
find_native_callees
inspect_jni
```

Candidate backends:

- Rizin for scriptable/headless CFG/XREF/disassembly;
- Ghidra headless for difficult ARM/ARM64, P-code/IR, JNI, crypto, or escalation.

No generic Rizin/Ghidra console is exposed to the agent.

Target PEG bridge:

```text
Java/Kotlin method
      ↓ JNI_BINDS
native function
      ↓
native CFG/data flow
```

## 0.7 acceptance

- generic native capability reuses 0.3 runtime/job/path/evidence contracts;
- JNI mappings carry provenance in both managed/native representations;
- framework-aware analyzers remain primary when they preserve higher-level semantics;
- native escalation can consume localized offsets/symbols from Flutter/other framework capabilities.

---

# 0.8.0 — Framework Coverage

**Priority:** P2

New frameworks are capability modules using the 0.3 SPI.

## React Native / Hermes

```text
inspect_react_native
decompile_hermes
build_hermes_index
find_js_symbols
extract_js_endpoints
```

Hermes must not be inferred from React Native alone.

## Unity / IL2CPP

```text
inspect_unity
recover_il2cpp_metadata
map_il2cpp_methods
search_unity_symbols
```

## Xamarin / .NET MAUI

Use managed assembly/IL-aware analysis rather than relying on Android host-shell JADX output.

## Protocol adapters

Specialized evidence producers may cover:

```text
protobuf / gRPC
GraphQL
WebSocket
Socket.IO
SSE
MQTT
custom DNS / DoH
```

## 0.8 acceptance

Adding a module must not require:

- another public MCP;
- another generic Docker/Podman wrapper;
- duplicated job/path/evidence lifecycle;
- a new evidence-state model;
- operation-name-specific dispatch branches in the control plane;
- weakening static sandbox policy.

---

# 0.9.0 — Pattern Discovery + Independent Verification

**Priority:** P3

Use graph/data-flow motifs and anomaly ranking to propose candidate weaknesses, then verify deterministically.

```text
known security knowledge
        ↓
PEG behavior motifs
        ↓
anomaly / unusual-flow ranking
        ↓
AI hypothesis
        ↓
reachability + data-flow + sanitizer verification
        ↓
targeted dynamic confirmation where needed
        ↓
validated candidate
        ↓
rule synthesis + regression corpus
```

Planned operations:

```text
mine_patterns
propose_rule
validate_rule
regression_test_rule
```

AI may propose rules. Production promotion requires deterministic positive/negative regression gates.

---

# 1.0.0 — Stable Platform Contracts

1.0 focuses on compatibility, operational hardening, reproducibility, and evidence quality rather than another orchestration rewrite.

Target guarantees:

- one public MCP control plane;
- documented Capability API/Worker ABI compatibility policy;
- public semantic-operation input/output schema compatibility policy;
- supported capability/artifact/framework/runtime matrix;
- reproducible image provenance and SBOM;
- bounded resource behavior;
- durable analysis/evidence identifiers;
- regression suites across framework/runtime versions;
- architecture/security release gate;
- migration policy for future contract changes.

Operation-name equality alone is not sufficient for 1.0 compatibility. Before 1.0, externally meaningful operation schemas must be versioned or otherwise compatibility-checked.

---

# Cross-cutting static Android improvements

Static Android fidelity evolves continuously behind `static-core` without changing the control-plane architecture.

Candidate additions:

```text
Apktool
aapt2
apksigner / apksig
smali / baksmali
APKiD subject to packaging/license review
```

Candidate semantic operations:

```text
inspect_manifest
inspect_resources
inspect_signature
list_components
list_permissions
find_exported_components
inspect_deep_links
inspect_network_security_config
list_dex
inspect_dex
search_smali
read_smali
```

These remain generic Android/package/DEX semantics. Framework-specific business logic remains in dedicated capabilities.

---

# Development sequencing after 0.3

Once 0.3 receives milestone acceptance:

```text
freeze orchestration unless a demonstrated platform defect requires change
        ↓
start 0.4 data-flow spike behind existing Capability SPI
        ↓
small feature slices
        ↓
review + deterministic tests after each slice
        ↓
merge only exact-head green work
```

The main measure of progress from 0.4 onward should be **analysis intelligence and evidence quality**, not additional control-plane refactoring.
