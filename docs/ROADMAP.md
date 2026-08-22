# Reverse Engineering Roadmap

## Vision

Safe Android Reverser is an **AI-native Android security and program-understanding platform**. It is built around semantic questions, deterministic evidence, framework-aware routing, isolated capability workers, and a shared evidence model—not around exposing a growing list of CLI tools.

Core principles:

> **The agent reasons. The MCP control plane controls. Capability workers execute.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

The canonical long-term architecture is documented in [`PROJECT_DIRECTION.md`](PROJECT_DIRECTION.md). The stable extension contract is defined in [`CAPABILITY_SPI.md`](CAPABILITY_SPI.md).

---

# Release train

```text
0.3.0  Platform Foundation + Flutter AOT
0.4.0  Data-flow Intelligence
0.5.0  Security Intelligence
0.6.0  Dynamic Correlation
0.7.0  Native/JNI Intelligence
0.8.0  Framework Coverage
0.9.0  Pattern Discovery + Verification
1.0.0  Stable Platform Contracts
```

From 0.3.0 onward, later milestones extend the same control-plane, capability, job, runtime, and evidence contracts. No roadmap milestone is intentionally designed as a temporary orchestration mechanism to be replaced by the next version.

Breaking Capability SPI / Worker ABI / Runtime Driver / Analysis Job / Evidence contract changes require an explicit architecture decision, migration path, compatibility tests, and senior review.

---

# 0.3.0 — Platform Foundation + Flutter AOT

**Priority: P0 / active**

0.3.0 is the architecture-foundation release. Flutter is the first external framework capability proving that the platform can add analyzers without creating a new orchestration architecture.

## Already merged into master

- [x] framework-aware routing foundation;
- [x] PEG schema v2 foundation;
- [x] bounded Flutter artifact/runtime inspector;
- [x] pinned offline-safe Blutter profile;
- [x] Flutter Dart AOT semantic index;
- [x] `find_dart_symbols`;
- [x] `find_dart_strings`;
- [x] `find_dart_xrefs`;
- [x] `map_dart_to_native`;
- [x] Flutter network/auth/signing/crypto evidence reconstruction.

## Final architecture slice — in progress

- [x] single host-side public MCP control plane;
- [x] Capability SPI v1 contract;
- [x] Worker ABI v1 contract;
- [x] manifest-driven capability registry;
- [x] shared Docker/Podman Runtime Driver;
- [x] shared host path/metadata safety primitives;
- [x] shared AnalysisJobStore;
- [x] static-core converted to an isolated worker behind the control plane;
- [x] framework-flutter converted to a capability module behind the same control plane;
- [x] worker-owned registry selection removed;
- [x] exact Flutter runtime cache bound to capability/worker/cache ABI;
- [x] shared result/EvidenceEnvelope compatibility contract;
- [x] modular CI split into static-worker, Flutter-worker, and control-plane integration gates;
- [ ] all pre-PR CI green on exact branch head;
- [ ] final architecture/security code review PASS;
- [ ] senior milestone acceptance;
- [ ] merge final 0.3.0 architecture PR;
- [ ] release-version/documentation commit;
- [ ] release CI;
- [ ] `safe-v0.3.0` tag.

## Public architecture

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
   +-- AnalysisJobStore
   +-- Evidence / PEG contracts
   |
   +-- static-core worker
   +-- framework-flutter worker
```

There is **one public MCP server**. Adding another framework must not create another public MCP control plane.

## Capability readiness model

Framework routing declares topology:

```text
primary_capability_id
primary representation
secondary capability routes
```

The host control plane independently discovers runtime state:

```text
declared
installed
ready
degraded
unavailable
unsupported
```

This prevents fingerprint logic from falsely claiming that an image/runtime is installed.

## 0.3.0 acceptance criteria

### Architecture

- one public MCP control plane;
- no worker has Docker/Podman socket access;
- Docker/Podman lifecycle exists only in the shared Runtime Driver;
- capability manifests define operation ownership and sandbox policy;
- duplicate public operation ownership is rejected;
- static-core and Flutter workers carry compatible Capability API / Worker ABI labels;
- later framework adapters can be added without duplicating generic runtime/job/path/evidence infrastructure.

### Security

- default static/framework workers use `network=none`;
- read-only root filesystem;
- dropped Linux capabilities;
- `no-new-privileges`;
- non-root execution;
- bounded CPU, memory, PIDs, tmpfs, generated files, archive entries, and output sizes;
- no arbitrary shell/exec MCP tool;
- no analyzer build/download during normal offline analysis;
- path traversal/symlink/archive-bomb defenses have regression tests;
- exact runtime images are provenance-checked before execution.

### Flutter capability

- APK/XAPK/APKS/APKM artifact preparation is bounded;
- `arm64-v8a` `libapp.so` + `libflutter.so` pair is extracted in worker isolation;
- exact Dart version/snapshot/cache identity is local and deterministic;
- runtime cache miss is explicit and never invokes an in-sandbox builder;
- semantic index is persistent and bounded;
- Dart symbols, strings, XREFs, native offsets, and network/auth/crypto evidence are queryable;
- XREF evidence is never represented as true data flow;
- worker returns cache identity, not registry/image policy;
- host chooses and verifies the exact immutable runtime image.

### Evidence

- optimized analyzer indexes remain private implementation details;
- all public capability results carry `safe_reverser_contract` metadata;
- material results with valid provenance receive a common EvidenceEnvelope;
- evidence states remain `observed`, `derived`, or `hypothesized`;
- no invented numeric confidence.

### CI/release

- static-worker CI green;
- Flutter-worker CI green;
- control-plane contract/integration CI green;
- exact release consistency gate green;
- at least one controlled exact-runtime cache build is verified before production 0.3.0 release;
- senior architecture/security milestone review PASS.

---

# 0.4.0 — Data-flow Intelligence

**Priority: P0/P1 after 0.3.0 acceptance**

0.4.0 adds true value/data-flow semantics **without replacing the 0.3 architecture**.

Planned operations:

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

Candidate backends may include:

```text
SootUp / Jimple
FlowDroid-family analysis
bounded custom DEX tracing
framework-specific IR/data-flow producers
```

Expensive whole-app taint analysis should not run by default. Existing symbol/XREF/network indexes localize the relevant subgraph first.

### 0.4 acceptance

- CALLS/XREFS remain distinct from FLOWS_TO;
- sources, sinks, transformations, and sanitizers are explicit;
- auth/token/header/signature paths can cross methods where supported;
- unsupported reflection/native/framework boundaries are reported rather than guessed;
- data-flow evidence uses the same EvidenceEnvelope/PEG contracts defined in 0.3;
- no new public MCP or parallel job/runtime architecture.

---

# 0.5.0 — Security Intelligence

**Priority: P1**

Add a machine-readable security knowledge layer over shared PEG/data-flow evidence.

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

A rule match is review evidence, not automatically a verified vulnerability.

### 0.5 acceptance

- each finding retains rule/version, weakness mapping, locations, analyzer provenance, evidence state, limitations, and flow evidence when applicable;
- Investigator and Verifier paths are logically independent;
- security engines consume the 0.3/0.4 evidence contracts rather than introducing a new result architecture.

---

# 0.6.0 — Dynamic Correlation

**Priority: P2**

Dynamic analysis is an explicit opt-in capability behind the same host control plane.

Candidate components:

```text
ADB
Android emulator / approved device
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

### 0.6 acceptance

- explicit user opt-in;
- separate dynamic trust boundary;
- device/network privileges never leak into static workers;
- secret/value redaction controls;
- runtime observations use the same analysis/evidence IDs and PEG contracts.

---

# 0.7.0 — Native/JNI Intelligence

**Priority: P1/P2**

Add native analysis as capability modules behind the existing Runtime Driver.

Current baseline already includes fast ELF triage tools:

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
- Ghidra headless as escalation for difficult ARM/ARM64, P-code/IR, JNI and crypto.

No generic Rizin/Ghidra console is exposed to the agent.

Target PEG mapping:

```text
Java/Kotlin method
      ↓ JNI_BINDS
native function
      ↓
native CFG / data flow
```

---

# 0.8.0 — Framework Coverage

**Priority: P2**

New frameworks are capability modules using the 0.3 SPI.

## React Native / Hermes

```text
inspect_react_native
decompile_hermes
build_hermes_index
find_js_symbols
extract_js_endpoints
```

Do not infer Hermes from React Native alone.

## Unity / IL2CPP

```text
inspect_unity
recover_il2cpp_metadata
map_il2cpp_methods
search_unity_symbols
```

## Xamarin / .NET MAUI

Add managed-assembly detection and IL-aware analysis rather than relying on JADX host code.

## Protocol adapters

Specialized evidence producers for:

```text
protobuf / gRPC
GraphQL
WebSocket
Socket.IO
SSE
MQTT
custom DNS / DoH
```

### 0.8 acceptance

Adding any one of these modules must not require:

- another public MCP server;
- another generic container-runtime wrapper;
- duplicated generic job/path/image lifecycle code;
- a new evidence architecture.

---

# 0.9.0 — Pattern Discovery + Verification

**Priority: P3**

Use graph/data-flow motifs and anomaly ranking to propose candidate weaknesses, then verify them deterministically.

Pipeline:

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

AI may propose rules; production promotion requires deterministic positive/negative regression gates.

---

# 1.0.0 — Stable Platform

1.0 focuses on compatibility, supported-capability matrices, operational hardening, reproducibility, and evidence quality rather than another orchestration rewrite.

Target guarantees:

- one public MCP control plane;
- documented Capability SPI / Worker ABI compatibility policy;
- clear worker support matrix by artifact/framework/runtime;
- reproducible image provenance/SBOM;
- bounded resource behavior;
- durable analysis/evidence identifiers;
- regression suites across framework/runtime versions;
- architecture/security release gate;
- migration policy for any future contract change.

---

# Cross-cutting strong Android static core

Static Android fidelity evolves continuously behind `static-core` without changing the control-plane architecture.

Planned additions:

```text
Apktool
aapt2
apksigner / apksig
smali / baksmali
APKiD packaging/license decision
```

Planned operations:

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
map_java_to_smali
```

Mutation/rebuild functionality, if later added, belongs in an explicit `patch-lab` capability rather than default static analysis.

---

# Program Evidence Graph

PEG is the cross-analyzer semantic layer.

Representative nodes:

```text
Artifact
APK
DexFile
NativeLibrary
AndroidComponent
Class
Method
Field
BasicBlock
Value
String
DartLibrary
DartFunction
NativeFunction
JNIBinding
Host
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

Representative edges:

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
IMPLEMENTS
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

Every material fact should preserve, when available:

```text
analysis_id
artifact/input SHA-256
capability id/API/worker ABI
analyzer name + version
image/build identity
configuration/schema version
source location or native offset
evidence state
limitations
```

---

# Tool integration policy

Before adding an analyzer or capability:

1. fit it behind an existing Capability SPI or explicitly review a contract extension;
2. pin the tool version or exact source revision;
3. verify provenance/hashes where redistribution permits;
4. review license compatibility;
5. prefer headless/scriptable operation;
6. expose bounded semantic operations, never arbitrary commands;
7. keep normal static/framework worker networking disabled;
8. add deterministic fixtures, unit tests, worker integration tests, and control-plane contract tests;
9. document resource limits and unsupported versions/architectures;
10. do not silently fall back to host-installed analyzers or build/download dependencies during analysis;
11. normalize material facts through the shared evidence contract;
12. update durable architecture/roadmap documentation.

---

# Testing and success metrics

Every capability needs:

```text
unit tests
worker contract tests
resource/security boundary tests
image provenance tests
end-to-end control-plane tests
regression fixtures across supported runtime/compiler versions
unsupported-version tests
```

Critical metrics:

```text
framework routing accuracy
capability readiness accuracy
first-party endpoint recall / precision
auth/signature reconstruction rate
call-edge precision
data-flow precision
security finding precision
runtime confirmation rate
native/framework mapping coverage
evidence completeness
analysis p50 / p95
peak memory / disk / process count
context/token cost per verified finding
regression rate across protected/obfuscated apps
```

---

# Current gate

Do **not** begin 0.4.0 until all 0.3.0 acceptance items are satisfied and the senior milestone review returns PASS.
