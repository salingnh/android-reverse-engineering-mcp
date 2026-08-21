# Reverse Engineering Roadmap

## Vision

Safe Android Reverser should become an **AI-native Android security and program-understanding platform**, not a container that merely accumulates reverse-engineering tools.

The target is an orchestration and evidence layer where an AI agent asks high-level questions, the MCP server selects the correct analyzer for the artifact representation, executes it inside an appropriate capability profile, normalizes the evidence, and returns bounded, reproducible facts for reasoning.

Core principles:

> **The agent reasons. The MCP server controls. The sandbox executes.**

> **Detect the framework first, then analyze the representation that actually contains the business logic.**

The canonical long-term direction and decision log live in [`PROJECT_DIRECTION.md`](PROJECT_DIRECTION.md).

---

## Current status — release 0.2.1

The current static-safe baseline already contains:

```text
Java 21
JADX 1.5.6
Vineflower 1.12.0
Androguard 4.1.4
file
binutils: strings / readelf / objdump / nm
Python MCP implementation
```

Current semantic MCP operations include:

```text
health
fingerprint
decompile
extract_api
search_source
read_source_file
recover_kotlin_names
list_jobs
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
```

Current strengths:

- APK/XAPK/APKS/APKM/JAR/AAR handling;
- framework fingerprinting;
- Java/Kotlin decompilation;
- Androguard-backed DEX semantic indexing;
- symbol localization and method XREFs;
- bounded CFG extraction;
- first-pass structured network modeling;
- basic ELF/native inventory;
- evidence provenance and bounded output;
- rootless/network-isolated static execution with no generic shell MCP surface.

Current gaps that materially block deeper analysis:

- framework-aware routing after fingerprinting;
- Flutter Dart AOT semantic recovery from `libapp.so`;
- true interprocedural value/data-flow tracing;
- richer Android manifest/resources/Smali analysis;
- deep native/JNI analysis;
- security knowledge/rule verification;
- React Native/Hermes, Unity/IL2CPP and managed-runtime analyzers;
- controlled dynamic instrumentation and static↔dynamic correlation.

---

# 1. Current development track — Framework Router + Flutter AOT

**Priority: P0 / active next development track**

A real Flutter application exposed an important architectural limitation: recognizing Flutter is not sufficient if the workflow then continues through Java/Kotlin-oriented analysis. In release Flutter apps, most Dart business logic is AOT-compiled into `libapp.so`; JADX therefore mainly exposes the Android host shell and plugins.

The platform must route analysis by framework:

```text
artifact
   ↓
fingerprint / framework router
   ├─ Native Android      → DEX / JADX / Androguard
   ├─ Flutter             → Dart AOT + libapp.so + Flutter assets
   ├─ React Native/Hermes → Hermes / JavaScript bytecode
   ├─ Unity IL2CPP        → metadata + native analysis
   └─ Xamarin/.NET MAUI   → managed assemblies
```

## 1.1 Flutter artifact inventory

Implement structural inspection for:

```text
lib/<abi>/libapp.so
lib/<abi>/libflutter.so
assets/flutter_assets/
AssetManifest*
FontManifest*
NOTICES*
package/config clues
Flutter/Dart snapshot/runtime metadata
```

Planned MCP operations:

```text
inspect_flutter
identify_dart_runtime
extract_flutter_assets
```

Acceptance criteria:

- identify all Flutter-related members across APK/XAPK splits;
- identify available ABI(s);
- locate the business-logic-bearing `libapp.so`;
- collect runtime/snapshot metadata sufficient to select an AOT analyzer;
- report explicit limitations when the runtime/version/ABI is unsupported.

## 1.2 Dart AOT-aware static analysis

Primary initial candidate: **Blutter**.

Blutter is valuable because it does not treat `libapp.so` as a generic stripped ELF only. It uses the Dart runtime corresponding to the target snapshot and can recover object-pool data, symbol-like function information, code offsets, assemblies and Frida-oriented metadata.

Do **not** allow the normal static sandbox to silently clone Dart sources or build missing analyzers during an analysis run. Blutter's build-on-demand behavior conflicts with the project's immutable, offline static trust model.

Preferred deployment:

```text
framework-flutter image/profile
        │
        ├─ pinned Blutter source/version
        ├─ prebuilt or controlled-cache Dart runtime analyzers
        ├─ no arbitrary caller command execution
        └─ normalized MCP adapter
```

Planned MCP operations:

```text
build_flutter_index
find_dart_symbols
find_dart_strings
find_dart_xrefs
map_dart_to_native
```

Normalize results into the Program Evidence Graph (PEG):

```text
DartLibrary
DartClass
DartFunction
DartObject
String
NativeOffset
Endpoint
HttpHeader
CryptoSignal
CallEdge / XrefEdge
Evidence
```

Acceptance criteria:

- recover high-signal Dart package/library/class/function metadata where supported;
- recover strings and object-pool values without relying only on generic `strings` output;
- map recovered functions to `libapp.so` code offsets;
- keep analyzer/version/runtime provenance;
- expose bounded semantic results rather than raw multi-megabyte dumps.

## 1.3 Flutter network/auth/crypto reconstruction

Build on the Dart AOT index rather than merely scanning for URL-shaped strings.

Planned operation:

```text
extract_flutter_network_model
```

Target evidence:

```text
first-party host
endpoint/path
Dart owning library/class/function
HTTP client clues (Dio/http/etc.)
request/header construction clues
auth/token/signature signals
native offset evidence
confidence state + limitations
```

Generic Rizin/Ghidra analysis should be used only after Dart-level localization identifies a native neighborhood that needs deeper CFG/XREF/decompilation.

---

# 2. Strong Android static core

**Priority: P0/P1**

Java/Kotlin semantic analysis is already present, but package fidelity and bytecode/resource coverage should be extended.

Add or complete:

```text
Apktool
aapt2
apksigner / apksig
smali / baksmali
APKiD packaging/license decision
```

Androguard, file and binutils are already present in the 0.2.1 static image and should not be tracked as missing work.

Planned MCP operations:

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

Acceptance criteria:

- manifest/resources parsed structurally across split APKs;
- package signing/certificate information exposed;
- exported components/deep links/network-security configuration normalized;
- DEX↔source↔Smali locations can be correlated;
- no arbitrary resource/smali modification in the default analysis profile.

Mutation/rebuild operations, if added later, belong in an explicit `patch-lab` capability rather than the default static profile.

---

# 3. True data-flow and value tracing

**Priority: P0/P1 — highest semantic capability after framework routing**

XREF/call adjacency is not proof of value flow. The next major semantic layer is interprocedural tracing.

Candidate backends:

```text
SootUp / Jimple
FlowDroid-family taint/data-flow analysis
custom bounded DEX tracing for simple cases
```

Do not run expensive whole-app FlowDroid-style analysis by default. Use the existing symbol/XREF/network indexes to localize a small relevant subgraph first.

Planned MCP operations:

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

Target flow:

```text
source/value
   ↓
definition
   ↓
transformations
   ↓
serialization / crypto / encoding
   ↓
header / body / query / sink
```

Acceptance criteria:

- findings distinguish CALLS/XREFS from FLOWS_TO evidence;
- sources, sinks and sanitizers are explicit;
- auth/token/header/signature paths can be reconstructed across methods;
- unsupported/reflection/native boundaries are reported instead of guessed.

---

# 4. Security knowledge and vulnerability analysis

**Priority: P1**

Security analysis should evolve beyond isolated Semgrep/mobsfscan hits into a machine-readable security knowledge layer mapped onto PEG evidence.

Candidate rule sources/tooling:

```text
Semgrep
mobsfscan
OWASP MASVS / MASWE / MASTG-derived knowledge
project-specific source/sink/sanitizer registry
```

Planned operations:

```text
scan_security
explain_finding
verify_finding
coverage_report
```

A rule match is evidence for review, not automatically a verified vulnerability.

Target lifecycle:

```text
candidate
   ↓
probable
   ↓
verified / refuted / unknown
```

Each finding should retain:

```text
rule/version
weakness mapping
source/sink/sanitizer definitions
graph/data-flow evidence
location/provenance
analyzer versions
limitations
runtime confirmation when available
```

---

# 5. Native and JNI analysis

**Priority: P1/P2**

Generic native analysis remains essential for request signing, custom encryption, anti-debugging, certificate pinning, proprietary protocols, JNI bridges and framework runtimes.

## 5.1 Fast ELF triage — current baseline

The static image already includes:

```text
file
strings
readelf
objdump
nm
```

Extend the semantic wrapper with:

```text
inspect_elf
list_sections
list_imports
list_exports
list_symbols
search_native_strings
find_jni_exports
```

## 5.2 Rizin profile — P1

Use Rizin for scriptable/headless native XREF/CFG/disassembly.

Planned operations:

```text
disassemble_function
find_native_xrefs
analyze_native_function
find_native_callers
find_native_callees
inspect_jni
```

Do not expose a generic Rizin console.

## 5.3 Ghidra headless — P2

Use a separate native image for difficult ARM/ARM64 decompilation, P-code/IR analysis, complex JNI and crypto routines.

Target cross-language graph:

```text
Java/Kotlin method
      ↓ JNI_BINDS
native function
      ↓
native CFG / data flow
```

Ghidra should be an escalation backend, not a reason to enlarge the default static image.

---

# 6. Additional framework analyzers

**Priority: P2 after Flutter foundation**

The framework-adapter pattern established for Flutter should be reused rather than implemented as ad-hoc tool wrappers.

## 6.1 React Native / Hermes

Detect:

```text
assets/index.android.bundle
Hermes bytecode
source maps
React Native bridge metadata
```

Planned operations:

```text
inspect_react_native
decompile_hermes
build_hermes_index
find_js_symbols
extract_js_endpoints
```

## 6.2 Unity / IL2CPP

Detect and correlate:

```text
libil2cpp.so
global-metadata.dat
assets/bin/Data
```

Candidate tooling:

```text
Il2CppDumper
Il2CppInspector or maintained alternatives after license/security review
```

Planned operations:

```text
inspect_unity
recover_il2cpp_metadata
map_il2cpp_methods
search_unity_symbols
```

## 6.3 Xamarin / .NET MAUI

Add managed assembly detection and IL-aware analysis instead of relying on JADX for host code.

## 6.4 Protocol adapters

Add specialized extraction/modeling for:

```text
protobuf / gRPC
GraphQL
WebSocket
Socket.IO
SSE
MQTT
custom DNS / DoH
```

---

# 7. Controlled dynamic analysis

**Priority: P2/P3; separate trust boundary**

Dynamic analysis must not be bolted onto the static container.

Candidate components:

```text
ADB
Android emulator / approved device
Frida
Objection where useful
mitmproxy / controlled TLS observation
reFlutter for Flutter-specific runtime investigation where appropriate
```

Prefer semantic runtime operations:

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

Avoid making unrestricted `run_frida_script(script)` the primary interface.

Target feedback loop:

```text
static evidence
   ↓
unresolved hypothesis
   ↓
targeted runtime observation
   ↓
OBSERVED_* evidence
   ↓
CONFIRMS / CONTRADICTS
   ↓
updated PEG
```

Acceptance criteria:

- explicit user opt-in;
- separate image/MCP capability;
- clear device/network privilege policy;
- secret/value redaction controls;
- runtime evidence uses the same normalized evidence model as static analysis.

---

# 8. AI-agent architecture

**Priority: P1/P2**

AI should orchestrate evidence rather than replace deterministic analysis.

Recommended roles:

```text
Planner
Surface Mapper
Graph Investigator
Flow Analyst
Endpoint Analyst
Native/Framework Analyst
Dynamic Explorer
Pattern Miner
Critic
Verifier
Reporter
```

The Critic/Verifier path should be logically independent of the Investigator so the same reasoning process does not both invent and approve a claim.

Long-lived investigations should use stable `analysis_id` / artifact hash handles and retrieve bounded graph neighborhoods/resources instead of repeatedly reading entire decompiled trees.

---

# 9. Novel vulnerability-pattern discovery

**Priority: P3 after PEG + data flow + verifier are stable**

Do not ask an LLM to scan a whole app and invent vulnerabilities directly. Use graph/data-flow motifs and anomaly ranking to generate candidates, then verify them deterministically.

Target pipeline:

```text
known rules / security knowledge
          ↓
PEG behavior motifs
          ↓
anomaly / unusual-flow ranking
          ↓
AI hypothesis
          ↓
reachability + data-flow + sanitizer verification
          ↓
targeted dynamic confirmation when necessary
          ↓
validated candidate
          ↓
rule synthesis
          ↓
positive + negative regression corpus
```

Planned operations:

```text
mine_patterns
propose_rule
validate_rule
regression_test_rule
```

AI may propose rules, but promotion into production rule packs requires deterministic regression gates.

---

# 10. Program Evidence Graph

PEG is the long-lived core that unifies all analyzers.

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

Evidence state:

```text
observed     direct bytecode / binary / IR / runtime fact
derived      deterministic analyzer inference
hypothesized agent/heuristic interpretation requiring verification
```

Every material fact should preserve:

```text
analysis_id
artifact/input SHA-256
analyzer name + version
image/build identity
configuration/schema version
source location or native offset
evidence state
limitations
```

---

# 11. Capability-image architecture

Do not grow one privileged image indefinitely.

```text
safe-android-reverser
├── static-core
│   ├── APK / bundle / manifest / resources
│   ├── DEX / Java / Kotlin / Smali
│   └── fast native triage
│
├── framework-flutter
│   ├── Dart runtime identification
│   ├── Dart AOT recovery
│   └── libapp.so semantic mapping
│
├── framework-hermes
├── framework-il2cpp
├── native
│   ├── Rizin
│   ├── Ghidra headless
│   └── JNI / native IR
│
└── dynamic
    ├── emulator / approved device
    ├── curated Frida instrumentation
    └── controlled network/TLS observation
```

The static/default profile remains rootless, offline, read-only where possible, and without generic shell execution.

---

# 12. Prioritized backlog

## P0 — current/next

- [x] Framework fingerprinting
- [x] Androguard-backed DEX program index
- [x] `find_symbols`
- [x] `find_xrefs`
- [x] `get_cfg`
- [x] `extract_network_model`
- [x] basic ELF/binutils triage
- [ ] Framework Router that changes analyzer strategy after fingerprinting
- [ ] Flutter artifact inventory
- [ ] `identify_dart_runtime`
- [ ] dedicated `framework-flutter` profile
- [ ] Blutter integration feasibility + version/cache strategy
- [ ] `build_flutter_index`
- [ ] `find_dart_symbols` / `find_dart_strings`
- [ ] `map_dart_to_native`
- [ ] `extract_flutter_network_model`
- [ ] structured manifest/resources/signature analysis

## P1

- [ ] `trace_value`
- [ ] taint/source/sink/sanitizer engine
- [ ] `find_auth_flow`
- [ ] `find_signing_logic`
- [ ] `trace_crypto`
- [ ] Semgrep/mobsfscan integration
- [ ] security knowledge graph/rule model
- [ ] Rizin native profile
- [ ] JNI cross-language mapping
- [ ] first-party/third-party endpoint attribution improvements
- [ ] Investigator → Critic → Verifier workflow

## P2

- [ ] Ghidra headless profile
- [ ] React Native/Hermes analyzer
- [ ] Unity/IL2CPP analyzer foundation
- [ ] Xamarin/.NET MAUI analyzer
- [ ] protobuf/gRPC/GraphQL/WebSocket specialized modeling
- [ ] controlled emulator/Frida dynamic profile
- [ ] static↔dynamic evidence correlation

## P3

- [ ] targeted symbolic execution for narrow native functions
- [ ] graph-motif/anomaly mining
- [ ] novel vulnerability-pattern discovery
- [ ] automatic rule proposal + regression validation
- [ ] mature multi-framework PEG querying and cross-analyzer verification

---

# 13. Tool integration policy

Before adding an analyzer:

1. pin the version or exact source revision;
2. verify hashes/provenance where redistribution allows it;
3. review license compatibility;
4. prefer headless/scriptable operation;
5. record analyzer/runtime version in evidence;
6. expose bounded semantic MCP operations, not arbitrary commands;
7. keep runtime network disabled unless the profile explicitly requires it;
8. add deterministic fixtures and integration tests;
9. document resource limits and unsupported versions/architectures;
10. do not silently fall back to host-installed tools or download/build dependencies during normal offline analysis.

---

# 14. Testing and success metrics

Every analyzer should have unit, tool-integration and end-to-end MCP tests.

Critical metrics:

```text
framework routing accuracy
first-party endpoint recall / precision
auth/signature reconstruction rate
call-edge and data-flow precision
security finding precision
runtime confirmation rate
native/framework mapping coverage
evidence completeness
analysis p50 / p95 and peak memory
context/token cost per verified finding
regression rate across protected/obfuscated apps
```

For framework adapters, fixtures must include multiple runtime/compiler versions and explicit unsupported-version tests.

---

## End state

The intended end state is an MCP platform that can answer questions such as:

```text
Which representation contains this app's real business logic?
Which first-party APIs does this Flutter XAPK use?
Which Dart function constructs this request and where is it in libapp.so?
Where does this Authorization value originate?
Which transformations produce X-Signature?
Which Java method crosses into which JNI/native function?
Was this predicted path actually observed at runtime?
Which security finding is directly supported, refuted, or still unknown?
Which unusual source→sink graph motif may represent a new vulnerability pattern?
```

The MCP layer should select and combine the right analyzers, preserve trust boundaries, normalize all facts into PEG, and return enough provenance for a reverse engineer or independent verifier agent to reproduce the conclusion.
