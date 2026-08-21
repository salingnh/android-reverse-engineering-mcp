# Project Direction

This document is the canonical long-term direction for Safe Android Reverser MCP. It should be updated whenever a significant architectural, security, analyzer-routing, or product-priority decision changes.

## Product vision

Safe Android Reverser should evolve into an **AI-native Android security and program-understanding platform**, not a collection of reverse-engineering CLI wrappers.

The stable product abstractions are:

- semantic MCP operations;
- framework-aware analyzer routing;
- a shared Program Evidence Graph (PEG);
- reproducible evidence and provenance;
- deterministic verification of agent hypotheses;
- strict capability and trust boundaries.

Underlying analyzers such as JADX, Androguard, Blutter, Rizin, Ghidra, Frida, Apktool, FlowDroid, or future replacements are implementation details and evidence producers.

## Core principles

### 1. The agent reasons. The MCP server controls. The sandbox executes.

AI agents may plan investigations, select semantic questions, correlate evidence, propose hypotheses, and explain findings. They should not receive a generic shell or unrestricted analyzer console.

### 2. Detect the framework before selecting the analyzer

Do not assume APK means Java/Kotlin.

```text
artifact
   ↓
fingerprint / framework router
   ├─ Native Android      → DEX / Java / Kotlin semantics
   ├─ Flutter             → Dart AOT + libapp.so + Flutter assets
   ├─ React Native/Hermes → Hermes / JavaScript bytecode
   ├─ Unity IL2CPP        → global metadata + native code
   └─ Xamarin/.NET MAUI   → managed assemblies
```

The analyzer must target the representation that actually contains the application's business logic.

### 3. Decompilation is a presentation layer, not canonical truth

JADX/Vineflower source is useful for human explanation and localization. Important conclusions should retain provenance to DEX, IR, native addresses, framework metadata, or runtime observations wherever possible.

### 4. Native analysis is a substrate, not a universal framework analyzer

Flutter illustrates the distinction. Its release business logic is commonly AOT-compiled into `libapp.so`, but generic ELF disassembly alone loses Dart runtime semantics. Flutter therefore requires **Dart AOT-aware native analysis** before or alongside generic native analysis.

The same principle applies to IL2CPP, Hermes, and managed runtimes.

### 5. Program Evidence Graph is the long-lived platform core

Normalize analyzer facts into a shared evidence model instead of returning disconnected tool reports.

Representative nodes:

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
JNIBinding
Endpoint
HttpHeader
CryptoOperation
StorageKey
RuntimeEvent
Finding
Evidence
```

Representative relationships:

```text
CONTAINS
DECLARES
CALLS
XREFS
READS
WRITES
FLOWS_TO
DERIVED_FROM
JNI_BINDS
BUILDS_REQUEST
SENDS_TO
AUTHENTICATES_WITH
OBSERVED_CALL
OBSERVED_VALUE
CONFIRMS
CONTRADICTS
```

Evidence states must remain distinct:

```text
observed
  direct bytecode / IR / binary / runtime fact

derived
  deterministic analyzer inference

hypothesized
  agent/heuristic interpretation requiring verification
```

### 6. XREF is not data flow

Call adjacency must never be presented as proof that a value flowed between two methods. `trace_value`, taint/slicing, and runtime confirmation are separate capabilities.

### 7. Static and dynamic analysis form a feedback loop

Dynamic analysis is not a fallback dump mode. Static analysis should localize unresolved questions, generate targeted observations, and feed runtime facts back into the PEG.

```text
static hypothesis
      ↓
targeted runtime observation
      ↓
CONFIRMS / CONTRADICTS
      ↓
updated evidence graph
```

Dynamic execution must remain an explicit opt-in trust boundary.

### 8. AI retrieves and ranks evidence; deterministic analyzers establish facts

Embeddings and LLM reasoning can prioritize methods, identify suspicious motifs, generate investigation plans, and propose vulnerability patterns. Similarity or model confidence is not proof.

### 9. Security findings require independent verification

Long-term agent topology should separate roles such as Planner, Investigator, Critic, Verifier, and Reporter. A finding should move through evidence-backed states such as:

```text
candidate → probable → verified / refuted / unknown
```

### 10. Optimize for useful answers, not number of installed tools

Success metrics include endpoint recall/precision, first-party attribution, data-flow precision, finding precision, runtime confirmation rate, framework routing accuracy, evidence completeness, analysis latency, and token/context cost per verified finding.

## Current development focus

The current release is **0.2.1**. The Java/Kotlin semantic foundation already includes Androguard-backed program indexing, symbol search, DEX XREFs, CFG inspection, network-model extraction, and evidence-aware bounded responses.

The highest-priority development track is now **framework-aware routing**, with **Flutter AOT analysis first**.

### Why Flutter moved forward

A real Flutter application demonstrated the current architectural gap:

```text
fingerprint → Flutter detected
                  ↓
             JADX continues
                  ↓
        Android host shell only
                  ↓
      main Dart logic still hidden
            inside libapp.so
```

The correct route is:

```text
Flutter detected
      ↓
Flutter artifact inventory
      ↓
Dart / Flutter runtime identification
      ↓
Dart AOT-aware analysis of libapp.so
      ↓
recover strings / objects / classes / functions / offsets
      ↓
endpoint / auth / crypto / feature reconstruction
      ↓
selective generic native analysis where needed
      ↓
optional targeted runtime verification
```

### Immediate Flutter implementation direction

Use a dedicated `framework-flutter` capability profile. Do not place build-on-demand Dart SDK checkout or unrestricted network access in the normal static sandbox.

Primary candidate for initial static AOT recovery: **Blutter**, because it uses the Dart runtime corresponding to the target snapshot and can recover object-pool information, function/code-offset information, and Frida-oriented metadata from Android ARM64 `libapp.so`.

Integration must wrap Blutter behind bounded semantic operations rather than exposing arbitrary commands.

Target operations:

```text
inspect_flutter
identify_dart_runtime
extract_flutter_assets
build_flutter_index
find_dart_symbols
find_dart_strings
find_dart_xrefs
extract_flutter_network_model
map_dart_to_native
```

Expected normalized evidence includes:

```text
Dart library/package
class/function
string/object-pool reference
native code offset
first-party endpoint
HTTP/auth/crypto signal
evidence location
analyzer/version
limitations
```

Generic Rizin/Ghidra analysis should be invoked only for native neighborhoods that require deeper CFG/XREF/decompilation after Dart-level localization.

Runtime patching, reFlutter, Frida, emulator/device access, TLS interception, and proxy control belong to a separate dynamic profile.

## Next strategic priorities

After framework routing and initial Flutter support, the priority order is:

1. **True value/data-flow analysis** — `trace_value`, slicing, sources/sinks/sanitizers, auth/token/signature tracing.
2. **Security knowledge engine** — machine-readable vulnerability knowledge mapped to PEG queries, including OWASP MASVS/MASWE/MASTG-oriented coverage.
3. **Independent agent verification** — Investigator → Critic → Verifier workflow with evidence-backed claim states.
4. **Targeted dynamic correlation** — curated runtime observations instead of arbitrary Frida JavaScript.
5. **Deep native/JNI analysis** — Rizin/Ghidra/IR integration and Java↔JNI↔native mapping.
6. **Additional framework adapters** — Hermes/React Native, Unity IL2CPP, protobuf/gRPC and managed runtimes.
7. **Novel-pattern discovery** — graph-motif/anomaly mining, agent hypothesis generation, deterministic verification, rule synthesis and regression testing.

## Capability profile direction

```text
safe-android-reverser
├── static-core
│   ├── APK / bundle structure
│   ├── manifest / resources / signatures
│   ├── DEX / Java / Kotlin / Smali
│   ├── fast native triage
│   └── program evidence indexing
│
├── framework-flutter
│   ├── Flutter/Dart fingerprint details
│   ├── Dart AOT recovery
│   ├── libapp.so semantic mapping
│   └── Flutter-specific endpoint/auth/crypto evidence
│
├── framework-hermes
├── framework-il2cpp
│
├── native
│   ├── ELF
│   ├── JNI
│   ├── native CFG / XREF / IR
│   └── targeted decompilation/symbolic reasoning
│
└── dynamic
    ├── emulator / approved device
    ├── curated Frida instrumentation
    ├── runtime values / coverage
    └── controlled network/TLS observation
```

Profiles may be separate images or separately enabled runtime capabilities, but broader privileges must never silently leak into the default static profile.

## Non-goals / guardrails

The project should not:

- expose arbitrary `shell`, `exec`, raw Rizin/Ghidra consoles, or unrestricted Frida JavaScript as the primary MCP interface;
- make the default static image privileged or network-enabled;
- treat a regex/security-rule hit as a verified vulnerability;
- treat XREF adjacency as data flow;
- use JADX as the universal analyzer for every Android package;
- grow one giant image solely to maximize the number of bundled tools;
- allow an analyzer to download/build dependencies silently during an offline analysis run;
- let an LLM manufacture unsupported confidence values or evidence.

## Documentation rule

Whenever a substantial project-direction decision changes, update all applicable sources in the same change:

1. `docs/PROJECT_DIRECTION.md` — canonical product/architecture direction;
2. `docs/ROADMAP.md` — priority, phases, implementation state and acceptance criteria;
3. `README.md` — short current-development status visible to users;
4. research/design documents when the decision introduces new technical evidence.

This rule exists so future agents and contributors can recover the project's intent from the repository instead of relying on chat history.

## Decision log

### 2026-08-21 — Promote framework-aware routing and Flutter AOT analysis

**Decision:** Move framework routing and Flutter AOT-aware analysis from a later framework phase into the immediate development track.

**Reason:** Real Flutter analysis showed that detecting Flutter without changing analyzer strategy leaves most business logic inaccessible because Dart release code resides in AOT-compiled `libapp.so`.

**Consequence:** Implement a `framework-flutter` analyzer/profile, initially evaluate/integrate Blutter semantics, normalize Dart evidence into PEG, and reserve generic native analysis for deeper localized investigation.

### 2026-08-21 — Repository documentation is the durable project memory

**Decision:** Keep project direction explicit and versioned in repository documentation.

**Reason:** Architectural intent must survive individual chats, agents, and maintainers.

**Consequence:** `PROJECT_DIRECTION.md`, `ROADMAP.md`, and the README development-status section must be updated when major priorities change.
