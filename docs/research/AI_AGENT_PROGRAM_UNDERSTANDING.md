# AI-Agent Program Understanding for Advanced Android Reverse Engineering

**Research snapshot:** 2026-08-20  
**Project:** `salingnh/android-reverse-engineering-mcp`  
**Status:** Architecture and roadmap research; not yet an implementation specification.

## Executive summary

The project should evolve from a safe MCP wrapper around decompilers into an **AI-native program-understanding platform**.

The most important architectural shift is:

> Do not ask an LLM to understand an APK primarily by reading decompiled source. Give the agent a structured, queryable model of program behavior — symbols, XREFs, call graph, CFG, data flow, JNI boundaries, network construction, crypto transformations, runtime traces, and evidence provenance — and let the LLM act as planner, investigator, and verifier.

The recommended investigation loop is:

```text
user question
    ↓
artifact / component localization
    ↓
class / method / native-function localization
    ↓
XREF + call-graph neighborhood
    ↓
backward / forward value tracing
    ↓
network / auth / crypto / JNI model
    ↓
targeted dynamic confirmation when static evidence is insufficient
    ↓
optional targeted symbolic reasoning
    ↓
evidence-backed explanation
```

The central product abstraction should become a **Program Evidence Graph (PEG)**. Reverse-engineering tools are replaceable producers of facts; the graph, evidence schema, semantic MCP API, and verifier become the stable platform.

## Current project baseline

The current MCP server already has a strong security-oriented execution model:

- project input mounted read-only;
- analysis output isolated under plugin data;
- allow-listed subprocess arguments;
- `shell=False`;
- no generic shell/exec tool exposed to the model;
- sandbox runtime intended to run without network access.

The current MCP surface is:

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

This is a good **Phase 0 static-safe baseline**, but most current capabilities remain file/text oriented. In particular:

- `extract_api` extracts URLs, Retrofit annotations, endpoint-shaped strings, and auth/network signals;
- `search_source` and `read_source_file` require the agent to interpret decompiled text;
- there is no first-class call graph, XREF graph, CFG, taint/data-flow, JNI graph, runtime trace model, or evidence verifier yet.

That means the project can already answer questions such as:

```text
Which HTTP framework is present?
Which URLs or Retrofit endpoints appear in the app?
Which files contain a token/header-related string?
```

but it cannot yet answer these reliably as structured program-analysis queries:

```text
Who calls this endpoint?
Where does Authorization originate?
Which UI action reaches this request?
What values contribute to X-Signature?
Where does the Java flow cross into JNI?
Was this path observed at runtime?
```

## Main research conclusions

### 1. Decompilation is a presentation layer, not canonical truth

Readable JADX output is useful for localization and explanation, but high-value conclusions should retain provenance back to lower-level evidence such as:

```text
DEX / Smali
CFG / data-flow facts
native address / P-code / SSA
runtime observation
```

This matters because decompilation is heuristic and can be incomplete or semantically incorrect.

**Integration implication:** keep `decompile`, `search_source`, and `read_source_file`, but stop treating their text output as the only authoritative representation.

### 2. XREF, call graph, CFG, and data flow should be first-class MCP capabilities

The next major capability is not “add another decompiler”; it is **program structure**.

The useful distinction is:

```text
control flow:
    if / branch / loop / CFG

call flow:
    caller → callee

data flow:
    value definition → transforms → sink
```

For the target use cases — APIs, auth, signing, tokens, identifiers, crypto, JNI — **backward and forward value tracing** is often the most valuable primitive.

Example:

```text
Authorization header
        ↓ backward slice
OkHttp interceptor
        ↓
SessionManager.getToken()
        ↓
SharedPreferences["access_token"]
```

**Integration implication:** prioritize `find_xrefs`, `get_cfg`, and `trace_value` immediately after the evidence schema.

### 3. Network understanding should produce a model, not a URL list

The target output should be a normalized network model:

```text
Host
 └─ api.example.com
      ├─ POST /v2/login
      │    ├─ caller: AuthRepository.login
      │    ├─ body: LoginRequest
      │    └─ auth: none
      │
      └─ GET /v2/profile
           ├─ caller: ProfileRepository.load
           ├─ Authorization: Bearer <token>
           └─ signing: X-Signature
```

Useful input signals include:

- Retrofit annotations/interfaces;
- OkHttp interceptors;
- Ktor, Volley, Apollo, GraphQL;
- URL/request-builder value flow;
- Manifest and Network Security Configuration;
- protobuf/gRPC descriptors;
- WebSocket/MQTT markers;
- native networking calls;
- runtime network events.

**Integration implication:** evolve the current `extract_api` implementation into `extract_network_model`, while keeping `extract_api` as a compatibility or convenience tool.

### 4. Static and dynamic analysis should form one feedback loop

Static and dynamic analysis should not be two independent modes.

Recommended flow:

```text
static analysis
    ├─ identifies suspicious method
    ├─ predicts endpoint / crypto routine
    └─ proposes hook location
             ↓
dynamic execution
    ├─ observes actual arguments
    ├─ records executed callers
    ├─ captures runtime-loaded code
    └─ confirms network activity
             ↓
Program Evidence Graph update
             ↓
refined static analysis
```

**Integration implication:** dynamic analysis should be a separate privileged trust boundary and should receive targeted questions generated from unresolved static evidence.

### 5. Symbolic execution should be narrow and targeted

Whole-app symbolic execution is not a good default for modern Android applications.

Use this sequence instead:

```text
large app
   ↓ localize
relevant call graph
   ↓ slice
small function set
   ↓ concrete runtime seeds when available
target function
   ↓
symbolic exploration
```

Good target questions include:

```text
Which conditions make isPremium() return true?
What input bytes select a native parser branch?
What contributes to a request signature?
Which flags lead to certificate verification failure?
```

**Integration implication:** `symbolically_explore` should be P2, after call graph, slicing, native mapping, and runtime correlation exist.

### 6. Native analysis must feed the same semantic model

Native `.so` analysis should not produce a disconnected “Ghidra report”.

Normalize important relationships into the same graph:

```text
DEX / Java                      native ELF

method                          function
parameter                       register/stack argument
field                           global/memory object
invoke-*                        call / indirect call
DEX CFG                         native CFG
value definition                SSA / P-code definition
return                          function return
JNI declaration        ↔        JNI implementation
```

**Integration implication:** use a dedicated native capability image and map JNI/native evidence back into the common graph.

### 7. AI/ML retrieval should rank evidence, not define truth

Embeddings and code models can help answer:

```text
find code related to login
find likely request signing
find license checks
cluster generated/library code
rank methods related to payment flow
```

But similarity scores are not proof of behavior.

Recommended retrieval stack:

```text
natural-language question
      ↓
semantic retrieval
  + symbol/string index
  + graph neighborhood retrieval
  + data-flow reachability
      ↓
small ranked evidence set
      ↓
LLM reasoning
```

Deterministic program-analysis facts and runtime observations remain authoritative.

## Recommended Program Evidence Graph

Representative node types:

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

Every important graph edge should point to evidence.

### Evidence states

Keep these states distinct:

```text
observed
    direct bytecode / IR / runtime fact

derived
    deterministic analyzer inference

hypothesized
    LLM or heuristic interpretation requiring verification
```

The LLM should not manufacture arbitrary confidence values. Confidence should come from evidence type, analyzer precision, independent corroboration, and runtime confirmation.

### Provenance fields

Every analyzer result should record at least:

```text
analysis_id
artifact_id / input SHA-256
analyzer name and version
container image digest
configuration hash
schema version
evidence status
source location / native address
limitations
```

This makes findings reproducible and allows later analyzer upgrades to be regression-tested.

## Recommended semantic MCP API

The primary API should expose reverse-engineering questions, not underlying CLI commands.

Avoid making these the main abstractions:

```text
run_jadx
run_ghidra_command
run_grep
run_frida_script
```

Prefer:

| MCP API | Main question |
|---|---|
| `identify_protector` | Is packing/obfuscation invalidating static assumptions? |
| `find_symbols` | Where is relevant logic likely located? |
| `find_xrefs` | Who references/calls this symbol? |
| `get_cfg` | Which branches and conditions exist here? |
| `trace_value` | Where does this value originate or go? |
| `extract_network_model` | Which backend interfaces exist and how are they built? |
| `find_auth_flow` | How does login/token/refresh/storage/header flow work? |
| `trace_crypto` | How is this value signed/encrypted/encoded? |
| `inspect_jni` | What crosses Java/native boundaries? |
| `observe_runtime` | Did the predicted path execute, and with what values? |
| `symbolically_explore` | Which conditions/inputs reach this target? |
| `verify_claim` | Is an agent conclusion supported, refuted, or unknown? |

Higher-level composite tools can later include:

```text
explain_behavior
explain_endpoint
trace_ui_to_endpoint
find_signing_logic
find_license_check
```

Composite tools should internally call deterministic primitives rather than embedding all logic in one opaque LLM workflow.

## Suggested MCP response pattern

Long-lived analysis should return explicit handles:

```json
{
  "analysis_id": "an_01J...",
  "artifact_id": "apk_sha256:..."
}
```

Subsequent tools should accept the handle explicitly.

Example normalized evidence location:

```json
{
  "artifact_id": "apk:base",
  "path": "sources/com/acme/auth/Signer.kt",
  "class": "com.acme.auth.Signer",
  "method": "sign",
  "line": 142,
  "address": null,
  "ir": "dex"
}
```

Native location:

```json
{
  "artifact_id": "elf:libsecure.so",
  "path": "lib/arm64-v8a/libsecure.so",
  "function": "sub_19A40",
  "address": "0x19a40",
  "ir": "pcode"
}
```

Large CFGs, source excerpts, traces, and reports should be linked as MCP resources rather than dumped into model context.

## Recommended capability-image architecture

Do not grow one giant image indefinitely.

Recommended topology:

```text
AI Agent
   ↓
semantic MCP / planner
   ↓
Program Evidence Graph
   ↑
   ├─ static-core
   ├─ native
   ├─ framework
   └─ dynamic   ← separate explicit trust boundary
```

### `static-core`

Responsibility:

- APK/bundle structure;
- manifest/resources;
- DEX/Java/Kotlin semantics;
- symbol index;
- XREF/call graph/CFG;
- data flow/taint;
- network/auth model;
- protector detection.

Candidate tooling:

```text
JADX
Apktool
Androguard
Soot / SootUp family
FlowDroid
APKiD
```

Trust model:

```text
network disabled
read-only artifact input
restricted output directory
non-root / rootless runtime
```

### `native`

Responsibility:

- ELF `.so` functions;
- JNI binding recovery;
- native call graph;
- lifted IR / SSA;
- targeted native data flow;
- targeted symbolic execution.

Candidate tooling:

```text
Ghidra headless / P-code
angr
optional rev.ng / Rizin adapters
```

### `framework`

Responsibility:

- Flutter/Dart;
- React Native/Hermes;
- Unity/IL2CPP;
- protobuf/gRPC;
- framework-specific metadata/assets.

The current `fingerprint` tool already provides the routing signals needed to choose many of these analyzers.

### `dynamic`

Responsibility:

- emulator/test-device control;
- Frida hooks;
- runtime call observations;
- dynamically loaded classes/DEX;
- concrete runtime values;
- controlled network/TLS observation.

This image must remain separate from static analysis because it requires a broader privilege and device/network model.

## Integration feasibility against the current project

### Immediately compatible — P0

These fit the existing sandbox/MCP architecture without changing the core security model.

#### A. Evidence schema and `analysis_id`

**Feasibility:** very high.  
**Change:** evolve current `job_id` metadata into a versioned analysis/evidence model while keeping `job_id` compatibility initially.

Suggested first artifact files:

```text
analysis.json
evidence.jsonl
symbols.json
xrefs.json
network-model.json
```

#### B. `identify_protector`

**Feasibility:** high.  
**Candidate:** APKiD in `static-core`.

The important output is not only a packer name but routing advice:

```json
{
  "dynamic_required": true,
  "static_graph_completeness": "low",
  "recommended_strategy": ["smali", "runtime_class_loading_trace"]
}
```

#### C. `find_symbols` + `find_xrefs`

**Feasibility:** high.  
**Candidate:** Androguard first, because XREFs over classes/methods/fields/strings map naturally to the proposed graph.

This should become the first true semantic navigation layer.

#### D. `get_cfg`

**Feasibility:** high to medium.  
**Candidate:** Androguard basic blocks initially; richer JVM analysis can follow with Soot-family tooling.

#### E. `extract_network_model`

**Feasibility:** high.  
**Migration path:** reuse the existing `extract_api` heuristics, then enrich them with callers, request builders, Network Security Config, first-party classification, and evidence IDs.

### High value but larger implementation — P0/P1

#### F. `trace_value`

**Feasibility:** medium.  
**Candidate:** Soot/FlowDroid-family program analysis.

This is the single most important semantic upgrade for auth, endpoints, identifiers, crypto, and request construction.

#### G. `find_auth_flow`

**Feasibility:** medium once `trace_value` exists.

It should be built as a composite operation over:

```text
network endpoint
→ interceptor/header construction
→ token getter
→ storage key
→ login/refresh writers
```

#### H. `trace_crypto`

**Feasibility:** medium after value tracing.

Start with deterministic Java/JCA patterns and backward slicing from HTTP fields. Add native and runtime confirmation later.

### Requires separate capability images — P1

#### I. `inspect_jni`

**Feasibility:** medium.  
**Dependencies:** native image, Ghidra/P-code or equivalent, JNI symbol/binding mapper.

#### J. `observe_runtime`

**Feasibility:** medium technically, but high security/operational complexity.

Requirements:

- separate dynamic image;
- explicit user opt-in;
- emulator or approved test device;
- resource/time budgets;
- secret redaction by default;
- coverage metadata on every runtime result.

### Defer until semantic foundations exist — P2

#### K. `symbolically_explore`

**Feasibility:** technically high for narrow native functions, poor for whole-app use.

Only enable after graph localization and slicing can produce a small bounded target.

#### L. Semantic embeddings / ML retrieval

**Feasibility:** high but not urgent.

Use only for candidate ranking and fuzzy retrieval. Do not make embedding similarity an evidence type equivalent to data-flow or runtime proof.

## Recommended implementation order

### Phase 1 — Semantic foundation

Deliver:

```text
analysis/evidence schema
stable artifact identities
symbol index
find_symbols
find_xrefs
get_cfg
identify_protector
evidence provenance
```

**Acceptance focus:** deterministic structured output and reproducibility.

### Phase 2 — Data flow and network semantics

Deliver:

```text
trace_value
extract_network_model
find_auth_flow
trace_ui_to_endpoint
trace_crypto MVP
```

**Acceptance focus:** source→sink and backward-origin correctness on controlled Android fixtures.

### Phase 3 — Native and framework semantics

Deliver:

```text
native capability image
JNI mapping
P-code/SSA evidence
Flutter/Hermes/Unity adapters
protobuf/gRPC model
```

### Phase 4 — Hybrid dynamic analysis

Deliver:

```text
dynamic capability image
Frida semantic wrappers
runtime trace events
static↔runtime symbol correlation
coverage metadata
```

### Phase 5 — Advanced reasoning

Deliver:

```text
targeted symbolic exploration
protocol inference
semantic retrieval/ranking
planner/retriever/verifier loop
```

## Verification and CI strategy

The project should evaluate **program understanding**, not only successful tool execution.

Weak checks:

```text
Did JADX exit 0?
Did Ghidra import the .so?
Did FlowDroid emit output?
```

Useful checks:

```text
Can the system identify the endpoint invoked by LoginButton?
Can it trace Authorization back to token storage?
Can it reconstruct a request-signature pipeline?
Can it map Java → JNI → native logic?
Can it distinguish first-party endpoints from analytics SDKs?
Can it attach evidence to every important conclusion?
```

### Proposed regression corpus

Create intentionally small, known-source fixtures:

```text
android-basic
    Retrofit endpoints
    OkHttp interceptor
    token storage
    deep links
    callbacks

android-obfuscated
    R8
    reflection
    encrypted strings

android-native
    JNI request signing
    native crypto

android-dynamic
    runtime-loaded class
    runtime URL generation

flutter
react-native-hermes
unity-il2cpp

protocol
    protobuf
    custom TLV
    WebSocket
```

Also track external Android data-flow benchmarks such as DroidBench.

### Proposed metrics

```text
call-edge precision / recall
XREF precision / recall
data-flow source→sink precision / recall
correct-origin rate for backward tracing
endpoint host/method/path precision / recall
auth token/header mapping accuracy
crypto pipeline reconstruction accuracy
JNI binding accuracy
runtime-event → static-symbol mapping rate
supported-claim rate
provenance completeness
tool calls / tokens / CPU / RAM / wall time
```

### Suggested CI layers

```text
MCP/schema contract tests
        ↓
analyzer unit fixtures
        ↓
static integration fixtures
        ↓
cross-analyzer differential checks
        ↓
rootless Podman/Docker tests
        ↓
security/image checks
        ↓
small agent investigation benchmark
```

Heavy dynamic and symbolic suites should run scheduled/nightly rather than on every small pull request.

## Key risks and mitigations

| Risk | Consequence | Mitigation |
|---|---|---|
| Decompiled source is wrong | agent explains nonexistent semantics | retain DEX/Smali/IR provenance and cross-check high-value claims |
| Reflection/dynamic loading | missing graph edges | represent unresolved edges and escalate to runtime tracing |
| Packing/runtime obfuscation | static graph appears complete when it is not | protector detection changes routing and completeness status |
| Native boundary hides behavior | endpoint/crypto flow stops at JNI | explicit JNI graph and native value analysis |
| Dynamic coverage is low | unseen path incorrectly treated as absent | attach coverage metadata and return `unknown` when appropriate |
| Symbolic path explosion | excessive CPU/time | pre-slice target functions and enforce state/time budgets |
| Agent context explosion | poor reasoning and high token use | graph retrieval + MCP resource links |
| Tool disagreement | conflicting results | preserve evidence separately and expose contradictions |
| Tool/version drift | non-reproducible findings | pin analyzer/container versions and provenance hashes |
| Runtime secrets leak | sensitive data reaches reports/model context | redact values by default; store hashes/metadata when sufficient |
| Dynamic privileges expand attack surface | weaker sandbox guarantees | keep dynamic analysis in a separate explicit trust boundary |

## Recommended project decisions

The next roadmap should adopt these five decisions:

1. **Make the Program Evidence Graph the product core.** Analyzer binaries remain replaceable producers.
2. **Use `localize → trace → hypothesize → verify → escalate` as the default agent workflow.**
3. **Make data-flow understanding the highest technical priority after XREF/call graphs.**
4. **Treat static and dynamic analysis as one feedback system, but keep dynamic execution in a separate trust boundary.**
5. **Require evidence-backed final answers.** Every important conclusion should be `supported`, `refuted`, or `unknown` with evidence references.

Long-term, the platform should be capable of answering questions such as:

```text
What happens after the user taps this button?
Which business rules determine this behavior?
Which classes and native functions participate?
Which backend endpoint is eventually called?
Where do its parameters come from?
How is authentication generated?
How is the request signed or encrypted?
Which runtime conditions alter the flow?
Which parts are proven statically?
Which parts were observed dynamically?
What remains uncertain?
```

That is the point where the project moves from **“safe MCP access to reverse-engineering tools”** to **“an AI-native program-analysis system that can explain how an Android application works with traceable evidence.”**

## Priority research references

### P0 — architecture and semantic foundations

- SWE-agent — agent/computer interface design: https://arxiv.org/abs/2405.15793
- Agentless — hierarchical localization: https://arxiv.org/pdf/2407.01489
- RepoGraph — repository-level graph retrieval: https://arxiv.org/abs/2410.14684
- MCP tools specification (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- MCP resources specification (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/server/resources
- Androguard XREFs: https://androguard.readthedocs.io/en/latest/intro/xrefs.html
- SootUp: https://soot-oss.github.io/SootUp/develop/
- FlowDroid: https://dl.acm.org/doi/10.1145/2594291.2594299
- JADX project and limitations: https://github.com/skylot/jadx

### P1 — hybrid, native, and validation

- TIRO — targeted static/dynamic Android analysis: https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-wong.pdf
- Frida Gum API: https://frida.re/docs/gum-api/
- Ghidra P-code: https://ghidra.re/ghidra_docs/languages/html/pcoderef.html
- angr: https://docs.angr.io/en/latest/quickstart.html
- DroidScope: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/yan
- DroidBench: https://github.com/secure-software-engineering/DroidBench
- CIPHERH: https://www.usenix.org/system/files/sec23summer_289-deng-prepub.pdf
- D-Helix / decompiler correctness: https://www.usenix.org/system/files/sec24fall-prepub-759-zou.pdf
- APKiD: https://github.com/rednaga/APKiD

### P2 — semantic retrieval

- GraphCodeBERT: https://arxiv.org/abs/2009.08366
- CodeBERT: https://arxiv.org/abs/2002.08155
- OpenHands agent/sandbox architecture: https://arxiv.org/abs/2407.16741
