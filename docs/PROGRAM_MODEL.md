# Canonical Program Model

Status: **Stage C design contract.** Production implementation is allowed only after the design gate in this document passes.

This document defines the durable semantic model and repository boundary for Safe Android Reverser. It sits above analyzer-specific indexes and is intended to remain valid through the intended 1.0 architecture.

The model is not a new public database schema, not a raw graph query surface, not a replacement for PEG/EvidenceEnvelope, and not a wrapper around one analyzer. It is the typed semantic vocabulary and query layer used by application maps, context retrieval, data flow, security intelligence, dynamic correlation, native/JNI analysis, additional framework capabilities, and later independent verification.

## 1. Architecture boundary

```text
Public semantic operations
        |
        v
Program Repository / Query Layer
        |
        +-- DEX/JVM provider       -> private static-core SQLite/indexes
        +-- Flutter provider       -> private Flutter SQLite/indexes
        +-- future flow provider   -> private Flow IR/index
        +-- future native provider -> private Rizin/Ghidra/native index
        +-- future runtime provider-> observed dynamic evidence
        |
        v
PEG / EvidenceEnvelope-compatible materialization when evidence is returned
```

One semantic model does **not** require one physical database. Storage/index schemas remain private and may be optimized independently.

The repository exposes semantic entities, relationships, evidence/provenance, bounded traversal, stable ordering, and explicit pagination/truncation. It never exposes arbitrary SQL or analyzer-specific query syntax as the product contract.

### 1.1 Relationship with PEG

PEG remains the shared evidence/interchange graph contract. The Program Model is the canonical typed repository/query view above private indexes.

They are complementary, not competing architectures:

```text
private indexes -> Program Model normalization/query -> bounded PEG/Evidence result
```

Where PEG v2 already has a directly compatible node/edge type, materialization uses it deterministically. Examples include `Class`, `Method`/`DartFunction`, `Endpoint`, `Evidence`, `DECLARES`, `CALLS`, `XREFS`, `READS`, `WRITES`, `FLOWS_TO`, `CONFIRMS`, and `CONTRADICTS`.

Program Model concepts that are not yet directly represented in PEG v2 do not justify a parallel graph. They remain typed repository concepts until an additive PEG evolution is justified. That additive serialization evolution must not change Program Model identity/equality semantics.

## 2. Program Snapshot and identity scope

Every repository view is scoped to one immutable **Program Snapshot** representing one exact top-level artifact.

The provider-neutral snapshot key is conceptually:

```text
pm-snapshot:v1:<artifact_sha256>
```

The snapshot key deliberately excludes:

```text
capability_id
analyzer/provider name
analyzer/provider version
private schema version
image tag/digest
build commit
query limits/truncation
```

Those values are provenance or execution metadata. Replacing an analyzer/provider must not rename otherwise identical semantic entities.

Snapshot metadata may still include:

```text
artifact_sha256
artifact_kind
representations discovered/analyzed
semantic_model_version
capability/producers and versions
analysis limitations
```

One artifact may contribute multiple representations. Representation belongs in representation-specific entity semantic keys, not in the Program Snapshot key. This allows DEX, Flutter and future native providers to refer to the same APPLICATION entity for the same artifact without collapsing representation-specific functions/classes.

The model distinguishes two identity concepts:

1. **entity_id** — deterministic identity inside one exact Program Snapshot. It is stable across repeated analysis of the same artifact when normalized semantic identity is unchanged.
2. **semantic_key** — versioned provider-neutral normalized identity used for deterministic ordering/reconciliation and as input to future cross-version correlation. A semantic-key match across different snapshots is a correlation candidate, not automatic proof of entity equality.

### 2.1 ID format

Entity IDs use a versioned semantic namespace, never a SQLite row ID, analyzer object ID, source line number, insertion order, or producer-specific identifier.

Conceptual form:

```text
pm:v1:<entity-kind>:<sha256(snapshot-key + canonical-semantic-key)>
```

Relationship IDs use:

```text
pmr:v1:<relationship-kind>:<sha256(snapshot-key + kind + source-id + target-id + canonical-discriminator)>
```

Evidence IDs use deterministic bounded provenance locators when available. Concrete encoding is internal, but equality semantics are shared.

Changing private storage, worker image, analyzer revision, or provider implementation must not change semantic IDs when the artifact snapshot and normalized semantic identity are unchanged.

### 2.2 Canonical semantic keys

Semantic keys are versioned, bounded and representation-aware where necessary. Conceptually:

```text
application:v1
class:v1:<representation>:<normalized-class-identity>
function:v1:<representation>:<container-semantic-key>:<normalized-signature>
module:v1:<representation>:<normalized-module-identity>
boundary:v1:<boundary-kind>:<normalized-boundary-identity>
```

A display name alone is never sufficient function identity. Overloads/closures must include enough deterministic signature/container information to avoid collisions. Representation-native addresses/offsets may be used only as a last-resort disambiguator when they are actual artifact facts, never analyzer row IDs.

## 3. Entity kinds

The durable entity-kind set is intentionally broader than Stage C's initial population coverage:

```text
APPLICATION
MODULE
FEATURE
COMPONENT
CLASS
FUNCTION
VALUE
ENDPOINT
STORAGE
EXTERNAL_BOUNDARY
EVIDENCE
```

Stage C implements the type system and populates only structural kinds current DEX/Flutter evidence can support without guessing. Later stages enrich coverage without introducing a competing graph.

### 3.1 APPLICATION

Represents the analyzed application within the Program Snapshot. There is one canonical APPLICATION identity per top-level artifact snapshot.

Observed package/application identifiers, artifact kind, representation summary and ownership model descriptor may be semantic properties. Absence of a package identifier must not prevent the APPLICATION entity.

### 3.2 MODULE

A structural/build/runtime module only when deterministic evidence supports it. Examples include an APK split, a Dart library grouping, or future native/managed module.

Do not invent modules from LLM interpretation.

### 3.3 FEATURE

A higher-level semantic grouping such as authentication or payments only when a deterministic feature producer or later projection has sufficient evidence. Stage C need not populate FEATURE merely to satisfy the type system.

Application Map may project/rank features later; it must not create a second underlying model.

### 3.4 COMPONENT

An application/runtime component with component semantics, for example Android activity/service/receiver/provider or a future equivalent framework component.

A COMPONENT may bind to or declare a CLASS but is not automatically identical to a CLASS.

### 3.5 CLASS

A language/runtime class-like declaration. DEX/JVM classes and Flutter classes normalize to this entity kind while retaining representation in the canonical semantic identity.

### 3.6 FUNCTION

A callable unit such as a DEX method, Flutter function/closure, future native function, managed method, or JavaScript function.

Normalized identity includes representation-appropriate container/signature information. Display names are presentation only.

### 3.7 VALUE

A semantic program value used by the durable Flow IR: parameter, argument, return, local, field, constant, source, sink, sanitizer, transformation, storage value, or future compatible subtype.

Stage C defines the kind but does not fabricate value-flow evidence. Stage F/G populate it.

### 3.8 ENDPOINT

A network/API endpoint or endpoint pattern backed by bounded semantic evidence. Endpoint entities are not equivalent to arbitrary raw strings; lexical candidates remain appropriately qualified evidence until promoted by a semantic producer.

### 3.9 STORAGE

An application storage surface such as preferences, databases, files, secure stores, key stores, caches, or future framework equivalents when evidence supports it.

### 3.10 EXTERNAL_BOUNDARY

A semantic boundary between application reasoning scope and an external implementation/system, including packaged SDK/platform ownership boundaries, unresolved external calls, native bridges, OS/platform APIs, or remote service boundaries.

Third-party implementation can remain queryable, while default application views may collapse it to a boundary without deleting evidence.

### 3.11 EVIDENCE

A graph-addressable semantic evidence/provenance reference when required. Ordinary entity/relationship support may use `evidence_refs` without materializing a separate EVIDENCE node for every observation.

Evidence reuses the existing PEG/EvidenceEnvelope contract and categorical states:

```text
observed
derived
hypothesized
```

The Program Model does not manufacture numeric confidence.

## 4. Common entity contract

Every normalized entity exposes at least:

```text
entity_id
semantic_key
kind
display_name
representation
ownership
properties
evidence_refs
```

Rules:

- `entity_id` is deterministic and snapshot-scoped.
- `semantic_key` is normalized and provider-neutral; backend row IDs are prohibited.
- `kind` is one canonical entity kind.
- `display_name` is presentation only and never drives equality.
- `representation` is a stable semantic value such as `artifact`, `dex`, `flutter-dart-aot`, `native`, `hermes`, `il2cpp`, or a future compatible value.
- `ownership` reuses Stage B `FIRST_PARTY / THIRD_PARTY / PLATFORM / GENERATED / UNKNOWN` where meaningful.
- `properties` contains only bounded **schema-allowlisted semantic properties for that entity kind**.
- `evidence_refs` points to bounded provenance/evidence records.

`properties` is not an escape hatch. Provider/analyzer table columns, raw analyzer JSON, object IDs, SQL fragments, source blobs, arbitrary environment values, and unreviewed backend-specific fields are prohibited from the canonical contract.

Provider-specific facts that are useful only for provenance belong in evidence locators or private storage. A new canonical property must have semantic meaning independent of the current provider.

Unknown ownership remains visible in application-oriented queries according to `docs/CODE_OWNERSHIP.md`.

## 5. Relationship kinds

Initial Stage C structural relationships:

```text
DECLARES
CALLS
XREF
CALLS_EXTERNAL
```

The same relationship model later grows monotonically to include:

```text
READS
WRITES
PASSES_ARGUMENT
RETURNS
TRANSFORMS
FLOWS_TO
SANITIZES
BINDS_TO_NATIVE
CONFIRMS
CONTRADICTS
```

### 5.1 DECLARES

Structural containment/declaration backed by deterministic representation evidence.

Examples:

```text
APPLICATION -> MODULE
APPLICATION -> CLASS        # when no real module evidence exists
MODULE      -> CLASS
CLASS       -> FUNCTION
COMPONENT   -> CLASS
```

Missing intermediate entities are not invented merely to force a hierarchy.

### 5.2 CALLS

An invocation/call edge supported by representation evidence that actually denotes invocation semantics.

CALLS is control/call topology only. It does not prove any value moved between source and target.

### 5.3 XREF

A structural reference where the producer can prove a reference but cannot or should not claim invocation semantics.

Backends never promote generic XREF to CALLS merely for convenience.

Program Model `XREF` maps to PEG v2 `XREFS` when materialized.

### 5.4 CALLS_EXTERNAL

A call crossing an explicit application/external boundary. It may connect a FUNCTION to an EXTERNAL_BOUNDARY while retaining concrete target-function evidence when available.

This is the durable mechanism for collapsing SDK/platform/external internals in application-oriented projections while preserving boundary evidence.

`CALLS_EXTERNAL` is a Program Model semantic relation. Until PEG has a directly matching additive edge type, bounded PEG materialization may retain the underlying `CALLS` plus boundary properties/evidence without inventing a conflicting second graph.

## 6. Common relationship contract

Every normalized relationship exposes at least:

```text
relationship_id
kind
source_entity_id
target_entity_id
representation
properties
evidence_refs
```

Relationship properties follow the same allowlisted-semantic rule as entity properties.

Relationships are deterministic within the Program Snapshot and use stable ordering in query results.

A relationship may have multiple evidence references. Duplicate analyzer observations of the same normalized relationship merge evidence rather than create unstable duplicate semantic edges.

## 7. Evidence and provenance

The repository normalizes evidence locators without copying unlimited analyzer output.

A provenance locator may contain bounded fields such as:

```text
capability_id
producer/analyzer
artifact/member
source_file + line
DEX offset
native address/offset
Flutter source/asm locator
runtime observation id
```

Not every producer supports every locator. Unsupported fields remain absent; the repository never guesses them.

Evidence records reuse PEG/EvidenceEnvelope provenance semantics, including artifact SHA, analysis id, analyzer name/version, state, location and limitations where available.

Raw source/decompiler text remains an explicit later retrieval step. Decompilation is presentation/localization evidence, not canonical truth.

## 8. Ownership integration

Stage B ownership is a first-class semantic property, not a post-query vendor filter.

Repository providers obtain ownership through the shared `CodeOwnershipClassifier` contract or a framework ownership producer that normalizes to the same categories and evidence model.

Application-oriented queries default to:

```text
FIRST_PARTY + UNKNOWN
```

Definite THIRD_PARTY / PLATFORM / GENERATED implementation may be suppressed as roots while direct boundaries remain visible as `CALLS_EXTERNAL` or preserved annotated XREF/CALLS evidence.

No provider may introduce a second vendor-specific skip/filter architecture.

## 9. Repository / Query Layer

The shared query layer is a semantic interface, not a public MCP tool by itself.

Conceptual repository capabilities:

```text
get_entity(entity_id)
find_entities(kind?, text?, ownership_scope?, representation?, page?)
get_relationships(entity_id, kinds?, direction?, ownership_scope?, page?)
expand(entity_id, relationship_kinds?, depth=1, budgets..., cursor?)
get_evidence(evidence_refs, page?)
```

Concrete names may follow project coding conventions, but these semantics are mandatory.

Stage C may migrate existing semantic operations such as symbol/XREF consumers to the repository only where semantics remain equivalent and bounded. A low-level CFG block query may continue to use its private analyzer/index path until the Program Model has a justified canonical basic-block contract; Stage C must not distort the Program Model merely to absorb every old operation.

Stage C must not add public `query_program_model`, `query_sqlite`, Cypher, Gremlin, SQL, generic graph-console, or provider-management operations.

New public Stage C operations are **not required**. Stage D/E introduce durable user-facing semantic operations once their contract is justified.

## 10. Provider contract

Each private index is accessed through a provider/adapter that emits canonical entities, relationships and evidence.

Providers are replaceable evidence producers.

Required current providers:

```text
DexProgramProvider
FlutterProgramProvider
```

Future providers may include:

```text
FlowProgramProvider
NativeProgramProvider
HermesProgramProvider
Il2CppProgramProvider
ManagedProgramProvider
RuntimeEvidenceProvider
```

Provider-specific row/table names, analyzer classes, SQL, Blutter fields, Androguard objects, Ghidra/Rizin concepts, and CI/runtime mechanics remain private.

Providers may exist in different capability workers. The shared Program Model contract/ID rules make their results composable without requiring a common process or shared database. Cross-capability orchestration remains owned by the one host control plane/adapters when a future semantic operation needs it.

A provider never requires network access inside a static analysis worker.

## 11. DEX normalization

The current static-core private index has method/call-edge storage. Stage C normalizes it without making those tables the semantic schema.

Durable mapping direction:

```text
artifact context                -> APPLICATION
DEX owner class                 -> CLASS
DEX method                      -> FUNCTION
class/function containment      -> DECLARES
proven method invocation        -> CALLS
external/SDK/platform crossing  -> CALLS_EXTERNAL + EXTERNAL_BOUNDARY
non-invocation structural ref   -> XREF
```

Current `method.id`, SQLite row identity, and source-fallback line identity are private inputs, not canonical Program Model IDs.

The current DEX builder creates `call_edges` from Androguard method XREF-to observations. `DexProgramProvider` may normalize those edges to CALLS only when the stored producer/kind contract proves they came from invocation semantics. Unknown/future edge kinds default conservatively to XREF rather than being promoted.

Source-fallback evidence must be marked according to what it actually proves; it must not receive DEX-strength invocation semantics unavailable from lexical source indexing.

## 12. Flutter normalization

The current Flutter private index stores libraries, classes, functions, xrefs and strings. Stage C normalizes these without exposing that SQLite schema.

Durable mapping direction:

```text
Flutter artifact                    -> APPLICATION
library                             -> MODULE when structurally meaningful
class                               -> CLASS
function/closure                    -> FUNCTION
library/class/function containment  -> DECLARES
proven invocation                   -> CALLS
structural-only reference           -> XREF
SDK/platform/external crossing      -> CALLS_EXTERNAL + EXTERNAL_BOUNDARY
```

Flutter `xrefs` normalize conservatively to XREF unless the producer contract proves invocation semantics. Stage C does not infer CALLS from target-looking text alone.

Raw strings remain evidence/candidates unless a semantic producer supports promotion to ENDPOINT/VALUE/etc.

## 13. Bounded query semantics

All repository traversal is bounded. Every collection result uses deterministic ordering and explicit page metadata.

Required metadata conceptually includes:

```text
returned_count
total_count      # only when cheaply and accurately known
truncated
has_more
cursor
limits/budget
```

Cursors are opaque semantic continuation tokens. They do not expose raw SQL offsets, filesystem paths, credentials, analyzer commands, mutable process state, or provider handles.

A cursor is bound to snapshot identity, query shape and Program Model version. Replaying it against a different snapshot/query/version fails closed.

Depth, node count, edge count, evidence count, wall-clock and serialized response size are bounded. Stage E adds ranking/context policy; Stage C provides the safe query substrate.

## 14. Determinism, merging and disagreement

For the same Program Snapshot and normalized evidence:

- entity IDs are deterministic;
- relationship IDs are deterministic;
- result ordering is deterministic;
- duplicate semantic entities merge provenance rather than depend on insertion order;
- duplicate relationships merge evidence;
- provider enumeration order does not affect semantic output.

Core identity fields must agree for records to merge. Canonical semantic properties merge only when values are equal or the property has an explicitly reviewed deterministic merge rule.

Conflicting property values are never resolved by last-write-wins. The canonical entity omits/marks the unresolved property as appropriate while preserving distinct supporting evidence. Later `CONFIRMS` / `CONTRADICTS` semantics may make such disagreement graph-addressable.

## 15. Versioning

The canonical semantic contract has internal `PROGRAM_MODEL_VERSION = 1` when implementation is accepted.

This is distinct from:

```text
private DEX SQLite schema
private Flutter SQLite schema
Capability API
Worker ABI
PEG schema
EvidenceEnvelope schema
```

Private index schemas evolve behind providers without changing Program Model semantics.

Adding a new compatible entity/relationship kind, evidence producer, representation, or allowlisted optional semantic property is monotonic evolution. Breaking identity/equality semantics require an explicit architecture decision and senior review.

## 16. Security / trust boundary

Program Model processing stays inside existing static/framework/native-static worker trust boundaries for provider-local work. Cross-capability orchestration, when eventually required, uses existing host adapters/control-plane contracts rather than runtime sockets or worker-to-worker networking.

Mandatory properties remain:

```text
network=none for static/framework/native-static workers
read-only root filesystem
non-root
cap-drop ALL
no-new-privileges
bounded CPU/memory/PIDs/tmpfs
host-owned runtime socket only
bounded artifact/index/source traversal
```

The repository never serializes secrets, CI credentials, registry credentials, runtime tokens, host filesystem absolute paths, or environment dumps into IDs, cursors, properties, evidence, or error messages.

## 17. Stage C implementation scope

Required production work after this design gate:

1. shared canonical entity/relationship/evidence contracts and deterministic ID helpers;
2. shared bounded repository/query abstractions;
3. DEX provider over existing private static-core index;
4. Flutter provider over existing private Flutter semantic index;
5. Stage B ownership normalization in canonical entities/boundaries where current evidence supports it;
6. deterministic pagination/order/merge behavior;
7. regression tests proving private schema/analyzer details do not leak;
8. migrate existing semantic consumers only where behavior is semantically equivalent and bounded;
9. documentation and CI coverage.

Non-goals:

- no Stage D Application Map;
- no Stage E context ranking/retrieval;
- no Stage F/G true data flow;
- no LLM-generated feature graph;
- no generic graph query language;
- no unified physical database requirement;
- no native/Hermes/IL2CPP/.NET implementation yet;
- no dynamic privileges;
- no public backend/provider management operations;
- no forced canonical basic-block/CFG model solely to absorb the old CFG tool.

## 18. Required Stage C tests

At minimum:

- deterministic entity ID across repeated normalization;
- same artifact/application identity across providers;
- IDs unaffected by analyzer/provider version when normalized semantics are unchanged;
- entity ID changes when artifact snapshot genuinely changes;
- semantic key independent of private row IDs;
- overload-safe function identity;
- deterministic relationship ID;
- duplicate entity merge with evidence preservation;
- conflicting semantic properties never last-write-win;
- duplicate relationship merge with evidence preservation;
- stable ordering independent of provider enumeration order;
- bounded pagination and opaque cursor round-trip;
- cursor bound to snapshot/query/model version;
- malformed/foreign cursor rejection;
- allowlisted semantic properties reject backend-specific fields;
- ownership application scope keeps FIRST_PARTY + UNKNOWN;
- definite SDK/platform/generated roots suppressed by default;
- application -> SDK boundary retained;
- DEX method -> canonical FUNCTION;
- DEX proven invocation -> CALLS;
- unknown/non-invocation DEX edge -> XREF;
- source fallback does not invent DEX invocation semantics;
- Flutter library/class/function -> canonical structural entities;
- Flutter xref remains XREF unless invocation is proven;
- private SQLite table/column names absent from semantic results;
- analyzer object IDs absent from semantic IDs/results;
- no arbitrary SQL/public graph-console surface;
- traversal count/depth/evidence/time bounds;
- PEG materialization uses existing compatible Evidence/edge/node semantics without creating a parallel graph;
- static-core worker remains offline;
- framework-flutter worker remains offline;
- MCP discovery remains zero-container;
- one public MCP/plugin invariant remains intact.

## 19. Long-Term Architecture Review — design gate

```text
1. Component expected to survive to 1.0:                 YES
2. Future roadmap extension requires replacement:        NO
3. Knowingly transitional public API introduced:         NO
4. Known schema/data migration already required:          NO
5. Analyzer/provider/storage detail leaked publicly:      NO
6. Temporary production fallback/compatibility path:      NO
7. Technical debt intentionally deferred in architecture: NO
```

Rationale:

- Stage D projects Application Map from this model rather than replacing it.
- Stage E performs bounded context retrieval through this repository rather than inventing a second graph.
- Stage F/G add VALUE and flow relationships to the same vocabulary.
- Stage H and 0.5 security intelligence query the same model.
- 0.6 dynamic analysis contributes runtime evidence and `CONFIRMS`/`CONTRADICTS`.
- 0.7 native/JNI adds compatible native functions/boundaries and `BINDS_TO_NATIVE`.
- 0.8 framework coverage adds providers, not competing models.
- 0.9 pattern discovery and independent verification query the same repository/evidence layer.
- PEG remains the evidence/interchange graph contract; the Program Model is its durable typed query/normalization layer, not a replacement.

**DESIGN VERDICT: PASS.**
