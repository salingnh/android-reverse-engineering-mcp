# Canonical Program Model

Status: **Stage C design contract — implementation must not begin until the Long-Term Architecture Review below passes.**

This document defines the durable semantic model and repository boundary for Safe Android Reverser. It sits above analyzer-specific indexes and is intended to remain valid through the intended 1.0 architecture.

The model is not a new public database schema, not a raw graph query surface, and not a wrapper around one analyzer. It is the common semantic vocabulary used by application maps, context retrieval, data flow, security intelligence, dynamic correlation, native/JNI analysis, additional framework capabilities, and later independent verification.

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
```

One semantic model does **not** require one physical database. Storage/index schemas remain private and may be optimized independently.

The repository must expose semantic entities, relationships, evidence/provenance, bounded traversal, stable ordering, and explicit pagination/truncation. It must never expose arbitrary SQL or analyzer-specific query syntax as the product contract.

## 2. Program snapshot and identity scope

Every repository view is scoped to one immutable **Program Snapshot** representing the exact analyzed artifact/representation state.

A Program Snapshot has provider-neutral metadata including:

```text
artifact_sha256
representation
capability_id
analysis_kind
semantic_model_version
producer_versions / provenance
```

`artifact_sha256` is snapshot identity metadata, not the semantic identity of every entity.

The model distinguishes two identity concepts:

1. **entity_id** — deterministic identity inside one exact Program Snapshot. It must be stable across repeated analysis of the same artifact with the same normalized semantic identity.
2. **semantic_key** — provider-neutral normalized identity used for deterministic ordering, reconciliation, and future cross-version correlation where the evidence supports such correlation.

This avoids falsely claiming that two functions from different application builds are the same entity merely because names happen to match.

### 2.1 ID format

Entity IDs use a versioned semantic namespace, never a SQLite row ID, analyzer object ID, source line number, or mutable insertion order.

Conceptual form:

```text
pm:v1:<entity-kind>:<sha256(snapshot-key + canonical-semantic-key)>
```

Relationship IDs use the same rule over:

```text
snapshot-key + relationship-kind + source-entity-id + target-entity-id + canonical-discriminator
```

Evidence IDs use deterministic provenance locators when available. The concrete encoding is private, but equality semantics are part of the shared model contract.

Changing private storage or analyzer implementation must not change semantic IDs when the normalized semantic identity and snapshot are unchanged.

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

Stage C is required to implement the model and populate the structural kinds that current DEX and Flutter evidence can support without guessing. Later stages enrich coverage without introducing a competing graph.

### 3.1 APPLICATION

Represents the analyzed application within the Program Snapshot.

Typical semantic attributes may include package/application identifier when observed, artifact kind, representation summary, and ownership model descriptor. Absence of a package identifier must not prevent creation of the entity.

### 3.2 MODULE

A structural or build/runtime module when there is deterministic evidence for one. Examples can include an APK split, Flutter library grouping, or future native/managed module.

Do not invent modules from LLM interpretation.

### 3.3 FEATURE

A higher-level semantic grouping such as authentication or payments only when a deterministic feature producer or later projection has sufficient evidence. Stage C need not populate FEATURE merely to satisfy the type system.

Application Map may project or rank features later; it must not create a second underlying model.

### 3.4 COMPONENT

Represents an application/runtime component with component semantics, for example Android activity/service/receiver/provider or future equivalent framework component.

A component may reference or declare a CLASS but is not automatically identical to a CLASS.

### 3.5 CLASS

A language/runtime type or class-like declaration. DEX/JVM classes and Flutter classes normalize to this entity kind while preserving representation-specific metadata privately or in bounded semantic attributes.

### 3.6 FUNCTION

A callable unit such as a DEX method, Flutter function/closure, future native function, managed method, or JavaScript function.

The normalized semantic key must include enough representation-appropriate signature information to avoid overload collisions. Display names are not identity.

### 3.7 VALUE

A semantic program value used by the durable Flow IR: parameter, argument, return, local, field, constant, source, sink, sanitizer, transformation, storage value, or future compatible subtype.

Stage C defines the entity kind but does not fabricate value-flow evidence. Stage F/G populate it.

### 3.8 ENDPOINT

A network/API endpoint or endpoint pattern backed by bounded semantic evidence. Endpoint entities are not equivalent to raw strings; lexical candidates require appropriate evidence/provenance and may remain candidate/derived evidence.

### 3.9 STORAGE

A durable abstraction for application storage surfaces such as preferences, databases, files, secure stores, key stores, caches, or future framework equivalents when evidence supports them.

### 3.10 EXTERNAL_BOUNDARY

A semantic boundary between application reasoning scope and an external implementation/system, including packaged SDK/platform ownership boundaries, unresolved external calls, native bridges, OS/platform APIs, or remote service boundaries.

Third-party implementation may remain queryable, but default application views can collapse it to a boundary without deleting evidence.

### 3.11 EVIDENCE

A semantic reference to provenance supporting an entity or relationship. Evidence uses the existing shared Evidence/PEG principles rather than inventing another evidence architecture.

Evidence states remain:

```text
observed
derived
hypothesized
```

The program model must not manufacture numeric confidence.

## 4. Common entity contract

Every normalized entity exposes at least:

```text
entity_id
semantic_key
kind
display_name
representation
ownership
attributes
evidence_refs
```

Rules:

- `entity_id` is deterministic and snapshot-scoped.
- `semantic_key` is normalized and provider-neutral; backend row IDs are prohibited.
- `kind` is one of the canonical entity kinds.
- `display_name` is presentation only and must not drive identity.
- `representation` identifies the semantic representation such as `dex`, `flutter-dart-aot`, `native`, `hermes`, `il2cpp`, or future values.
- `ownership` reuses the Stage B `FIRST_PARTY / THIRD_PARTY / PLATFORM / GENERATED / UNKNOWN` contract where ownership is meaningful.
- `attributes` is bounded semantic metadata, not a dump of analyzer output.
- `evidence_refs` points to bounded provenance/evidence records.

Unknown ownership remains visible in application-oriented queries according to `docs/CODE_OWNERSHIP.md`.

## 5. Relationship kinds

Initial Stage C structural relationships:

```text
DECLARES
CALLS
XREF
CALLS_EXTERNAL
```

The same relationship model must later grow without replacement to include:

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
MODULE      -> CLASS
CLASS       -> FUNCTION
COMPONENT   -> CLASS
```

The exact hierarchy depends on evidence; missing intermediate entities must not be invented.

### 5.2 CALLS

Represents an invocation/call edge supported by instruction/xref/call-target evidence from the representation.

CALLS is control/call topology only. It does not prove any value moved between source and target.

### 5.3 XREF

Represents a structural reference where the backend can prove a reference but cannot or should not claim invocation semantics.

Backends must not promote generic XREF to CALLS merely for convenience.

### 5.4 CALLS_EXTERNAL

Represents a call crossing an explicit external boundary. It may connect a FUNCTION to an EXTERNAL_BOUNDARY and retain the concrete target function/evidence when available.

This is the durable mechanism used to collapse SDK/platform/external internals in application-oriented projections while preserving boundary evidence.

## 6. Common relationship contract

Every normalized relationship exposes at least:

```text
relationship_id
kind
source_entity_id
target_entity_id
representation
attributes
evidence_refs
```

Relationships are deterministic within the Program Snapshot and must use stable ordering in query results.

A relationship may have multiple evidence references. Duplicate analyzer observations of the same normalized relationship should merge evidence rather than create unstable duplicate semantic edges.

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

Not every producer supports every locator. Unsupported fields remain absent; the repository must not guess them.

Raw source/decompiler text remains an explicit later retrieval step. Decompilation is presentation/localization evidence, not canonical truth.

## 8. Ownership integration

Stage B ownership is a first-class semantic property, not a post-query filter.

Repository providers must obtain ownership through the shared `CodeOwnershipClassifier` contract or an equivalent shared framework ownership producer that normalizes to the same categories.

Application-oriented queries default to:

```text
FIRST_PARTY + UNKNOWN
```

Definite THIRD_PARTY / PLATFORM / GENERATED implementation may be suppressed as roots while direct boundaries remain visible as `CALLS_EXTERNAL` or preserved annotated XREF/CALLS evidence.

No provider may add a second vendor-specific skip/filter architecture.

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

Concrete names may follow project coding conventions, but the semantics above are mandatory.

Stage C should migrate existing semantic operations such as symbol/XREF/CFG consumers to use the repository where the repository supports their semantics. It must not add a public `query_program_model`, `query_sqlite`, Cypher, Gremlin, SQL, or generic graph-console operation.

New public Stage C operations are **not required**. Stage D/E add durable user-facing semantic operations once their contract is justified.

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

Provider-specific row/table names, analyzer classes, SQL, Blutter fields, Androguard objects, Ghidra/Rizin concepts, and CI/runtime mechanics are private.

A provider must never require network access inside a static analysis worker.

## 11. DEX normalization

The current static-core private index has method/call-edge storage. Stage C must normalize it without making those tables the semantic schema.

Durable mapping direction:

```text
artifact/application context -> APPLICATION
DEX owner class               -> CLASS
DEX method                    -> FUNCTION
method containment            -> DECLARES
instruction/xref call         -> CALLS
external/SDK/platform call    -> CALLS_EXTERNAL + EXTERNAL_BOUNDARY when applicable
other structural reference    -> XREF
```

Current `method.id`, SQLite row identity, and source fallback line identity are private inputs, not canonical Program Model IDs.

Source-fallback evidence must be marked according to what it actually proves; it must not receive DEX-strength invocation semantics that are unavailable from lexical source indexing.

## 12. Flutter normalization

The current Flutter private index already stores libraries, classes, functions, xrefs and strings. Stage C normalizes these without exposing that SQLite schema.

Durable mapping direction:

```text
Flutter analysis/artifact -> APPLICATION
library                    -> MODULE when structurally meaningful
class                      -> CLASS
function/closure           -> FUNCTION
library/class/function containment -> DECLARES
resolved invocation/xref   -> CALLS when call semantics are supported
structural-only reference  -> XREF
SDK/platform/external crossing -> CALLS_EXTERNAL + EXTERNAL_BOUNDARY
```

Raw strings remain evidence/candidates unless a semantic producer supports promoting them to ENDPOINT/VALUE/etc.

## 13. Bounded query semantics

All repository traversal is bounded. Every collection result uses deterministic ordering and explicit page metadata.

Required response metadata conceptually includes:

```text
returned_count
total_count      # only when cheaply/accurately known
truncated
has_more
cursor
limits/budget
```

Cursors are opaque semantic continuation tokens. They must not expose raw SQL offsets, filesystem paths, credentials, analyzer commands, or mutable process state.

Depth, node count, edge count, evidence count, wall-clock, and serialized response size must be bounded. Stage E may add ranking/context policy; Stage C provides the safe query substrate.

## 14. Determinism and merge semantics

For the same Program Snapshot and normalized evidence:

- entity IDs are deterministic;
- relationship IDs are deterministic;
- result ordering is deterministic;
- duplicate semantic entities merge provenance rather than depend on insertion order;
- duplicate relationships merge evidence;
- provider enumeration order must not affect semantic output.

When two providers disagree, the Program Model preserves distinct evidence and may later represent `CONFIRMS` / `CONTRADICTS`; it does not silently overwrite one producer with another.

## 15. Versioning

The canonical semantic contract has its own internal `PROGRAM_MODEL_VERSION`, starting at `1` when implementation is accepted.

This version is **not** the private DEX SQLite schema, Flutter SQLite schema, Capability API, Worker ABI, PEG schema, or EvidenceEnvelope version.

Private index schemas may evolve behind providers without changing Program Model semantics.

Adding a new entity kind, relationship kind, evidence producer, representation, or optional bounded attribute that follows this contract is expected to be monotonic evolution. A breaking change to identity/equality semantics requires an explicit architecture decision and senior review.

## 16. Security / trust boundary

Program Model processing remains inside the existing static/framework worker trust boundaries unless a future capability explicitly owns a different trust class.

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

The repository must not serialize secrets, CI credentials, registry credentials, runtime tokens, or host filesystem paths into entity IDs, cursors, attributes, evidence, or error messages.

## 17. Stage C implementation scope

Required Stage C production work after design acceptance:

1. shared canonical entity/relationship/evidence contracts and deterministic ID helpers;
2. shared bounded repository/query abstractions;
3. DEX provider over the existing private static-core index;
4. Flutter provider over the existing private Flutter semantic index;
5. Stage B ownership normalization in canonical entities/boundaries;
6. deterministic pagination/order/merge behavior;
7. regression tests proving private schema/analyzer details do not leak;
8. migrate existing semantic consumers only where behavior is semantically equivalent and bounded;
9. documentation and CI coverage.

Non-goals:

- no Stage D Application Map implementation;
- no Stage E context ranking/retrieval implementation;
- no Stage F/G true data-flow implementation;
- no LLM-generated feature graph;
- no generic graph query language;
- no unified physical database requirement;
- no native/Hermes/IL2CPP/.NET implementation yet;
- no dynamic privileges;
- no public backend/provider management operations.

## 18. Required Stage C tests

At minimum:

- deterministic entity ID across repeated normalization;
- entity ID changes when snapshot identity genuinely changes;
- semantic key independent of private row IDs;
- overload-safe function identity;
- deterministic relationship ID;
- duplicate entity merge with evidence preservation;
- duplicate relationship merge with evidence preservation;
- stable ordering independent of provider enumeration order;
- bounded pagination and opaque cursor round-trip;
- malformed/foreign cursor rejection;
- ownership application scope keeps FIRST_PARTY + UNKNOWN;
- definite SDK/platform/generated roots suppressed by default;
- application -> SDK boundary retained;
- DEX method -> canonical FUNCTION;
- DEX call/xref -> correct CALLS/XREF distinction;
- source fallback does not invent DEX invocation semantics;
- Flutter library/class/function -> canonical structural entities;
- Flutter relationship normalization;
- private SQLite table/column names absent from semantic results;
- analyzer object IDs absent from semantic IDs/results;
- no arbitrary SQL/public graph-console surface;
- traversal count/depth/evidence/time bounds;
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
- Stage F/G add VALUE and flow relationships to the same entity/relationship vocabulary.
- Stage H and 0.5 security intelligence query the same model.
- 0.6 dynamic analysis contributes runtime evidence and `CONFIRMS`/`CONTRADICTS` relationships.
- 0.7 native/JNI adds compatible native functions/boundaries and `BINDS_TO_NATIVE`.
- 0.8 framework coverage adds providers, not competing models.
- 0.9 pattern discovery and independent verification query the same repository/evidence layer.

**DESIGN VERDICT: PASS — implementation may begin only if senior review confirms this document does not introduce a known replacement path.**
