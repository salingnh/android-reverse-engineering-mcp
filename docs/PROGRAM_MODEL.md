# Canonical Program Model

Status: **Stage C durable design contract.**

This document defines the canonical semantic model and repository/query boundary for Safe Android Reverser. It is intended to survive through the intended 1.0 architecture and to be enriched by later stages rather than replaced.

The Program Model is:

- a typed semantic normalization/query layer above private analyzer indexes;
- provider-neutral at the semantic contract boundary;
- bounded, deterministic and evidence-preserving;
- compatible with the existing PEG/EvidenceEnvelope architecture;
- not a new public database schema;
- not a raw graph console;
- not a wrapper around one analyzer.

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
        +-- future native provider -> private native index/cache
        +-- future runtime provider-> observed dynamic evidence
        |
        v
bounded PEG / EvidenceEnvelope-compatible materialization
```

One semantic model does **not** imply one physical database. DEX, Flutter, native, flow and runtime stores remain private implementation details.

Storage table names, SQLite row IDs, analyzer objects, SQL, Blutter internals, Androguard objects, runtime handles, worker image identities and CI details never become the public semantic contract.

## 2. Relationship with PEG

PEG remains the shared evidence/interchange graph contract. The Program Model is the typed repository/query view above private indexes.

They are complementary:

```text
private indexes
      -> Program Model normalization/query
            -> bounded PEG/Evidence result where serialization is required
```

The Program Model must not create a competing graph architecture.

Where PEG v2 already has compatible concepts, deterministic materialization reuses them, including `Class`, `Method`/`DartFunction`, `Endpoint`, `Evidence`, `DECLARES`, `CALLS`, `XREFS`, `READS`, `WRITES`, `FLOWS_TO`, `CONFIRMS` and `CONTRADICTS`.

A Program Model concept not yet represented directly by PEG v2 remains a typed repository concept until an additive PEG evolution is justified. PEG serialization changes must not alter Program Model identity/equality semantics.

## 3. Program Snapshot

A **Program Snapshot** identifies one exact artifact payload whose semantic evidence a provider is normalizing.

The provider-neutral snapshot key is:

```text
pm-snapshot:v1:<artifact_sha256>
```

The key deliberately excludes:

```text
capability id
analyzer/provider name
analyzer/provider version
private index/schema version
worker image/tag/digest
build commit
query limits/truncation state
```

Those are provenance/execution metadata, not semantic identity.

### 3.1 Exact-artifact rule

A provider must use the SHA-256 of the artifact it actually analyzed.

Examples:

```text
DEX provider     -> APK/XAPK artifact hash used by the DEX index
Flutter provider -> libapp.so hash recorded by the Flutter semantic index
```

Do **not** pretend a derived child artifact has the same Program Snapshot as its APK/XAPK parent when only the child hash is known.

Therefore two providers can be composed into one `ProgramRepository` only when their Program Snapshot IDs actually match.

Cross-artifact composition requires explicit lineage/correlation evidence, for example:

```text
APK artifact
   |
   +-- CONTAINS / DERIVED_FROM evidence
   |
libapp.so artifact
```

Lineage/correlation is not identity equality. A later orchestration stage may correlate snapshots through explicit evidence without changing the Program Model ID rules.

## 4. Stable semantic identity

The model distinguishes:

1. `entity_id` — deterministic identity inside one exact Program Snapshot;
2. `semantic_key` — versioned provider-neutral normalized semantic identity used for ordering/reconciliation and future correlation.

A semantic-key match between different snapshots is a correlation candidate, not proof that two entities are identical across application versions.

### 4.1 Entity IDs

Conceptual format:

```text
pm:v1:<entity-kind>:sha256(snapshot-key + canonical-semantic-key)
```

Entity IDs must never depend on:

```text
SQLite row id
analyzer object id
source insertion order
worker process state
provider name/version
private schema version
```

### 4.2 Relationship IDs

Conceptual format:

```text
pmr:v1:<relationship-kind>:
  sha256(snapshot-key + kind + source-id + target-id + canonical-discriminator)
```

Duplicate observations of the same normalized relationship merge evidence rather than creating unstable duplicate edges.

### 4.3 Evidence IDs

Evidence references are deterministic from bounded provenance locators when available. Evidence equality is based on semantic provenance, not database insertion order.

## 5. Canonical entity kinds

The long-lived entity vocabulary is:

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

Stage C implements the type system and initially populates only entities current deterministic evidence supports.

### APPLICATION

Represents the analyzed application/artifact semantic root inside one Program Snapshot.

### MODULE

A real structural/runtime module when deterministic evidence exists, such as a Dart library or future split/native/managed module. Do not invent modules solely to force a hierarchy.

### FEATURE

A higher-level semantic grouping only when a deterministic producer supports it. Stage D may project features without creating a second model.

### COMPONENT

An Android/runtime component such as activity/service/receiver/provider or a future equivalent. A component is not automatically identical to its implementation class.

### CLASS

A normalized language/runtime class-like declaration across DEX/JVM, Dart AOT and future representations.

### FUNCTION

A callable unit. Function identity includes enough representation-appropriate container/signature information to avoid overload/closure collisions. Display name alone is never identity.

### VALUE

The durable value entity used by Stage F/G flow semantics. Stage C defines the kind but does not fabricate value flow.

### ENDPOINT

A semantic network/API endpoint or pattern backed by evidence. Arbitrary strings are not automatically endpoints.

### STORAGE

A semantic application storage surface when supported by evidence.

### EXTERNAL_BOUNDARY

A boundary between application reasoning scope and SDK/platform/unresolved/native/remote implementation.

Third-party implementation can remain explicitly queryable while application-oriented views collapse it to a boundary without deleting evidence.

### EVIDENCE

A graph-addressable evidence entity when required. Ordinary entities/relationships may reference evidence without materializing one EVIDENCE node per observation.

## 6. Canonical entity contract

Every entity exposes at least:

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

`ownership` reuses exactly the Stage B contract:

```text
FIRST_PARTY
THIRD_PARTY
PLATFORM
GENERATED
UNKNOWN
```

Default application scope remains:

```text
FIRST_PARTY + UNKNOWN
```

### 6.1 Semantic-property allowlist

`properties` is not a generic JSON escape hatch.

Each entity kind has an allowlist of provider-independent semantic properties. Raw analyzer JSON, SQL columns, row IDs, source blobs, environment variables, worker handles and arbitrary backend fields are prohibited.

Provider-specific facts belong in private storage or bounded evidence provenance.

## 7. Canonical relationship kinds

Initial Stage C structural relationships:

```text
DECLARES
CALLS
XREF
CALLS_EXTERNAL
```

The same model later grows monotonically with:

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

### DECLARES

Deterministic structural containment/declaration.

Examples:

```text
APPLICATION -> CLASS
APPLICATION -> MODULE
MODULE      -> CLASS
CLASS       -> FUNCTION
COMPONENT   -> CLASS
```

Missing intermediate nodes are not invented.

### CALLS

A call/invocation edge only when representation evidence supports invocation semantics.

`CALLS` is topology, not value flow.

### XREF

A structural/reference relationship when invocation semantics are not proven.

A generic XREF must never be promoted to CALLS merely because a target was resolved.

### CALLS_EXTERNAL

A proven call crossing an explicit external boundary. This allows application-oriented projections to collapse SDK/platform implementation while preserving the crossing evidence.

## 8. DEX provider normalization

`DexProgramProvider` reads the private static-core index and normalizes it into the shared contract.

Direction:

```text
artifact context                -> APPLICATION
DEX owner class                 -> CLASS
DEX method                      -> FUNCTION
class/function containment      -> DECLARES
proven invocation               -> CALLS
app -> SDK/platform invocation  -> CALLS_EXTERNAL + EXTERNAL_BOUNDARY
non-invocation reference        -> XREF
```

The existing `methods`/`call_edges` tables remain private.

Current `dex-xref` edges may normalize to `CALLS` only when the stored analysis provenance is the Androguard call-site/XREF-to producer used by the DEX index contract.

Source-fallback/unknown edge kinds remain `XREF`. Source fallback must never receive DEX-strength invocation semantics it did not observe.

## 9. Flutter provider normalization

`FlutterProgramProvider` reads the private Flutter semantic index.

Direction:

```text
libapp.so snapshot              -> APPLICATION
Dart library                    -> MODULE
Dart class                      -> CLASS
Dart function/closure           -> FUNCTION
containment                     -> DECLARES
Blutter xref                    -> XREF
platform crossing               -> EXTERNAL_BOUNDARY
```

Blutter XREF annotations remain `XREF` even when the target resolves uniquely. Target resolution is not sufficient evidence to claim call or value-flow semantics.

Current conservative ownership:

```text
dart:*              -> PLATFORM
package:flutter/*   -> PLATFORM
other package:*     -> UNKNOWN unless stronger evidence exists
```

Do not classify every `package:` URI as third-party: application code and dependencies both use that namespace form.

Raw strings remain lexical evidence/candidates unless a semantic producer justifies promotion to ENDPOINT/VALUE/etc.

## 10. Repository / Query Layer

The repository is an internal semantic interface, not a generic public MCP graph tool.

Durable conceptual capabilities:

```text
get_entity(entity_id)
find_entities(...)
find_relationships(...)
get_evidence(...)
```

Stage C does **not** add public operations such as:

```text
query_program_model
query_sqlite
SQL console
Cypher/Gremlin console
generic graph console
provider-management API
```

Stage D/E introduce user-facing semantic operations only when their contracts are justified.

A CFG/basic-block query may continue using its private analyzer path until a durable basic-block semantic contract is justified; Stage C does not distort the model merely to absorb every legacy tool.

## 11. Provider continuation contract

Repository pagination must remain correct for indexes much larger than one provider page.

Providers therefore expose bounded semantic pages with:

```text
items
has_more
truncated
```

and accept an `after` canonical sort key.

The repository passes its continuation position down to every provider. It must **not** repeatedly request a fixed provider prefix and then apply the cursor only after that prefix, because that loses entities on deeper pages.

Provider pages must be deterministically ordered by canonical entity/relationship sort keys.

Provider continuation is private infrastructure: the public cursor never exposes SQL offsets, row IDs, file paths or mutable process state.

## 12. Bounded query semantics

Every collection response includes explicit concepts equivalent to:

```text
returned_count
total_count        # nullable when not cheap/accurate
truncated
has_more
cursor
limits
```

Hard bounds apply to:

- page size;
- provider page size;
- provider scan rows/edges;
- query text;
- evidence count/size;
- wall-clock time;
- serialized semantic metadata;
- cursor size.

`truncated=true` means a hard analysis/query budget prevented complete evaluation.

`has_more=true` means continuation is required or data may remain because a hard budget was reached.

Normal pagination is not represented as arbitrary JSON truncation.

## 13. Cursor semantics

Cursors are bounded continuation tokens bound to:

```text
Program Model version
Program Snapshot
normalized query shape
last canonical sort key
```

A cursor from another snapshot/query/version is rejected.

The token is an implementation detail; callers must not depend on its encoding.

## 14. Determinism and merge semantics

For the same Program Snapshot and normalized evidence:

- entity IDs are deterministic;
- relationship IDs are deterministic;
- query ordering is deterministic;
- provider enumeration order does not change semantic ordering;
- duplicate semantic entities merge evidence;
- duplicate relationships merge evidence;
- conflicting strong ownership does not silently use last-write-wins;
- conflicting semantic properties are not silently overwritten.

When providers disagree, preserve distinct evidence. Later stages may materialize `CONFIRMS` / `CONTRADICTS`; do not silently erase a producer.

## 15. Security and trust boundary

Stage C does not change the worker trust model.

Static/framework workers remain:

```text
network=none
read-only root
non-root
cap-drop=ALL
no-new-privileges
bounded CPU/memory/PIDs/tmpfs/traversal/output
```

Program providers do not obtain Docker/Podman sockets, network credentials or generic execution surfaces.

Evidence and properties are bounded. Paths/analyzer-specific data remain private unless intentionally represented as bounded provenance.

## 16. Stage C non-goals

Stage C does not implement:

- Application Map projection;
- LLM context ranking;
- true value/data flow;
- auth/token/crypto reasoning;
- dynamic observation;
- native/JNI bridging;
- cross-build identity matching;
- generic public program-model queries;
- a second persistent graph/database.

Those later stages consume or enrich this contract.

## 17. Compatibility with later roadmap stages

```text
Stage D Application Map
    -> projection over ProgramRepository

Stage E Context Retrieval
    -> bounded graph/evidence slices from ProgramRepository

Stage F Flow IR
    -> adds VALUE and flow relationships to same model

Stage G Value Tracing
    -> populates proven flow evidence

Stage H Security Semantics
    -> consumes same entities/relationships/evidence

0.6 Dynamic Correlation
    -> adds runtime CONFIRMS/CONTRADICTS evidence

0.7 Native/JNI
    -> adds native provider + BINDS_TO_NATIVE

0.8 Framework Coverage
    -> adds compatible providers

0.9 Pattern Discovery
    -> queries the same semantic/evidence model
```

No known roadmap stage requires replacement of the Stage C abstraction.

## 18. Long-Term Architecture Review

```text
1. Component expected to survive to 1.0:                 YES
2. Future roadmap extension requires replacement:        NO
3. Knowingly transitional public API introduced:         NO
4. Known schema/data migration already required:          NO
5. Analyzer/provider/storage detail leaked publicly:      NO
6. Temporary production fallback/compatibility path:      NO
7. Technical debt intentionally deferred in architecture: NO
```

Design verdict: **PASS**.

Implementation acceptance still requires unit/regression/integration tests, architecture/security review, dead-reference sweep, exact-head CI, CI-log inspection and senior gate approval before merge.
