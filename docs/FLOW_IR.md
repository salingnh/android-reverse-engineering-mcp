# Durable Data-flow IR

Stage F defines the long-lived, analyzer-independent data-flow representation for Safe Android Reverser 0.4. It extends the canonical Program Model; it does not create a competing program graph and it does not implement a disposable tracer.

## Architecture

```text
Public semantic operation (Stage G+)
        ↓
Localized analysis planner
        ↓
replaceable evidence producer(s)
        ↓
Durable Flow IR
        ↓
Program Model entity/evidence anchors
```

Potential producers include bounded DEX tracing, SootUp/Jimple, FlowDroid-family analysis, Flutter producers and later native/framework producers. They may be replaced or combined without changing the Flow IR contract.

Stage F deliberately adds **no public MCP operation**. `trace_value`, `find_source_to_sink`, auth and crypto semantics belong to later stages after real flow evidence exists.

## Canonical concepts

### `FlowNode`

A flow node is a value-level semantic overlay anchored to the canonical Program Model snapshot.

Structural `value_kind` values:

```text
PARAMETER
ARGUMENT
RETURN
CONSTANT
LOCAL
FIELD
STORAGE
UNKNOWN
```

Security/semantic roles are orthogonal to structural value kind:

```text
SOURCE
SINK
SANITIZER
TRANSFORMATION
```

For example, a `PARAMETER` can also carry the `SOURCE` role. This avoids inventing incompatible node kinds when later security semantics enrich the same value.

Every node has:

- the canonical Program Model `snapshot_id`;
- a deterministic `node_id` derived from snapshot + semantic identity;
- `owner_entity_id`, normally the containing canonical function;
- optional `program_entity_id` when the value already has a canonical Program Model entity;
- representation, bounded allowlisted properties and evidence references.

Raw constant values are not part of the durable IR. Constant nodes must use a hashed semantic key of the form `constant:<sha256>` and an empty label. A producer may retain only a validated `value_fingerprint` of the form `sha256:<64 lowercase hex>` plus bounded literal/type metadata. This prevents node identity, labels and properties from becoming secret-dump channels.

### `FlowEdge`

Allowed proven flow relations are:

```text
ASSIGNMENT
ARGUMENT_TO_PARAMETER
RETURN_TO_CALLSITE
FIELD_WRITE
FIELD_READ
CONSTANT_TO_VALUE
TRANSFORMS
FLOWS_TO
SANITIZES
```

`CALLS` and `XREF` are intentionally absent. Structural call/xref topology can localize an analysis region, but it is never sufficient proof of value flow.

Each edge is deterministic, snapshot-bound, provenance-bearing and connects two `FlowNode`s. Edge properties are kind-specific and allowlisted. A bounded semantic `discriminator` participates in edge identity so two distinct occurrences such as different statements/callsites connecting the same node pair remain distinct instead of colliding.

### `FlowGap`

Unsupported or intentionally bounded propagation is represented explicitly instead of guessed. Initial durable gap kinds are:

```text
REFLECTION
NATIVE
DYNAMIC_DISPATCH
UNSUPPORTED_INSTRUCTION
EXTERNAL_BOUNDARY
MISSING_EVIDENCE
BUDGET
UNKNOWN
```

A gap may connect two known nodes or terminate at a known source/target boundary. Gap reasons are bounded diagnostic codes/text; they are not synthetic `FLOWS_TO` evidence. Gaps also carry a semantic discriminator so multiple unsupported occurrences across the same endpoints remain independently addressable.

### `FlowPath`

A path is an ordered sequence of node IDs and segment IDs. Every segment is either a real `FlowEdge` or a `FlowGap` joining the adjacent nodes.

A complete path contains only real edges. An incomplete path must contain at least one gap. `complete` is a strict boolean rather than a truthy/coerced value. This makes uncertainty machine-readable and prevents callers from silently treating an unsupported boundary as proven flow.

### `FlowDocument`

`FlowDocument` is a bounded, deterministic transport/normalization envelope for one Program Model snapshot. It validates:

- one snapshot across all records;
- unique IDs;
- all edge endpoints resolve to nodes;
- all path segments resolve and connect the correct adjacent nodes;
- `complete` is consistent with gap presence;
- count and serialized-size limits;
- deterministic ordering on serialization.

It is an IR envelope, not a persistent database or public storage schema.

## Deterministic identity

IDs are versioned and content-derived from the Program Model snapshot plus semantic identity:

```text
flown:v1:...
flowe:v1:...
flowg:v1:...
flowp:v1:...
```

Analyzer-private IDs are not used as public semantic identity. Edge and gap IDs include their bounded semantic discriminator; constant node semantic keys are hash-derived and never include the raw literal.

## Bounds

The IR contract enforces hard in-memory/document limits so a producer cannot return an unbounded graph. Stage G will impose much smaller localized tracing budgets on top of these hard bounds.

Current hard limits:

- nodes: 5,000
- edges: 10,000
- gaps: 2,000
- paths: 1,000
- path nodes: 256
- evidence references per IR record: 128
- serialized `FlowDocument`: 2 MiB

These are safety bounds, not a whole-app tracing target.

## Security and trust boundary

Stage F does not change worker privileges, networking, host/container ownership or persistence. Static-core and framework-flutter images package the same shared IR contract so later producers can normalize into identical semantics while remaining offline and isolated.

The IR never treats backend assertions as canonical merely because they came from one analyzer. Provenance remains attached through evidence references and producer identity; higher-level semantic operations decide what evidence threshold is sufficient.

## Non-goals

Stage F does not:

- implement value tracing;
- infer flow from `CALLS` or `XREF`;
- add FlowDroid/SootUp/Jimple as a public API;
- create a flow SQLite schema;
- add auth/token/signing/crypto heuristics;
- expose raw constant secrets;
- introduce a legacy or host-executed fallback.

## Required regressions

The Stage F gate must prove at least:

1. deterministic IDs and serialization;
2. value-kind/property/role validation;
3. constant literal/identity redaction and strict fingerprints;
4. distinct multi-edge/multi-gap occurrences retain unique IDs;
5. `CALLS` and `XREF` cannot be represented as flow edges;
6. edge endpoints must resolve within the document snapshot;
7. gap-bearing paths cannot claim `complete=true`;
8. complete paths cannot contain a gap;
9. path segments must connect the exact adjacent nodes;
10. snapshot mismatches fail closed;
11. duplicate IDs fail closed;
12. document count and serialized-size bounds fail closed;
13. static-core and Flutter locked images package the same Flow IR version;
14. no public MCP operation is added by Stage F.

## Long-Term Architecture Review

1. Component expected to survive to 1.0: **YES** — value-flow semantics remain required by security, native, dynamic and framework intelligence.
2. Future roadmap extension requires replacement: **NO** — later stages add producers, coverage, evidence and semantic queries over the same IR.
3. Knowingly transitional public API introduced: **NO** — Stage F adds no public MCP operation.
4. Known schema/data migration already required: **NO** — no persistent flow storage schema is introduced.
5. Analyzer/provider/storage detail leaked publicly: **NO** — producers normalize to semantic node/edge/gap/path records.
6. Temporary production fallback/compatibility path: **NO**.
7. Technical debt intentionally deferred in architecture: **NO** — coverage is intentionally incomplete, but the representation is the durable target.

**Design verdict: PASS.**
