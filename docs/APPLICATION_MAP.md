# Canonical Application Map Projection

This document defines the durable Stage D contract for **Application Map** in Safe Android Reverser 0.4.

It extends `docs/PROGRAM_MODEL.md`; it does not replace the Canonical Program Model, PEG/EvidenceEnvelope, ownership semantics, or private analyzer indexes.

All requirements in `ARCHITECTURE_EVOLUTION_RULES.md` apply. Application Map is a deterministic, bounded semantic projection expected to survive through the intended 1.0 architecture.

## 1. Purpose

Agents need a compact first view of an application before requesting detailed context.

Raw symbol/XREF indexes are too large and too storage-oriented. Application Map projects the Canonical Program Model into a small semantic navigation surface:

```text
private DEX / Flutter / future indexes
              |
              v
      ProgramRepository
              |
              v
      ApplicationMapProjector
              |
      +-------+--------+
      |                |
get_application_map  expand_application_node
```

The map is a **projection**, not a new database, graph, cache authority, analyzer output format, or identity namespace.

## 2. Non-negotiable invariants

### 2.1 Program Model remains source of truth

Every projected entity references an existing `ProgramEntity.entity_id` from the Canonical Program Model.

Every projected relationship references an existing `ProgramRelationship.relationship_id` when the relationship is emitted directly. Projection-only aggregation metadata may summarize multiple relationships, but must retain the underlying relationship/evidence references needed for later expansion.

Application Map must never create a second semantic identity system.

### 2.2 No persistent map database

Stage D must not add a separate Application Map SQLite database, graph database, map index, or persisted denormalized source of truth.

A bounded in-process memoization cache is permitted only as an optimization when:

- it is derived entirely from the exact Program Snapshot and query contract;
- losing it changes only performance, never semantics;
- it is not required for entity or relationship re-resolution;
- it has hard memory/lifetime bounds.

No cache is required for Stage D acceptance.

### 2.3 Deterministic without an LLM

The same exact Program Snapshot, Program Model contents, ownership model, projection version, and query parameters must produce the same ordered result.

An LLM may consume the map but must not be required to construct the canonical projection.

### 2.4 Exact-artifact semantics remain unchanged

Application Map inherits the exact-artifact snapshot rule from `docs/PROGRAM_MODEL.md`.

A DEX APK snapshot and a Flutter `libapp.so` snapshot are not silently fused merely because they came from one package. Cross-artifact composition requires explicit lineage/correlation evidence in a later orchestration contract.

Stage D does not weaken this rule.

## 3. Public semantic operations

Stage D introduces two durable semantic operations, subject to the normal trusted-catalog review:

```text
get_application_map
expand_application_node
```

These names describe semantic intent rather than analyzer/backend implementation.

Do not expose operations such as:

```text
query_program_sqlite
build_jadx_map
build_blutter_map
run_application_map_indexer
```

### 3.1 `get_application_map`

Returns a bounded top-level projection for one analyzed Program Snapshot.

Conceptual input:

```text
job_id / artifact context
ownership_scope = application
node_limit
edge_limit
cursor?                 # only when a bounded deterministic continuation is required
```

Normal default ownership scope is `application`, preserving Stage B semantics:

```text
FIRST_PARTY + UNKNOWN
```

Collapsed SDK/platform/generated boundaries remain visible when application code crosses them.

### 3.2 `expand_application_node`

Expands one previously returned Program Model entity ID.

Conceptual input:

```text
job_id / artifact context
entity_id               # canonical Program Model entity ID
ownership_scope = application
direction = both
relationship_kinds?
node_limit
edge_limit
cursor?
```

The operation must re-resolve `entity_id` through `ProgramRepository`; it must not depend on state from a previous `get_application_map` call.

That restart/re-resolution property is mandatory for Application Map just as it is for Stage C external boundaries.

## 4. Projection vocabulary

Application Map uses existing Program Model entity kinds:

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

Stage D initially projects only kinds supported by deterministic current evidence. Missing future kinds are feature-coverage gaps, not reasons to change the architecture.

### 4.1 Projected node

A projected node is a view over a canonical `ProgramEntity`.

Conceptual fields:

```text
entity_id               # canonical Program Model ID
kind
label
display_name
ownership
representation
map_role
importance
expandable
collapsed
properties              # bounded semantic allowlist only
evidence_refs            # bounded
```

`map_role` is projection metadata, not a new entity kind. Initial durable roles may include:

```text
application-root
module
component
entrypoint
important-function
endpoint
storage
external-boundary
```

`importance` is a deterministic projection score used only for bounded ranking. It is not semantic truth and must not leak analyzer-specific confidence internals.

### 4.2 Projected edge

A projected edge references canonical relationship semantics:

```text
relationship_id?        # present for direct ProgramRelationship projection
kind
source_entity_id
target_entity_id
collapsed
relationship_refs       # when one projection edge aggregates bounded canonical relations
evidence_refs
```

Initial relationships come from the Program Model vocabulary, including:

```text
DECLARES
CALLS
XREF
CALLS_EXTERNAL
```

Stage D must never turn `XREF` into `CALLS` or either one into future `FLOWS_TO`.

## 5. Top-level projection policy

The top-level map should normally contain **tens of meaningful nodes**, not thousands.

Recommended normal target:

```text
20-60 nodes
<= 120 edges
```

Hard API bounds must remain configurable private policy constants, not caller-controlled unbounded values.

The default top-level projection should include, when evidence exists:

1. the application root;
2. bounded first-party/unknown modules or structural roots;
3. bounded application classes/components with the strongest deterministic structural/connectivity signal;
4. bounded important application functions;
5. endpoint/storage entities when Stage C or later providers supply them;
6. collapsed external SDK/platform/generated boundaries reached from application code.

It must suppress large third-party implementation subgraphs by default without deleting the application-to-boundary evidence.

## 6. Deterministic importance ranking

Ranking is deterministic policy, not machine-learning inference.

Stage D may use only stable semantic signals available from the Program Model, for example:

```text
entity kind priority
ownership scope priority
number of bounded incoming/outgoing canonical relationships
application-root proximity
external-boundary crossing participation
endpoint/storage participation when those entity kinds exist
stable lexical / entity-id tie break
```

It must not use:

```text
LLM judgment
wall-clock discovery order
SQLite row ids
Python hash randomization
provider insertion order
non-deterministic container iteration
```

The exact weighting is private projection policy but must be versioned with the projection contract and regression-tested for deterministic ordering.

## 7. Collapsing semantics

Collapsing changes presentation, not truth.

### 7.1 External SDK/platform/generated code

Default map:

```text
App Function
     |
CALLS_EXTERNAL / XREF
     v
[External Boundary]
```

Do not emit thousands of implementation nodes behind the boundary.

Explicit expansion with an ownership scope such as `third_party`, `platform`, `generated`, or `all` may expose the underlying Program Model entities when available.

### 7.2 Structural collapse

When a class/module contains many low-signal functions, the top-level map may emit the structural node plus a bounded summary count rather than every child.

Expansion must retrieve children from `ProgramRepository`; the summary is never an alternate child index.

## 8. Progressive expansion

Expansion is semantic navigation:

```text
Application Map
    -> selected node
        -> bounded neighboring entities/relationships
            -> later Stage E context retrieval
```

`expand_application_node` must support deterministic pagination/continuation using Program Repository continuation semantics.

Expansion result metadata must include at least:

```text
returned_nodes
returned_edges
has_more
truncated
cursor / continuation when applicable
projection_version
snapshot_id
```

No structured JSON may be cut at an arbitrary character boundary.

## 9. Budgets and resource safety

Application Map is intentionally bounded.

Private hard ceilings must exist for:

```text
nodes per response
edges per response
canonical relationship scans
provider/repository pages consumed
wall-clock projection time
evidence refs per node/edge
semantic property bytes
cursor bytes
serialized response bytes
```

Recommended normal response target remains <=64 KiB. Stage D should remain comfortably below the Stage E hard semantic target of <=256 KiB.

If a hard budget is reached, return structured `truncated=true` and continuation metadata where meaningful. Never silently pretend the map is complete.

## 10. Evidence and provenance

Projected nodes and edges retain bounded canonical evidence references.

The map must make it possible for a later operation to answer:

```text
Why is this node present?
Why is this boundary connected?
Which canonical relationship justified this edge?
Which exact artifact snapshot produced this projection?
```

Projection ranking itself is not evidence. Evidence always comes from Program Model / PEG-compatible provenance.

## 11. Security and trust boundary

Stage D does not change the worker sandbox:

```text
network=none
read-only root
non-root
cap-drop ALL
no-new-privileges
bounded CPU/memory/PIDs/tmpfs
```

No runtime socket is exposed to workers.

Map operations are semantic worker operations; host `initialize` and `tools/list` remain zero-container/host-local.

No arbitrary SQL/Cypher/index query enters the public MCP surface.

## 12. Testing requirements

Before Stage D may pass, tests must cover at least:

1. deterministic map output across repeated provider/repository construction;
2. top-level node and edge hard bounds;
3. stable ordering independent of insertion order;
4. default application scope suppresses SDK implementation noise;
5. application-to-SDK/platform boundary remains present;
6. explicit ownership scope can expand external implementation when available;
7. `expand_application_node` works after process/provider reconstruction;
8. unknown/obfuscated application code is not silently discarded;
9. XREF remains XREF and is never promoted to CALLS/FLOWS_TO;
10. truncation and continuation are explicit and deterministic;
11. no private SQLite row/analyzer IDs leak into output;
12. no new database/index/cache authority is created;
13. response serialization remains within semantic bounds;
14. zero-container MCP discovery and sandbox regressions remain green;
15. both DEX and Flutter Program Model projections pass where the current exact-artifact provider supports them.

A large-noise fixture should demonstrate that hundreds/thousands of SDK symbols do not starve meaningful application nodes from the bounded top-level map.

## 13. Initial acceptance scenario

### Native/DEX fixture

Expected map shape:

```text
Application
  -> first-party application class/component
      -> important function
          -> [Firebase/Facebook/etc. boundary]
```

The map remains bounded even with a large SDK fixture.

### Flutter fixture

Expected map shape for one exact `libapp.so` Program Snapshot:

```text
Flutter application artifact
  -> package: application module
      -> application class
          -> application function
              -> [Dart / Flutter platform boundary]
```

Do not combine this snapshot with a parent APK snapshot unless explicit lineage evidence exists.

## 14. Non-goals for Stage D

Do not implement:

- Stage E source/context ranking;
- Stage F data-flow IR;
- Stage G value tracing;
- Stage H auth/crypto flow inference;
- whole-program feature clustering requiring an LLM;
- a persisted map database;
- a generic graph query language;
- cross-artifact identity fusion without lineage evidence.

## 15. Long-Term Architecture Review

Stage D implementation may start only if this design evaluates as:

```text
1. Component expected to survive to intended 1.0:        YES
2. Future roadmap extension requires replacement:         NO
3. Knowingly transitional public API introduced:          NO
4. Known schema/data migration already required:           NO
5. Analyzer/provider/storage detail leaked publicly:       NO
6. Temporary production fallback/compatibility path:       NO
7. Technical debt intentionally deferred in architecture: NO
```

If any answer differs, Stage D is BLOCKED before implementation.
