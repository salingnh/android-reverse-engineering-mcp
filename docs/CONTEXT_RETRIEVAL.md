# Intelligent Context Retrieval

Status: **Stage E durable design contract.**

This document defines progressive semantic context retrieval for Safe Android Reverser 0.4. It extends the Canonical Program Model and Application Map; it does not create a second semantic model, graph, index, source-of-truth cache, or analyzer-specific public API.

## 1. Purpose

Agents should move from a bounded application map to a bounded function-centric context slice without requesting a full decompile or arbitrary graph dump:

```text
Application Map
      ↓
selected canonical function
      ↓
ContextRetriever
      ↓
ProgramRepository neighborhood
      + bounded evidence
      + bounded source/presentation slice when available
      ↓
agent
```

Context retrieval is deterministic infrastructure. An LLM may select which canonical entity to inspect, but an LLM is not required to construct the canonical context response.

## 2. Source of truth

`ProgramRepository` remains the semantic source of truth. `ContextRetriever` consumes canonical `ProgramEntity`, `ProgramRelationship`, and evidence references.

A private source-slice provider may add a bounded presentation slice for an entity using source/provenance locators. Source text is presentation/localization evidence, not canonical semantic truth.

Do not add:

- a context SQLite database;
- a persisted context graph;
- a vector store as canonical truth;
- raw SQL/Cypher/Gremlin;
- analyzer-specific public retrieval operations;
- arbitrary JSON/text truncation.

A future embedding/ranking implementation may propose candidate entities behind the same semantic contract, but deterministic canonical retrieval and provenance remain authoritative.

## 3. Public semantic operation

Stage E adds one durable public operation:

```text
get_function_context
```

It is owned by the host control-plane semantic catalog and routes by the same public analysis locator as Application Map:

```text
job_id
representation = dex | flutter-dart-aot
```

`capability_id`, analyzer names, SQLite tables, worker image names and private paths are not public routing inputs.

Conceptual input:

```text
job_id
representation
entity_id                 # canonical FUNCTION entity id
ownership_scope=application
direction=both
relationship_kinds?       # bounded structural topology only
relationship_limit
source_line_limit
source_byte_limit
response_budget_bytes
cursor?
```

The operation re-resolves `entity_id` through `ProgramRepository`; it must not depend on a prior Application Map or prior process state.

## 4. Canonical response

A function context response contains only bounded semantic views:

```text
context_retrieval_version
program_model_version
snapshot_id
artifact_sha256
ownership_scope
root
structural_context
neighbors
relationships
evidence
source_slices
returned_* counts
has_more
truncated
cursor
limits
warnings
```

### Root

`root` is the canonical function entity. Stage E rejects non-`FUNCTION` roots instead of silently changing semantics.

### Structural context

A small bounded parent slice may include canonical `DECLARES` parents such as CLASS/MODULE/APPLICATION when available. These are ordinary Program Model entities/relationships, not invented context nodes.

### Neighborhood

Default structural relationships are:

```text
CALLS
CALLS_EXTERNAL
XREF
```

They remain topology only. Stage E must never emit `FLOWS_TO` or imply value propagation from CALLS/XREF.

### Evidence

Evidence is resolved from canonical evidence references and remains bounded. Missing evidence is reported explicitly rather than synthesized.

### Source slice

A source slice is optional bounded presentation evidence. It contains a safe relative locator, line range, representation/source kind, text, and truncation metadata when available.

The source provider must:

- resolve only beneath the capability-owned analysis job/output root;
- reject symlinks/resolved escape;
- bound file size, lines, bytes and number of slices;
- never return host absolute paths;
- return explicit `unavailable`/`not-localized` state when provenance cannot identify a safe local source.

For DEX/JVM the provider may use bounded JADX/Vineflower source localization. For Flutter it may use bounded Blutter-generated semantic/source artifacts. These are private producer details and do not alter the public context schema.

## 5. Ownership semantics

Stage B ownership is reused exactly:

```text
FIRST_PARTY
THIRD_PARTY
PLATFORM
GENERATED
UNKNOWN
```

Default `application` scope remains `FIRST_PARTY + UNKNOWN` while collapsed `EXTERNAL_BOUNDARY` entities remain visible when canonical crossing evidence exists.

Direct third-party/platform/generated implementation functions are not valid default application roots. Explicit ownership scope may retrieve them when the Program Model exposes them.

No second SDK filter is introduced.

## 6. Pagination and continuation

Context pagination is relationship-page continuation over the canonical Program Repository.

A response cursor is bound to the Program Snapshot and normalized repository query. It remains opaque to callers.

Critical invariant:

> A returned cursor may advance only past canonical relationships actually represented by that response.

If a fully materialized context page does not fit the response budget, retry the same incoming cursor with a smaller repository page. Never consume a larger page, drop entries, and return its advanced cursor.

Scope-filtered relationships are not silently represented as delivered context. The response records filtering warnings and the continuation remains aligned with the consumed canonical repository page contract.

## 7. Budgets

Normal response target:

```text
<= 64 KiB
```

Hard semantic response ceiling:

```text
<= 256 KiB
```

Private hard bounds also cover:

- relationship page size;
- structural-parent relationships;
- resolved entities;
- evidence refs/items;
- source slices;
- source lines and bytes;
- source-file size;
- cursor bytes;
- wall-clock time;
- serialized response bytes.

A caller may request a response budget only within the documented hard range. Increasing future model context windows changes policy/budgets, not architecture.

Structured JSON is never cut at an arbitrary character boundary.

## 8. Determinism

For the same exact Program Snapshot and normalized query:

- root identity is deterministic;
- structural parent ordering is canonical;
- relationship ordering follows Program Repository ordering;
- evidence ordering is deterministic;
- source slices are chosen from deterministic bounded provenance locators;
- provider insertion order, SQLite row IDs and Python hash order do not affect semantics.

## 9. Trust boundary

Stage E does not change worker privileges:

```text
network=none
read-only root
non-root
cap-drop=ALL
no-new-privileges
bounded CPU/memory/PIDs/tmpfs/traversal/output
```

Only the host Runtime Driver invokes Docker/Podman. Workers receive no runtime socket.

`initialize` and `tools/list` remain host-local/zero-container.

## 10. Relationship to later stages

```text
Stage E Context Retrieval
    -> localizes canonical entities/topology/evidence

Stage F Flow IR
    -> adds durable VALUE/flow vocabulary

Stage G Value Tracing
    -> produces proven localized flow evidence

Stage H Auth/Crypto Semantics
    -> consumes Program Model + Flow IR + bounded context
```

Stage F/G/H extend the same model. They do not replace ContextRetriever with a backend-specific taint or grep architecture.

## 11. Stage E non-goals

Stage E does not implement:

- data-flow IR;
- value tracing;
- source-to-sink inference;
- auth/token/signing/crypto conclusions;
- whole-app taint;
- embeddings/vector search as canonical truth;
- generic decompiler/source dump API;
- cross-artifact snapshot fusion.

## 12. Required tests

Before Stage E can pass, tests must cover at least:

1. deterministic repeated retrieval;
2. exact function re-resolution after provider reconstruction;
3. non-function root rejection;
4. default ownership scope and external-boundary preservation;
5. CALLS/XREF remain structural, never `FLOWS_TO`;
6. explicit relationship pagination with no skip/duplication;
7. response-size retry keeps cursor aligned with returned relationships;
8. normal response <=64 KiB under normal fixtures;
9. hard response <=256 KiB under large fixtures;
10. source path escape/symlink rejection;
11. source line/byte/file-size bounds;
12. DEX provider integration;
13. Flutter provider integration;
14. host semantic routing and zero-container discovery;
15. no capability manifest publicly owns `get_function_context`;
16. worker images contain the shared retrieval contract and private provider hook.

## 13. Long-Term Architecture Review

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

Implementation acceptance still requires tests, architecture/security review, Blocker/High remediation, dead-reference sweep, exact-head CI/log inspection and senior acceptance before merge.
