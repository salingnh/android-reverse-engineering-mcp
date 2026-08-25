# Architecture Evolution Rules

This document defines a mandatory architecture rule for Safe Android Reverser:

> **Do not merge temporary architecture. Every accepted production mechanism must be a durable building block of the intended long-term platform and must be extensible without planned replacement.**

This rule applies to humans and coding agents. It applies to code, public MCP operations, schemas, indexes, storage abstractions, runtime orchestration, capability boundaries, CI/release workflows, and evidence models.

The project may intentionally ship **incomplete feature coverage**. It must not intentionally ship an **architectural direction already expected to be discarded or fundamentally replaced**.

## 1. Required evolution model

Allowed evolution:

```text
stable foundation
      ↓
additional semantics
      ↓
additional evidence producers
      ↓
additional capabilities
      ↓
stronger analysis
```

Not allowed:

```text
temporary production mechanism
      ↓
known replacement later
      ↓
migration/rewrite
      ↓
new architecture
```

A later milestone should normally enrich or extend an earlier abstraction rather than invalidate it.

## 2. Mandatory pre-implementation questions

Before implementing any non-trivial stage, PR, public operation, schema, storage model, runtime mechanism, or orchestration path, answer:

1. Is this component expected to remain valid in the intended 1.0 architecture?
2. Can later roadmap milestones extend it without replacing its core abstraction?
3. Does it expose a public contract that is already expected to change?
4. Is it solving the durable abstraction or only the current analyzer/use case?
5. Does another known roadmap milestone require a different model?
6. Does the design intentionally introduce technical debt to move faster?
7. Is analyzer/provider/storage implementation detail leaking into the public semantic contract?
8. Is a temporary compatibility/fallback path being introduced into production behavior?

If the design knowingly requires future replacement, the implementation is **BLOCKED** until redesigned.

## 3. Public semantic contract rule

Do not expose public MCP operations merely because they are convenient for the current backend.

Prefer durable semantic operations, for example:

```text
get_application_map
expand_application_node
get_function_context
trace_value
find_source_to_sink
find_auth_flow
trace_crypto
```

Do not make backend-specific operations the product contract, for example:

```text
run_flowdroid
run_soot
run_blutter_command
run_ghidra_console
query_sqlite_index
```

Analyzers are replaceable evidence producers. Semantic operations are the durable product interface.

## 4. Program model rule

Do not create a separate competing graph/data model for each milestone.

The program-understanding model must evolve monotonically.

Target conceptual entities include:

```text
Application
Module / Feature
Component / Class
Function
Value
Endpoint
Storage
External Boundary
Evidence
```

Relationships may progressively grow from:

```text
DECLARES
CALLS
XREF
```

toward:

```text
READS
WRITES
PASSES_ARGUMENT
RETURNS
TRANSFORMS
FLOWS_TO
SANITIZES
CALLS_EXTERNAL
BINDS_TO_NATIVE
CONFIRMS
CONTRADICTS
```

0.5 Security Intelligence must consume the same semantic/evidence model created in 0.4.

0.6 Dynamic Correlation must add observed runtime evidence to the same model rather than creating a second evidence architecture.

0.7 Native/JNI Intelligence must bridge native nodes into the same model.

0.8 framework capabilities must produce compatible semantic evidence.

0.9 pattern discovery must query the same model.

## 5. Storage/index rule

Optimized storage is private implementation detail.

Examples:

```text
SQLite program index
Flutter SQLite index
future IR cache
Rizin/Ghidra cache
Hermes index
IL2CPP index
```

MCP behavior must not depend on a public SQLite schema or raw storage query interface.

Use a separation equivalent to:

```text
Semantic Contract
      ↓
Repository / Query Layer
      ↓
Private storage/index implementation
```

A future storage optimization must be possible without changing the meaning of public semantic operations.

## 6. Analyzer/backend rule

Never design the platform around one analyzer.

Potential backends such as JADX, Androguard, Blutter, SootUp, FlowDroid, Rizin, Ghidra, Semgrep, or future replacements are evidence producers.

Use the durable direction:

```text
Semantic Operation
       ↓
Analysis Planner
       ↓
Analyzer Backend(s)
       ↓
Normalized Evidence / Program Model
```

A backend may later be upgraded, replaced, supplemented, or independently verified without replacing the semantic operation or evidence architecture.

## 7. Runtime-cache rule

Runtime-cache architecture must be provider-independent.

Do not hard-code Flutter analysis directly to GitHub Actions.

Use durable abstractions such as:

```text
RuntimeCacheResolver
ControlledBuildProvider
```

A provider may be:

```text
GitHub Actions
self-hosted builder
Jenkins/enterprise CI
prebuilt cache service
```

Runtime identity, state transitions, provenance verification, deduplication, and immutable image semantics remain provider-independent.

The deterministic request identity names one exact runtime cache and remains
stable across retries. Each controlled build retry has a distinct, private,
provider-neutral build-attempt identity with persisted time bounds. Providers
translate that attempt metadata into their own run model so reconciliation can
select the current attempt instead of a historical run. Build-attempt and
provider-handle details are never part of the public MCP contract.

Analysis workers remain offline. A cache miss must never justify network/build privileges inside an untrusted analysis worker.

## 8. Code ownership rule

Third-party suppression is not implemented as scattered package-name filtering.

Ownership classification belongs in the general program model, with categories such as:

```text
FIRST_PARTY
THIRD_PARTY
PLATFORM
GENERATED
UNKNOWN
```

Optional metadata may include:

```text
owner
sdk
classification_reason
classification_evidence
relevance
```

SDK registries are rules/data, not architecture.

Program index, application map, network model, context retrieval, data-flow, and security analysis must consume the same ownership classification.

Third-party implementations may be collapsed by default, but application-to-SDK boundaries must remain visible and queryable.

## 9. Context/retrieval rule

Do not solve LLM context pressure with arbitrary truncation as the primary design.

The durable retrieval model is progressive semantic retrieval:

```text
Application Map
      ↓
Relevant Module / Feature
      ↓
Relevant Functions
      ↓
Relevant Graph Slice
      ↓
Bounded Evidence / Source Slice
```

Budgets, pagination, ranking, and continuation are policies/infrastructure around this model.

A larger future model context window should increase budgets, not require a new retrieval architecture.

Structured results must expose truncation/pagination explicitly rather than cutting JSON at an arbitrary byte boundary.

## 10. Data-flow rule

Do not implement a disposable "basic data flow" that is knowingly expected to be replaced by a later real engine.

Define the durable flow IR first, then increase coverage incrementally.

Examples of durable concepts:

```text
parameter
argument
return
constant
assignment
field read
field write
transformation
source
sink
sanitizer
flow gap
```

Potential producers may include custom bounded DEX tracing, SootUp/Jimple, FlowDroid-family analysis, Flutter-specific producers, and later native/framework producers.

All producers must normalize into the same durable flow model.

CALLS/XREFS remain distinct from proven data flow.

## 11. Compatibility and fallback rule

Do not add a temporary production fallback merely to preserve an old implementation path that the product direction has rejected.

Compatibility is acceptable only when it is an intentional long-term supported contract with explicit ownership, tests, and migration policy.

The removed legacy `android-reverse-engineering` host-executed model must not return as a fallback.

## 12. PR and stage acceptance gate

Every non-trivial PR/stage must include a **Long-Term Architecture Review** with the following questions:

```text
1. Component expected to survive to 1.0:                 YES / NO
2. Future roadmap extension requires replacement:        YES / NO
3. Knowingly transitional public API introduced:         YES / NO
4. Known schema/data migration already required:          YES / NO
5. Analyzer/provider/storage detail leaked publicly:      YES / NO
6. Temporary production fallback/compatibility path:      YES / NO
7. Technical debt intentionally deferred in architecture: YES / NO
```

Required result:

```text
1 = YES
2 = NO
3 = NO
4 = NO
5 = NO
6 = NO
7 = NO
```

Otherwise:

```text
VERDICT = BLOCKED
```

Do not proceed to the next stage and do not merge until the design is corrected or a deliberate breaking architecture decision is documented and approved.

## 13. Stage-gated development rule

Each roadmap slice must stop after its own implementation and validation gate.

Required sequence:

```text
implementation
   ↓
unit/regression tests
   ↓
integration tests
   ↓
architecture/security review
   ↓
fix Blocker + High
   ↓
dead-reference/code sweep
   ↓
exact-head CI
   ↓
Long-Term Architecture Review
   ↓
senior acceptance
   ↓
merge
```

Do not start the next stage merely because the current code appears to work locally.

Exact-head CI means the CI result must belong to the exact commit under review.

## 14. Practical review heuristic

Before merge, ask:

> If tomorrow we replace or supplement Androguard, upgrade Blutter, move the controlled builder from GitHub Actions to Jenkins/self-hosted CI, add Hermes/IL2CPP/.NET/native/dynamic capabilities, and increase the LLM context budget by 10x, does this PR's abstraction still belong in the same architectural location?

Good answer:

> Yes. The same abstraction/contract remains; only producers, backends, edge types, capabilities, ranking, or policy are extended.

Bad answer:

> No. We would remove this implementation and replace the architecture.

A bad answer blocks merge.

## 15. Relationship to existing project rules

This document strengthens and operationalizes the existing project decision that roadmap milestones must not intentionally introduce mechanisms expected to be replaced later.

It does not weaken any rule in:

- `PROJECT_DIRECTION.md`
- `CAPABILITY_SPI.md`
- `DEVELOPMENT.md`
- `ROADMAP.md`
- `RELEASING.md`

When there is uncertainty, prefer the design that preserves stable semantic contracts, shared evidence, capability isolation, offline analysis, and monotonic extension toward 1.0.
