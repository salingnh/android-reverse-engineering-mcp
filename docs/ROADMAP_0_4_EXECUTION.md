# Safe Android Reverser 0.4 Execution Plan

This document is the durable, stage-gated execution plan for milestone **0.4.0 — Data-flow Intelligence**. It refines `ROADMAP.md`; it does not replace the release train or the long-term architecture in `PROJECT_DIRECTION.md`.

All work here is governed by `ARCHITECTURE_EVOLUTION_RULES.md`: feature coverage may be incomplete, but accepted production architecture must not knowingly be temporary or planned for replacement.

Current production baseline: **0.3.1**.

## Execution discipline

Implement exactly one stage at a time:

```text
design
  -> Long-Term Architecture Review
  -> implementation
  -> unit/regression tests
  -> integration tests
  -> architecture/security review
  -> fix Blocker/High
  -> dead-reference sweep
  -> exact-head CI
  -> inspect real CI logs
  -> Gate Report
  -> STOP for senior acceptance
```

Do not begin the next stage automatically. Exact-head means the exact commit under review; an older green run is not sufficient.

A stage is blocked unless the required Long-Term Architecture Review result is:

```text
component survives to intended 1.0 architecture          YES
future roadmap requires replacement                       NO
knowingly transitional public API                         NO
known required schema/data migration                      NO
analyzer/provider/storage detail leaked publicly          NO
temporary production fallback/compatibility path          NO
intentional architecture debt deferred                    NO
```

## Stage 0 — Baseline and Architecture Audit

Purpose: prove the current platform baseline before adding 0.4 features.

Required checks include:

- one public plugin and one public MCP;
- no legacy host-executed fallback;
- `initialize` and `tools/list` work without worker/container startup;
- `health` and `list_capabilities` work;
- static-core and framework-flutter readiness;
- Docker/Podman stays host-owned;
- worker sandbox remains `network=none`, read-only root, non-root, cap-drop ALL, no-new-privileges, bounded resources;
- `/data/jobs` is writable by the actual worker identity;
- path/archive/job negative tests fail safely;
- no leaked worker process/container/temp state;
- single-plugin and release-consistency guards pass;
- all relevant static-core, Flutter, control-plane unit/regression/integration suites pass;
- exact-head GitHub CI is run and inspected.

A user/private APK/XAPK is optional validation evidence and must not be committed. Absence of a real proprietary artifact is not by itself a baseline blocker when deterministic fixtures and platform E2E tests pass.

No Compose file is required by this architecture. Worker lifecycle is owned by the Host Runtime Driver; introducing a parallel Compose lifecycle merely for validation is not an acceptance criterion.

## Stage A — Runtime Cache Resolver + Controlled Build Provider

Problem: exact Flutter AOT runtime cache misses currently require manual CI action.

Durable architecture:

```text
Flutter capability
      -> RuntimeCacheResolver
            -> ControlledBuildProvider
                  -> GitHub Actions provider
                  -> future self-hosted/enterprise provider
```

GitHub Actions is one provider, not the semantic architecture.

Runtime identity remains exact and immutable, including Dart version, snapshot hash, architecture, OS, compressed-pointer mode, pinned analyzer revision, private cache schema, Capability API and Worker ABI.

Durable states: `READY`, `BUILD_REQUIRED`, `BUILDING`, `FAILED`.

Required behavior:

- exact cache lookup and immutable provenance verification;
- provider-independent build request/status abstraction;
- a deterministic request identity for the exact cache plus a distinct,
  persisted, private provider-neutral identity for each genuine build attempt;
- reconcile only the current attempt, never a historical retry, and deduplicate
  concurrent requests for one identity across threads and processes;
- timeout/failure/resume behavior;
- never put builder credentials in worker environment, job metadata, MCP result or evidence;
- analysis workers remain offline and never build/download runtime dependencies.

Gate branch: `feat/0.4-runtime-cache-resolver`.

## Stage B — Canonical Code Ownership

Introduce one durable ownership classification consumed by all semantic queries:

```text
FIRST_PARTY
THIRD_PARTY
PLATFORM
GENERATED
UNKNOWN
```

Metadata may include owner/SDK, reason, evidence and relevance.

Use a `CodeOwnershipClassifier` abstraction and multiple evidence sources: manifest/application namespace/components, resources/BuildConfig, entrypoints/reachability, known SDK/platform/generated patterns and source/index evidence.

Known SDK rules are data, not architecture. Do not scatter Firebase/Facebook-specific `skip` conditions through tools. Do not assume short/obfuscated namespaces are third-party.

Third-party internals are collapsed by default but application-to-SDK boundary calls remain queryable.

Gate branch: `feat/0.4-code-ownership`.

## Stage C — Canonical Program Model / Query Layer

Create the durable semantic model above private analyzer indexes.

Conceptual entities must be able to grow through 1.0:

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

Initial structural relationships include `DECLARES`, `CALLS`, `XREF`, `CALLS_EXTERNAL`. Later stages enrich the same model with `READS`, `WRITES`, `PASSES_ARGUMENT`, `RETURNS`, `TRANSFORMS`, `FLOWS_TO`, `SANITIZES`, `BINDS_TO_NATIVE`.

Architecture boundary:

```text
Public semantic contract
        -> Program Repository / Query Layer
              -> private DEX SQLite
              -> private Flutter SQLite
              -> future data-flow/native/framework indexes
```

Storage tables are never the public MCP contract. One semantic model does not require one physical database.

Gate branch: `feat/0.4-program-model`.

## Stage D — Application Map Projection

`Application Map` is a bounded projection of the canonical program model, not another graph/database.

Durable semantic operations should provide top-level map and progressive expansion, e.g. `get_application_map` and `expand_application_node` if those names pass contract review.

Top-level output should normally contain tens of meaningful nodes, not thousands. It should surface business features/components/functions/endpoints/auth signals and collapsed external SDK boundaries with provenance and truncation metadata.

Map generation must be deterministic. LLM reasoning may consume the map; analyzer workers must not require an LLM to build the canonical projection.

Gate branch: `feat/0.4-application-map`.

## Stage E — Intelligent Context Retrieval

Context management is progressive semantic retrieval, not arbitrary text truncation:

```text
Application Map
  -> relevant feature
  -> relevant functions
  -> bounded graph slice
  -> localized evidence/source slice
  -> agent
```

Candidate durable operations include `get_function_context` and bounded call-path expansion.

Structured responses must use explicit budget/pagination fields such as returned count, total count where known, `truncated`, `has_more`, and cursor/continuation where appropriate. Do not cut structured JSON at arbitrary character positions.

Recommended normal semantic response target: <=64 KiB; hard semantic operation target: <=256 KiB, leaving host MCP hard bounds as emergency protection rather than the normal retrieval mechanism.

Gate branch: `feat/0.4-context-retrieval`.

## Stage F — Durable Data-flow IR

Define the long-lived data-flow representation before implementing a particular analyzer backend.

Durable concepts:

```text
FlowNode
FlowEdge
FlowPath
FlowGap
```

Value semantics cover parameter, argument, return, constant, local, field, source, sink, sanitizer, transformation and storage values.

Flow relationships can include:

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

`CALLS`/`XREF` remain distinct from `FLOWS_TO`.

Custom DEX tracing, SootUp/Jimple, FlowDroid, Flutter producers and future native producers are replaceable evidence backends normalized into the same IR.

Gate branch: `feat/0.4-flow-ir`.

## Stage G — Localized Value Tracing

Build real flow evidence on the durable Flow IR. Whole-app taint is not the default.

Localization uses ownership, application map, symbol/XREF topology and network/auth evidence to choose a bounded analysis region.

Internal gated sequence:

1. intraprocedural assignments;
2. argument -> parameter;
3. return -> callsite;
4. field write/read propagation;
5. bounded interprocedural path composition.

Each step must test before the next. Unsupported reflection/native/dynamic dispatch boundaries are explicit `FlowGap`s, never guesses.

Critical regression: an XREF-only path must never become `FLOWS_TO`.

Gate branch: `feat/0.4-value-tracing`.

## Stage H — Auth / Token / Signing / Crypto Semantics

Higher-level security-relevant semantic queries consume the generic program/flow model; do not create standalone grep architectures.

Long-lived semantic questions include auth flow, header generation, signing logic and crypto flow. They must retain SDK boundaries, provenance, unsupported gaps and source-to-sink evidence.

Representative scenarios: bearer/refresh tokens, API keys, HMAC request signatures, AES transformations, Firebase token boundary and payment SDK boundary, with negative false-positive fixtures.

Gate branch: `feat/0.4-auth-crypto-flow`.

## 0.4 Milestone Acceptance

Only after Stages A-H are individually accepted.

Run clean end-to-end validation covering MCP discovery, native Android semantic navigation, ownership, program/application map, bounded context retrieval, localized data flow and auth/signing semantics. For Flutter, validate runtime identity -> resolver -> controlled build on miss -> immutable verification -> offline AOT -> semantic queries when a suitable artifact/runtime fixture is available.

Collect metrics including indexed functions, ownership distribution, SDK boundaries, map size, normal response sizes, runtime-cache hit/miss behavior, data-flow paths/gaps, cleanup, network policy and warnings.

Verify:

- no leaked containers/processes;
- no static/framework worker network;
- no builder credentials in analysis state;
- no legacy fallback;
- no analyzer/provider/storage-specific public API;
- no temporary production architecture;
- exact-head CI green and inspected;
- durable docs match implementation.

Do not release 0.4.0 until a separate senior milestone/release acceptance is recorded.

## Required Gate Report

Every stage reports at least:

- stage, branch and exact head SHA;
- implemented scope and non-goals;
- files and public operations changed;
- private schema and platform contract impact;
- trust-boundary/resource-bound impact;
- exact unit/regression/integration/E2E tests and results;
- architecture/security reviews;
- Blocker/High/Medium findings and known limitations;
- dead-code/reference sweep;
- exact-head workflow/run/result;
- the Long-Term Architecture Review required by `ARCHITECTURE_EVOLUTION_RULES.md`;
- final verdict `READY FOR SENIOR REVIEW` or `BLOCKED`;
- proposed next stage;
- then STOP.
