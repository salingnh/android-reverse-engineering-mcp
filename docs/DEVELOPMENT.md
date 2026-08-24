# Development Rules

This document is the canonical engineering process for Safe Android Reverser from 0.3.0 onward. It applies to humans and coding agents.

The architecture source of truth is [`PROJECT_DIRECTION.md`](PROJECT_DIRECTION.md). The extension contract is [`CAPABILITY_SPI.md`](CAPABILITY_SPI.md). The release sequence is [`RELEASING.md`](RELEASING.md).

## 1. Development objective

Development should increase reverse-engineering intelligence without repeatedly rewriting orchestration.

The stable direction is:

```text
AI agent
   |
   v
one safe-android-reverser MCP control plane
   |
   +-- Capability Registry
   +-- Adapter Registry
   +-- Runtime Driver
   +-- Path / Job / Evidence contracts
   |
   +-- isolated capability workers
```

New analyzers are evidence producers behind this platform. They are not reasons to create new public MCP servers, container wrappers, job stores, or evidence models.

## 2. Mandatory architecture invariants

Every change must preserve these invariants unless an explicit architecture decision changes them:

1. Exactly one public MCP server: `safe-android-reverser`.
2. Only the host control plane invokes Docker/Podman.
3. Analyzer workers never receive Docker/Podman sockets.
4. Static/framework/native-static workers use `network=none`.
5. Dynamic privileges require an explicit `dynamic-opt-in` capability with `activation=opt-in`.
6. Capability manifests own public operation names; duplicate ownership is rejected.
7. Capability dispatch is manifest/adapter driven, never an operation-name switch in the control plane.
8. Generic runtime, path, job, evidence, and health logic must not be duplicated in framework modules.
9. Decompilation is evidence presentation/localization, not canonical truth.
10. XREF/CALL adjacency is never reported as proven data flow.
11. Analyzer outputs are bounded and provenance-carrying.
12. A release never silently reuses an incompatible worker/runtime-cache image.
13. Security boundaries may become stricter in a compatible release; privilege expansion requires explicit senior review.
14. A roadmap milestone must not intentionally introduce orchestration that the next milestone is expected to replace.

## 3. Capability boundary rules

### static-core

`static-core` owns generic Android package/DEX/JVM/resource triage and semantics that are not specific to one external application framework.

It may perform framework detection and bounded generic preflight required for routing.

It must not become a dumping ground for deep framework semantics. Deep Dart, Hermes, IL2CPP, .NET, or future framework-specific program understanding belongs in dedicated capability modules.

### Framework capabilities

A framework capability owns semantic analysis of the representation that contains that framework's business logic.

Examples:

```text
framework-flutter  -> Dart AOT / libapp.so semantics
framework-hermes   -> Hermes bytecode / JS semantics
framework-il2cpp   -> IL2CPP metadata + native correlation
framework-dotnet   -> managed assemblies / IL semantics
```

### Native capability

Generic ELF/native/JNI analysis is a shared substrate, not a substitute for framework-aware analysis.

### Dynamic capability

Dynamic analysis is explicit opt-in and lives in a separate trust boundary. Static workers must never gain device/network privileges as a shortcut.

## 4. Adding a capability

A normal new capability should require:

1. a capability manifest;
2. an existing adapter kind, or a narrowly scoped adapter factory implementation;
3. an isolated worker image;
4. semantic operations rather than raw analyzer consoles;
5. deterministic tests and capability-specific CI;
6. shared provenance/evidence normalization;
7. internal readiness diagnostics compatible with Worker ABI.

It must not require changes to generic dispatch, public health semantics, Runtime Driver ownership, shared path/job logic, or the EvidenceEnvelope model.

Central CI must validate platform invariants, not hard-code the complete forever list of capability IDs. A release may require a baseline capability subset, but adding a compatible optional capability must not fail because it was not manually added to an exact-set assertion.

## 5. Adapter rules

`adapter` and `protocol` are different contracts.

An adapter owns host-side orchestration that cannot be represented by a generic transport. A protocol describes communication with a worker.

Prefer reusable adapter factories. Adding a capability using an existing adapter must not require a new control-plane branch.

If a new adapter kind is required, register it behind the adapter factory/registry. Do not add framework-specific branches to `ControlPlane.call()`, `health()`, or tool dispatch.

## 6. Contract versioning

Current platform contracts are independently versioned:

```text
Capability API
Worker ABI
EvidenceEnvelope
PEG schema
capability-private cache/index schemas
```

Breaking changes require:

1. an explicit decision entry in `PROJECT_DIRECTION.md`;
2. a migration/compatibility strategy;
3. version increment of the affected contract;
4. compatibility/regression tests;
5. updated release/upgrade documentation;
6. senior architecture/security review.

### Controlled runtime-cache builders

Analyzer workers remain offline when a runtime cache is missing. Optional controlled build providers are configured only on the host control plane:

```text
SAFE_REVERSER_CONTROLLED_BUILD_PROVIDER=github-actions
SAFE_REVERSER_CONTROLLED_BUILD_TOKEN=<host-only credential>
SAFE_REVERSER_CONTROLLED_BUILD_REPOSITORY=salingnh/android-reverse-engineering-mcp
SAFE_REVERSER_CONTROLLED_BUILD_WORKFLOW=build-flutter-runtime-cache.yml
SAFE_REVERSER_CONTROLLED_BUILD_REF=master
SAFE_REVERSER_CONTROLLED_BUILD_TIMEOUT_SECONDS=21600
SAFE_REVERSER_CONTROLLED_BUILD_RETRY_SECONDS=300
```

Do not use a generic provider token variable that is automatically inherited by child processes. The Runtime Driver passes an explicit allowlist of worker environment variables; controlled-build credentials must never be added to it. Provider configuration and opaque handles are private implementation details and are not public MCP operations.

If no provider is configured, an exact cache miss remains `BUILD_REQUIRED`. If one is configured, subsequent analysis calls reconcile `BUILDING` state and use the cache only after exact provenance and immutable-image verification. The stable runtime request identity must never be randomized for retry. Resolver private state schema 2 persists a separate current `BuildAttempt` before submission. Ambiguous responses and process restarts reconcile that exact attempt; after a bounded failure/backoff, a genuine retry creates a new attempt identity while retaining the request identity. Provider reconciliation must parse authoritative provider creation metadata, remain bounded, and reject historical or duplicate current-attempt matches.

The GitHub provider stays on REST API `2026-03-10`. Its workflow-dispatch body contains exactly `ref` and `inputs`; the removed `return_run_details` parameter must not be sent. The HTTP 200 `workflow_run_id`, `run_url`, and `html_url` response is validated before its opaque handle is persisted.

Operation names alone are not sufficient for long-term compatibility. Before 1.0, public semantic operations must gain a stable schema compatibility policy for inputs and externally meaningful outputs.

## 7. Security engineering rules

Treat application artifacts, generated analyzer output, archives, paths, metadata, symbols, strings, and tool responses as untrusted.

Required patterns:

```text
bounded input
bounded traversal
bounded CPU/time
bounded memory/storage
bounded output
explicit provenance
```

Prefer fail-closed behavior for security invariants.

Host filesystem security should reject lexical escape, resolved escape, symlink substitution, unsafe deletion targets, and oversized metadata. Where the threat model later includes hostile same-UID filesystem races, migrate critical operations toward dirfd/openat/openat2-style primitives rather than repeated check-then-use path operations.

Never fix a failing test by weakening sandbox restrictions unless the privilege change is the explicit reviewed purpose of the PR.

## 8. Branch and PR workflow

Use small logical branches where practical:

```text
master
  -> feat/<capability-or-feature>
  -> fix/<issue>
  -> docs/<topic>
  -> release/<version>
```

For a milestone integration branch, keep commits logically reviewable even when several slices are combined.

Every non-trivial PR should state:

- scope and non-goals;
- architecture contracts affected;
- trust-boundary impact;
- new/changed operations;
- resource bounds;
- provenance/evidence behavior;
- tests executed;
- known limitations;
- release/migration impact.

Do not hide known Blocker/High findings in a general TODO list.

## 9. Review gate

Before merge:

```text
implementation
   ↓
unit/regression tests
   ↓
architecture/security review
   ↓
fix Blocker + High
   ↓
dead-reference/code sweep
   ↓
exact-head CI
   ↓
senior acceptance for milestone/platform changes
   ↓
merge
```

Severity policy:

- **Blocker**: cannot merge.
- **High**: cannot merge without explicit senior exception and documented rationale.
- **Medium**: normally fix in the PR when it affects platform extensibility, correctness, security assumptions, or release reproducibility; otherwise create a tracked follow-up with an owner/milestone.
- **Low**: hardening/cleanup; may be deferred when documented.

Exact-head means CI must run against the commit that will be reviewed/merged. A green run for an older commit is not sufficient.

## 10. CI rules

CI is part of the architecture contract.

Required classes of gates:

- syntax/static validation;
- Capability SPI/Worker ABI contract tests;
- operation ownership collision tests;
- path/archive/job bound regressions;
- immutable worker-image identity/provenance tests;
- capability worker tests;
- real image build where applicable;
- one public MCP integration smoke test;
- release-consistency checks.

Platform gates should assert invariants and required baseline capabilities, not an exact global set that blocks future compatible extensions.

## 11. Documentation rule

A durable decision must be committed to the repository, not left only in a chat or PR discussion.

Update all applicable documents in the same PR:

- `docs/PROJECT_DIRECTION.md` for architecture/product decisions;
- `docs/ROADMAP.md` for milestone scope/status/acceptance;
- `docs/CAPABILITY_SPI.md` for platform contracts;
- `docs/DEVELOPMENT.md` for engineering/review rules;
- `docs/INSTALL_MCP.md` for user/runtime changes;
- `docs/RELEASING.md` for release changes;
- `README.md` for concise current state;
- capability skill/design docs for agent-facing behavior.

If implementation and documentation disagree, the PR is incomplete.

## 12. Release discipline

Do not bump the marketplace to a release whose required immutable capability images are unavailable.

The release candidate must pass the exact contract/integration gate, then required semver images are published from the exact tested release commit, then the marketplace-visible release is merged according to `RELEASING.md`.

Never overwrite a published semver image. Release a new patch version.

## 13. Milestone transition rule

Do not start the next milestone merely because feature code exists. A platform milestone closes only after:

- acceptance criteria are satisfied;
- exact-head CI is green;
- architecture/security review passes;
- known blockers/highs are closed;
- durable docs match reality;
- senior milestone acceptance is recorded.

After 0.3.0 acceptance, normal work should move to analysis intelligence (0.4+) rather than continue restructuring orchestration without a demonstrated architectural need.
