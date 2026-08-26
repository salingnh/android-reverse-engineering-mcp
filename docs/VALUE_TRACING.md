# Localized Value Tracing

Stage G adds real, bounded value-flow evidence on top of the durable Stage F Flow IR. It does not reinterpret call/XREF topology as flow and it does not introduce a whole-app taint engine as the default product architecture.

## Architecture

```text
Public semantic query
  trace_value / find_source_to_sink
              ↓
Localized Flow Query Layer
              ↓
representation-owned producer
              ↓
Normalized FlowDocument (Stage F)
              ↓
Program Model + evidence anchors
```

The first producer is DEX/Androguard because the static-core capability already owns that representation and ships pinned Androguard 4.1.4. The semantic operations and Flow IR are backend-independent; future SootUp/Jimple, FlowDroid, Flutter, native and framework producers extend coverage without replacing the contract.

## DEX producer semantics

The producer normalizes Androguard bytecode instructions and CFG blocks before creating Flow IR. It uses structured operands, not decompiler text, and stays inside the offline static-core worker.

Initial proven relations:

1. register assignment / move;
2. constants into register definitions;
3. deterministic arithmetic/cast/transformation inputs into result definitions;
4. field writes and reads;
5. exact argument -> parameter binding for statically resolved direct/static calls;
6. function return value -> callsite result binding;
7. bounded interprocedural composition across first-party/unknown internal methods.

Control-flow joins use a conservative may-flow merge of reaching definitions. This is static may-flow evidence, not a claim that every runtime path carries the value.

## Explicit gaps

The producer fails closed when it cannot establish value semantics. Examples:

- reflection -> `REFLECTION`;
- native body -> `NATIVE`;
- virtual/interface/polymorphic/custom dispatch when the exact implementation is not proven -> `DYNAMIC_DISPATCH`;
- SDK/platform/third-party internals suppressed by ownership policy -> `EXTERNAL_BOUNDARY`;
- unavailable register definition or unsupported result semantics -> `MISSING_EVIDENCE` / `UNSUPPORTED_INSTRUCTION`;
- method/instruction/depth/resource limit -> `BUDGET`.

A `FlowGap` is never converted to `FLOWS_TO` by path composition.

## Localized budgets

Normal tracing is intentionally smaller than Stage F hard document bounds:

- root methods per trace: default 12, max 32;
- interprocedural depth: default 3, max 8;
- normalized instructions: default 8,000, max 20,000;
- returned nodes: default 160, max 500;
- source-to-sink search depth: default 12, max 32;
- returned paths: default 20, max 100.

The worker remains subject to its existing wall-clock, container CPU/memory, read-only root, non-root, network-none and host-owned runtime limits.

## Public semantic operations

### `trace_value`

Inputs identify a canonical function and a semantic seed. Seed kinds are durable rather than DEX-register-specific:

- `parameter` + parameter index;
- `return`;
- `field` + field name/ref fragment;
- `node` + Flow IR node ID returned by a previous semantic query.

The response contains a bounded Flow IR subgraph and adjacent explicit gaps. It never exposes raw analyzer SQL/register query APIs.

### `find_source_to_sink`

Inputs identify one canonical root function plus semantic source and sink selectors. The operation builds the same localized Flow IR and performs bounded path composition over **real FlowEdge records only**. Complete paths never traverse a `FlowGap`; unresolved candidate boundaries are returned separately as gaps.

Stage H consumes these same semantics for auth/token/signing/crypto questions.

## Ownership and SDK boundaries

Localization can use Program Model CALLS/XREF topology to decide which methods to inspect, but those relationships never become value-flow edges. Application-to-SDK boundaries stay visible. Third-party/platform/generated internals are not recursively analyzed by default; their boundary is recorded as an explicit gap with provenance.

## Security-sensitive constants

Raw literal values remain private to the instruction producer long enough to compute a SHA-256 fingerprint. Stage F constant node rules continue to prohibit raw values in semantic keys, labels and Flow IR properties.

## Non-goals

Stage G does not:

- claim whole-app soundness/completeness;
- resolve arbitrary reflection/native/dynamic dispatch;
- infer flow from `CALLS` or `XREF` alone;
- add analyzer-specific public operations;
- add auth/HMAC/AES/token conclusions (Stage H);
- enable network access or host execution inside analysis workers.

## Stage G acceptance

The gate must prove:

1. intraprocedural move/constant/transformation flow;
2. exact argument -> parameter binding;
3. exact return -> callsite binding;
4. field write/read propagation through shared field nodes;
5. bounded interprocedural composition;
6. branch join may-flow is deterministic and bounded;
7. virtual/interface/reflection/native/external/budget uncertainty is explicit;
8. XREF/CALLS-only fixtures produce no `FLOWS_TO` path;
9. raw constants never appear in semantic output;
10. `trace_value` cannot seed on private DEX register numbers;
11. source-to-sink complete paths contain only real FlowEdge segments;
12. path/subgraph limits fail closed or mark truncation explicitly;
13. host routing stays `job_id + representation` and zero-container discovery remains intact;
14. exact-head static-core/control-plane/release CI is green.

## Long-Term Architecture Review

1. Component expected to survive to 1.0: **YES**.
2. Future roadmap extension requires replacement: **NO** — stronger producers add evidence to the same Flow IR/query layer.
3. Knowingly transitional public API introduced: **NO**.
4. Known schema/data migration already required: **NO** — no persistent flow schema is introduced.
5. Analyzer/provider/storage detail leaked publicly: **NO**.
6. Temporary production fallback/compatibility path: **NO**.
7. Technical debt intentionally deferred in architecture: **NO** — unsupported coverage is represented as explicit gaps rather than hidden debt.

**Design verdict: PASS.**
