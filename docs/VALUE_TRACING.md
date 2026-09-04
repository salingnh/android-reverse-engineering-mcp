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
4. static-field writes and reads through one canonical declaring-class field node;
5. exact argument -> parameter binding for statically resolved direct/static calls;
6. function return value -> callsite result binding;
7. bounded interprocedural composition across first-party/unknown internal methods.

Control-flow joins use a conservative may-flow merge of reaching definitions. This is static may-flow evidence, not a claim that every runtime path carries the value.

Dalvik-specific ABI normalization is private to the producer. Wide `long`/`double` arguments consume two register words but map to one semantic parameter; instance-call receivers are preserved until the semantic call layer removes them exactly once. Transformations read all source operands before overwriting their destination, including `/2addr` instructions.

### Static vs instance fields

Static fields (`sget`/`sput`) have one process-level storage location for a declaring field, so Stage G can safely normalize their accesses through one canonical `FIELD` node owned by the declaring Program Model class. Access-site provenance remains on `FIELD_READ` / `FIELD_WRITE` edges rather than changing the shared node identity.

Instance fields (`iget`/`iput`) are different: the same declaring field can belong to many object instances. Stage G does **not** claim those instances alias merely because the field descriptor matches. Until receiver-alias evidence exists, an instance-field access is represented as `MISSING_EVIDENCE` and does not emit a proven `FIELD_READ` / `FIELD_WRITE` edge. A future alias-aware producer may extend this coverage without changing Flow IR or the public semantic operations.

## Explicit gaps

The producer fails closed when it cannot establish value semantics. Examples:

- reflection -> `REFLECTION`;
- native body -> `NATIVE`;
- virtual/interface/polymorphic/custom dispatch when the exact implementation is not proven -> `DYNAMIC_DISPATCH`;
- SDK/platform/third-party internals suppressed by ownership policy -> `EXTERNAL_BOUNDARY`;
- instance-field access without proven receiver alias -> `MISSING_EVIDENCE`;
- unavailable register definition or unsupported result semantics -> `MISSING_EVIDENCE` / `UNSUPPORTED_INSTRUCTION`;
- method/instruction/depth/resource limit -> `BUDGET`.

A `FlowGap` is never converted to `FLOWS_TO` by path composition.

## Localized budgets

Normal tracing is intentionally smaller than Stage F hard document bounds:

- root methods per trace: default 12, max 32;
- interprocedural depth: default 3, max 8;
- normalized instructions: default 8,000, max 20,000;
- returned/reachable nodes: default 160/240 depending on query, max 500;
- source-to-sink search depth: default 12, max 32;
- returned paths: default 20, max 100;
- source-to-sink exploration states: hard max 10,000.

The node bound applies to the reachable frontier, not only the final response. The state bound prevents combinatorial simple-path expansion on dense graphs even when the final number of returned paths is small. Hitting either bound marks the result truncated and does not invent a path.

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
- infer instance-object aliasing from a matching field descriptor;
- infer flow from `CALLS` or `XREF` alone;
- add analyzer-specific public operations;
- add auth/HMAC/AES/token conclusions (Stage H);
- enable network access or host execution inside analysis workers.

## Stage G acceptance

The gate must prove:

1. intraprocedural move/constant/transformation flow;
2. exact argument -> parameter binding, including wide Dalvik arguments and one-time receiver handling;
3. exact return -> callsite binding;
4. static-field write/read propagation through a canonical declaring-class field node;
5. instance fields fail closed without receiver-alias evidence;
6. bounded interprocedural composition;
7. branch join may-flow is deterministic and bounded;
8. virtual/interface/reflection/native/external/budget uncertainty is explicit;
9. XREF/CALLS-only fixtures produce no `FLOWS_TO` path;
10. raw constants never appear in semantic output;
11. `trace_value` cannot seed on private DEX register numbers;
12. source-to-sink complete paths contain only real FlowEdge segments;
13. path/subgraph/frontier/exploration-state limits fail closed or mark truncation explicitly;
14. host routing stays `job_id + representation` and zero-container discovery remains intact;
15. exact-head static-core/control-plane/release CI is green.

## Long-Term Architecture Review

1. Component expected to survive to 1.0: **YES**.
2. Future roadmap extension requires replacement: **NO** — stronger producers add evidence to the same Flow IR/query layer.
3. Knowingly transitional public API introduced: **NO**.
4. Known schema/data migration already required: **NO** — no persistent flow schema is introduced.
5. Analyzer/provider/storage detail leaked publicly: **NO**.
6. Temporary production fallback/compatibility path: **NO**.
7. Technical debt intentionally deferred in architecture: **NO** — unsupported coverage is represented as explicit gaps rather than hidden debt.

**Design verdict: PASS.**
