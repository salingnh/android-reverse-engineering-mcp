# `trace_call_path` — M1 Call-Path Traversal

`trace_call_path` is the first post-0.2 semantic milestone. It answers bounded questions such as:

```text
LoginActivity.onClick
  -> LoginViewModel.login
  -> LoginUseCase.invoke
  -> AuthRepository.login
  -> AuthApi.login
```

It traverses the SQLite DEX XREF graph produced by `build_program_index`. It does **not** infer data flow.

## MCP input

```json
{
  "job_id": "012345abcdef",
  "source": "LoginActivity onClick",
  "target": "AuthApi login",
  "direction": "forward",
  "max_depth": 12,
  "max_paths": 20,
  "max_visited_nodes": 50000,
  "max_scanned_edges": 200000,
  "timeout_seconds": 300
}
```

`direction` may be `forward` (caller -> callee) or `reverse` (callee -> caller).

## Resolution semantics

Endpoint queries are resolved against exact method symbols. A broad query may match multiple methods/classes/overloads; those remain an explicit candidate set. They are never collapsed into one synthetic method.

An exact full symbol ID takes priority over substring search. If method metadata was omitted because the method index was truncated but the exact symbol still exists as a `call_edges` caller/callee, that exact XREF symbol remains a valid traversal anchor. The response still carries `index_methods_truncated`, so incomplete metadata is never presented as a complete index.

Candidate search is capped at 200 symbol IDs. When more candidates exist, `truncated=true`, `candidate_count_is_lower_bound=true`, and `candidate_count_lower_bound` reports the minimum number known to exist. Traversal over a truncated candidate set is therefore never marked complete.

## Traversal semantics

The implementation performs deterministic bounded breadth-first traversal and returns only shortest **logical method paths**. Multiple callsite offsets between the same caller/callee pair do not create duplicate logical paths; the deterministic lowest ordered edge is retained as evidence for that hop.

A returned path uses exact symbol IDs:

```json
{
  "depth": 2,
  "node_ids": ["method-A", "method-B", "method-C"],
  "edges": []
}
```

Each edge contains both traversal orientation and original call semantics:

```json
{
  "traversal_from": "method-A",
  "traversal_to": "method-B",
  "caller": "method-A",
  "callee": "method-B",
  "offset": 42,
  "confidence": 0.98,
  "kind": "dex-xref"
}
```

For reverse traversal, `traversal_from/to` are reversed while `caller/callee` remain the original DEX call edge.

## Completeness and budgets

Possible truncation reasons include:

```text
source_candidates_truncated
target_candidates_truncated
index_methods_truncated
index_edges_truncated
depth_limit
node_budget
edge_budget
path_limit
response_budget
```

A negative result (`found=false`) is conclusive only when `truncated=false`, both endpoint queries resolved, and the current program index is a complete `dex-xref` index within its configured limits.

The tool also applies an internal response budget below the MCP core text limit using the same pretty-JSON serializer as the MCP core. If detailed paths or candidate IDs would exceed that budget, `found` and `shortest_depth` are preserved while path/candidate detail is omitted explicitly and `response_budget` is reported. This prevents silent mid-JSON truncation.

A `source-fallback` index exposes no call graph, so `trace_call_path` returns `available=false` rather than fabricating call paths from lexical source proximity.

## Safety bounds

Hard limits:

```text
max_depth          32
max_paths          50
max_visited_nodes  200000
max_scanned_edges  500000
response detail    150000 JSON characters
wall-clock timeout 3600s
```

Default limits are intentionally lower. Semantic wall-clock cancellation uses an MCP-boundary control-flow exception that normal analyzer `except Exception` handlers cannot swallow. A stricter already-active outer deadline is preserved when semantic scopes are nested.

## Test gate

M1 cannot progress to M2 until the Senior Tester gate passes:

- deterministic shortest paths;
- multiple shortest paths;
- duplicate-callsite collapse;
- cycles and recursion;
- same-name methods and overloads;
- exact edge-only XREF anchors;
- forward/reverse traversal;
- unresolved endpoints;
- fallback index behavior;
- depth/node/edge/path/response budgets;
- candidate-cap lower-bound semantics;
- truncated-index semantics;
- intermediate symbols absent from method metadata;
- synthetic 100k-method / 250k-edge graph;
- real DEX -> Androguard XREF -> `trace_call_path` integration;
- semantic timeout propagation and nested-deadline behavior;
- final locked-down Docker image execution;
- MCP registration/schema/health regression;
- documentation/version consistency.

Only after `Senior Tester: APPROVED` may `trace_value` development begin.
