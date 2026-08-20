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

An exact full symbol ID takes priority over substring search.

## Traversal semantics

The implementation performs deterministic bounded breadth-first traversal and returns only shortest paths. For a node reached at the same shortest depth through multiple call edges, all predecessor edges are retained up to `max_paths`.

Each returned edge contains both traversal orientation and original call semantics:

```json
{
  "traversal_from": "...",
  "traversal_to": "...",
  "caller": "...",
  "callee": "...",
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
```

A negative result (`found=false`) is conclusive only when `truncated=false`, both endpoint queries resolved, and the current program index is a complete `dex-xref` index within its configured limits.

A `source-fallback` index exposes no call graph, so `trace_call_path` returns `available=false` rather than fabricating call paths from lexical source proximity.

## Safety bounds

Hard limits:

```text
max_depth          32
max_paths          50
max_visited_nodes  200000
max_scanned_edges  500000
wall-clock timeout 3600s
```

Default limits are intentionally lower.

## Test gate

M1 cannot progress to M2 until the Senior Tester gate passes:

- deterministic shortest paths;
- multiple shortest paths;
- cycles and recursion;
- same-name methods and overloads;
- forward/reverse traversal;
- unresolved endpoints;
- fallback index behavior;
- depth/node/edge/path budgets;
- truncated-index semantics;
- missing intermediate symbol metadata;
- synthetic 100k-method / 250k-edge graph;
- final locked-down Docker image execution;
- MCP registration/schema/health regression.

Only after `Senior Tester: APPROVED` may `trace_value` development begin.
