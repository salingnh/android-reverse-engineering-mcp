# Program Understanding Phase 1

Safe Android Reverser 0.2.0 adds a semantic program-understanding layer on top of the sandboxed decompilation flow. This phase is intentionally focused on reliable code navigation and evidence correlation before adding broad analyzer coverage.

## New MCP tools

```text
build_program_index
find_symbols
find_xrefs
get_cfg
identify_protector
extract_network_model
```

### `build_program_index`

Builds a bounded normalized method/call-edge index for a decompile job. Androguard DEX XREF analysis is preferred. APK members from XAPK/APKS/APKM bundles are loaded into one shared analysis graph before XREF creation so references between base and feature splits can resolve.

The canonical index is stored in SQLite rather than a monolithic graph JSON file:

```text
program-index.sqlite3
├── metadata
├── methods
└── call_edges
```

Indexes on class/method identity and caller/callee columns keep symbol and XREF queries bounded on large applications. `program-index.json` is retained only as a small human-readable summary.

If semantic DEX analysis cannot process a protected/malformed artifact, the server falls back to a lower-confidence source declaration index. The fallback reason is persisted and exposed to the client rather than silently presenting source-derived data as DEX-grounded evidence.

Cache reuse is guarded by schema/builder versions, artifact stat and SHA-256, configured graph limits, truncation state, and analyzer availability. A source fallback is automatically rebuilt when Androguard later becomes available.

### `find_symbols`

Queries normalized methods from SQLite without making the agent scan the whole JADX tree. Search results retain class, method, DEX descriptor/parameter count, external/internal state, and provenance.

### `find_xrefs`

Returns incoming/outgoing method cross-references from indexed DEX call edges. XREF queries use indexed caller/callee columns instead of rescanning every graph edge for every question.

### `get_cfg`

Returns a bounded basic-block control-flow graph for matching internal DEX methods. `max_blocks` is a total response budget across all matches rather than a per-method multiplier.

### `extract_network_model`

Extends plain endpoint extraction into a structured model that correlates Retrofit annotations with source declarations and DEX symbols.

Endpoint-to-symbol resolution is conservative:

```text
exact class + method + parameter count
        ↓ if no match
exact class + method
        ↓
simple class + method + parameter count
        ↓
simple class + method
```

A caller list is returned only when this process resolves to exactly one DEX method. Multiple candidates are reported as `ambiguous`; their callers are not silently unioned. This prevents common names such as `login`, `get`, `post`, `execute`, or overloaded methods in unrelated classes from contaminating the flow.

The source declaration parser is declaration-aware enough to reject Retrofit annotations and method invocations as declarations. For example, this sequence:

```java
@POST("/v1/login")
Call<LoginResponse> login(LoginRequest request);
```

is associated with `login`, not a synthetic method parsed from `@POST(...)`.

Request/response model candidates remain lexical evidence in this phase. XREF adjacency is explicitly not described as proven data-flow.

### `identify_protector`

Provides the existing optional APKiD process adapter. APKiD is not bundled in the default 0.2.0 image; when absent the capability is reported unavailable rather than emulated.

## Default image additions

The static image contains:

```text
Androguard 4.1.4
file
binutils (strings/readelf/objdump/nm)
libmagic
```

Androguard's top-level wheel is version-pinned and SHA-256 verified during the build. Its runtime dependencies are installed into the isolated `/opt/python-site` bundle, and the final image validates imports of the actual DEX/Analysis modules used by the MCP. The exact resolved Python package set is recorded in `/opt/python-site/installed-requirements.txt`.

The compiler, pip and Python build toolchain are not retained in the runtime image. A future supply-chain phase should hash-lock the complete transitive wheel set rather than only recording its resolved versions.

The existing static security boundary remains unchanged:

```text
network              disabled
project              read-only
root filesystem      read-only
Linux capabilities   dropped
privilege escalation disabled
generic shell MCP    absent
container execution  non-root
CPU/memory/PID       bounded
```

## CI / regression gates

Phase 1 CI now tests both source-level behavior and the actual final container image.

Host tests cover:

- Retrofit annotations are not parsed as methods;
- calls such as `refresh();` are not treated as declarations;
- source fallback uses SQLite;
- same-named methods in different classes are not unioned;
- overloads are resolved with parameter count when possible;
- XREF queries use the SQLite edge index;
- unchanged artifacts reuse the semantic cache.

The final image is then run with the normal static sandbox restrictions. An embedded tiny DEX fixture from the Apache-2.0 Androguard test corpus must successfully execute:

```text
real DEX
  → Androguard Analysis
  → build_program_index == dex-xref
  → find_symbols
  → find_xrefs
  → get_cfg
```

A separate JSON-RPC MCP health smoke test requires the final image to report Androguard and CFG support as available. This prevents a shallow `import androguard` check from hiding missing runtime dependencies.

Only after these runtime gates pass is the release workflow allowed to publish a master/tag image.

## Recommended analysis workflow

```text
health
  → fingerprint
  → identify_protector (when available)
  → decompile
  → build_program_index
  → find_symbols / find_xrefs / get_cfg
  → extract_network_model
  → targeted read_source_file for evidence verification
```

This changes the agent workflow from full-tree reading toward indexed, graph-guided and evidence-backed investigation.

## Known limitations / next work

- Source fallback remains lower-confidence than DEX XREF analysis and does not claim complete call-graph correctness.
- Nested/local/anonymous source class ownership is not yet a replacement for a full Java/Kotlin AST; DEX identity remains the authoritative graph layer.
- Request/response models are lexical hints until bounded data-flow/type analysis is implemented.
- APKiD remains optional in the default image.
- Native `.so` XREF/JNI correlation is not implemented yet.
- Dynamic analysis remains a separate future privilege profile.
- The full transitive Python wheel set should be hash-locked for stronger reproducible supply-chain guarantees.

Next semantic targets:

1. `trace_value` with bounded forward/backward data-flow.
2. `find_auth_flow` and `find_signing_logic` built on data-flow traces.
3. Android manifest/component/lifecycle and callback graph.
4. JNI/native evidence mapping.
5. hierarchical feature/module summaries and graph-guided retrieval.
