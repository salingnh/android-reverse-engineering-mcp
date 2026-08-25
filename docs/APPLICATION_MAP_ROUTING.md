# Application Map Semantic Routing

This document complements `docs/APPLICATION_MAP.md` and resolves the Stage D cross-capability routing contract.

Application Map is one public semantic surface over multiple Program Model providers. The routing architecture must preserve one public MCP server, zero-container discovery, unique capability operation ownership, and worker isolation.

## 1. Why capability-owned public map tools are invalid

The Capability Registry intentionally rejects duplicate public operation ownership.

Therefore this is invalid:

```text
static-core          -> get_application_map
framework-flutter    -> get_application_map
```

It would either collide in `tools/list` or force framework-specific public names.

Both outcomes violate the intended semantic architecture.

Likewise, `static-core` must never invoke `framework-flutter`, because workers do not orchestrate other workers and never receive the runtime socket.

## 2. Durable ownership

The two public Stage D operations are **control-plane-owned semantic operations**:

```text
get_application_map
expand_application_node
```

The host control plane owns only:

- host-local public tool descriptors;
- input validation;
- deterministic semantic routing;
- capability invocation;
- normalized result envelopes.

The host does **not** analyze APK/DEX/Dart data and does not build the Application Map itself.

Projection remains inside the isolated semantic worker selected for the exact analyzed representation.

Conceptually:

```text
AI Agent
   |
   v
safe-android-reverser MCP
   |
   v
Host Semantic Router
   |
   +-- representation=dex ----------------> static-core internal map hook
   |
   +-- representation=flutter-dart-aot ----> framework-flutter internal map hook

Each worker:
private index -> ProgramRepository -> ApplicationMapProjector
```

This architecture survives future native/framework providers without changing the public operation names.

## 3. Public analysis locator

Existing `job_id` values are allocated independently inside capability-specific job stores and are not globally unique by contract.

Stage D must not route on `job_id` alone and must not rely on collision probability.

Public Stage D inputs therefore use the pair:

```text
job_id
representation
```

`representation` is a Canonical Program Model semantic representation, not an analyzer/provider/capability identifier.

Initial accepted representations:

```text
dex
flutter-dart-aot
```

The host maps semantic representation to the corresponding installed adapter. It must reject unknown or ambiguous routing; it must never silently select one provider by registry order.

`capability_id`, image name, analyzer name, SQLite schema and worker protocol are not public routing inputs.

### 3.1 Why no global analysis-ref registry in Stage D

Stage D does not add a persisted host mapping database merely to turn `(job_id, representation)` into another opaque token.

Such a registry is not required for correct semantics today and would create a new state lifecycle unrelated to Application Map.

If a future platform requirement needs a global durable analysis handle, it must be designed as a general analysis-lifecycle contract rather than introduced as Stage D glue.

## 4. Host-local public descriptor source

`initialize` and `tools/list` must remain zero-container.

The control-plane-owned semantic operations therefore use a host-local canonical descriptor catalog. The preferred durable catalog is:

```text
plugins/safe-android-reverser/tool-catalogs/control-plane.json
```

It should become the canonical descriptor source for all control-plane-owned public tools:

```text
health
list_capabilities
get_application_map
expand_application_node
```

The control plane must not maintain a second hand-written schema for those same tools.

## 5. Private worker projection hook

Public operation ownership and private worker execution are separate concerns.

### static-core

The MCP worker may expose the map operations as **internal worker operations**. They are not listed in the `static-core` public capability manifest and are filtered from the public adapter catalog.

The internal operation invokes:

```text
DexProgramProvider
    -> ProgramRepository
        -> ApplicationMapProjector
```

### framework-flutter

The Flutter adapter invokes an internal CLI semantic command with the analyzed job mounted read-only:

```text
FlutterProgramProvider
    -> ProgramRepository
        -> ApplicationMapProjector
```

The public `framework-flutter` capability operations remain unchanged.

## 6. Private adapter interface

The host adapter layer gains a private semantic projection interface conceptually equivalent to:

```text
program_model_call(operation, arguments)
```

This is not a public Capability API operation name and does not appear in the capability manifest.

The adapter must either support the requested Program Model representation or return a bounded unsupported error. It must not implement analysis on the host.

Future native/framework adapters can implement the same private interface without changing the public Application Map contract.

## 7. Worker ABI / Capability API versioning

Stage D does not require a breaking change to Capability API 1 or Worker ABI 1.

Reasons:

- existing public capability operations remain compatible;
- the host adds new control-plane-owned semantic operations;
- the worker map hook is an additive internal operation;
- sandbox and protocol invariants do not change;
- existing workers without Stage D support fail readiness/semantic routing explicitly rather than being silently treated as compatible map providers.

If implementation reveals that the internal worker contract cannot be added compatibly, Stage D must stop and perform an explicit ABI review rather than hiding the incompatibility.

## 8. Routing validation

Before invoking a worker, the host validates:

```text
representation is supported
job_id syntax is valid
adapter is enabled
adapter supports the requested semantic projection interface
```

The selected worker then validates that the job actually exists in its own job store and that its Program Snapshot representation matches the requested representation.

A mismatched `(job_id, representation)` fails. It must not trigger fallback probing of unrelated capability job stores.

## 9. Result normalization

Both DEX and Flutter workers return the same Application Map schema and projection version.

The host normalizes the result through the existing EvidenceEnvelope/capability-result boundary without rewriting map semantics.

Provider-specific fields are forbidden in the public map schema.

## 10. Discovery and health invariants

`tools/list` reads only the host-local control-plane catalog and capability public catalogs. It does not start a worker.

`health` may verify worker compatibility/readiness as today.

The Stage D internal projection hook must be included in readiness/integration tests so a public map operation cannot be advertised while the target exact worker image lacks the corresponding internal implementation.

## 11. Routing regression tests

Stage D must include tests proving:

1. `tools/list` exposes exactly one `get_application_map` and one `expand_application_node`;
2. no capability manifest publicly owns either operation;
3. zero-container discovery remains true;
4. `representation=dex` dispatches only to static-core;
5. `representation=flutter-dart-aot` dispatches only to framework-flutter;
6. unknown representation fails without invoking a worker;
7. mismatched job/representation fails without fallback probing;
8. duplicate/ambiguous representation routing fails closed;
9. static worker cannot invoke Flutter worker;
10. both providers emit the same public projection schema/version.

## 12. Long-Term Architecture Review

With this routing contract, Stage D design evaluates as:

```text
1. Component expected to survive to intended 1.0:        YES
2. Future roadmap extension requires replacement:         NO
3. Knowingly transitional public API introduced:          NO
4. Known schema/data migration already required:           NO
5. Analyzer/provider/storage detail leaked publicly:       NO
6. Temporary production fallback/compatibility path:       NO
7. Technical debt intentionally deferred in architecture: NO
```

Stage D implementation may proceed only while these answers remain true.
