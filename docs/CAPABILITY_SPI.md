# Safe Reverser Capability SPI v1

## Purpose

Safe Android Reverser exposes one public MCP control plane and executes analyzers in isolated capability workers. Capability SPI v1 is the extension contract established by 0.3.0 and extended by later milestones rather than replaced.

```text
AI agent
   |
   v
safe-android-reverser MCP
host control plane
   |
   +-- Capability Registry
   +-- Adapter Registry/factory
   +-- Runtime Driver
   +-- Path / Job / Evidence contracts
   |
   +-- isolated capability workers
```

The agent never chooses Docker/Podman commands and never receives raw unrestricted analyzer consoles. The host control plane is the only layer allowed to invoke the container runtime.

## Versioned contracts

0.3.0 defines independently versioned contracts:

```text
Capability API       1
Worker ABI           1
EvidenceEnvelope     1
PEG schema           2
Flutter cache schema 2
```

A future breaking change requires an architecture decision, migration path, compatibility tests, documentation, and senior review.

## Capability manifest

Capabilities are declared under:

```text
plugins/safe-android-reverser/capabilities/*.json
```

Representative manifest:

```json
{
  "id": "framework-flutter",
  "capability_api": 1,
  "worker_abi": 1,
  "representations": ["dart-aot", "libapp.so", "flutter-assets"],
  "trust_boundary": "framework-static",
  "activation": "required",
  "adapter": "flutter-aot",
  "protocol": "cli-json",
  "image": {
    "repository": "ghcr.io/salingnh/safe-android-reverser-flutter",
    "role": "framework-flutter"
  },
  "operations": ["analyze_flutter_aot", "find_dart_symbols"],
  "sandbox": {
    "network": "none",
    "read_only_root": true,
    "drop_all_capabilities": true,
    "no_new_privileges": true,
    "memory": "6g",
    "cpus": "2",
    "pids_limit": 256,
    "tmpfs_tmp": "1g",
    "tmpfs_work": "512m"
  }
}
```

Unknown/missing fields are rejected. Booleans, integers, strings, arrays, IDs, operation names, image descriptors, and policy values are strictly validated.

Public operation ownership is unique across all manifests.

## Activation contract

```text
required
  The release baseline depends on this capability. Its failure degrades overall health.

optional
  Active when installed/declared by the release, but failure does not make the required platform unhealthy.

opt-in
  Declared but inactive until its exact capability id is explicitly enabled through
  SAFE_REVERSER_ENABLE_CAPABILITIES.
```

A `dynamic-opt-in` trust boundary must use `activation=opt-in`.

Disabled opt-in capabilities do not expose analyzer tools. They remain discoverable through `list_capabilities` as declared/not enabled.

## Trust boundaries

Current identifiers:

```text
static
framework-static
native-static
dynamic-opt-in
```

Static-style workers preserve:

```text
network = none
read-only root = true
cap-drop = ALL
no-new-privileges = true
non-root UID/GID
bounded memory / CPU / PIDs / tmpfs
```

No worker receives a Docker/Podman socket.

Only `dynamic-opt-in` may declare `sandbox.network=controlled`.

The 0.3 Runtime Driver intentionally refuses execution of `controlled`. A later dynamic Runtime Driver implementation may support that already-defined policy without changing Capability SPI or public MCP topology.

## Adapter vs protocol

These are separate concepts.

### `adapter`

The host adapter owns capability-specific orchestration that cannot be expressed by a generic transport.

Current kinds:

```text
mcp-container
  Generic MCP-over-stdio capability worker.

flutter-aot
  Flutter-specific exact runtime-cache orchestration followed by bounded CLI JSON worker calls.
```

Prefer existing reusable adapters. A new adapter kind must be registered behind the adapter factory/registry boundary.

It must not add framework/operation branches to generic `ControlPlane.call()`, health aggregation, job ownership, evidence normalization, or public MCP topology.

### `protocol`

The worker communication protocol currently supports:

```text
mcp-stdio
cli-json
```

Protocol is not framework identity. Multiple capabilities can share a protocol/adapter.

## Public operations and ownership

The control plane reserves:

```text
health
list_capabilities
```

A capability manifest must not claim them.

Each other public semantic operation has exactly one manifest owner. Duplicate ownership causes registry startup failure.

The control plane resolves:

```text
operation name
   ↓
manifest owner
   ↓
enabled adapter
   ↓
worker/domain implementation
```

Do not implement public dispatch as a framework/operation `if/elif` tree in the control plane.

## Internal diagnostics

Worker ABI v1 requires readiness/diagnostic behavior behind the adapter contract.

For `mcp-stdio`, the worker exposes an internal `health` tool. The generic adapter validates it, removes it from the public capability tool surface, and exposes diagnostics through the host platform health response.

CLI/domain adapters must supply equivalent bounded diagnostics.

A capability is `ready` only when its image/runtime identity is compatible **and** the worker surface satisfies the declared contract. Image existence alone is not readiness.

## Capability boundary rules

### static-core

`static-core` owns generic Android package/DEX/JVM/resource triage and semantics, framework detection/routing preflight, and fast generic native triage.

It must not accumulate deep semantics for external frameworks merely because those frameworks are packaged inside APK files.

### Framework capabilities

A framework capability owns semantic analysis of the representation carrying framework business logic, for example:

```text
framework-flutter -> Dart AOT semantics
framework-hermes  -> Hermes/JS semantics
framework-il2cpp  -> IL2CPP metadata/native correlation
framework-dotnet  -> managed assemblies/IL semantics
```

### Native capability

Generic native/JNI analysis is a substrate and escalation path. A higher-level framework analyzer remains primary when it preserves richer semantics.

### Dynamic capability

Dynamic execution/device/network access is a separate explicit opt-in trust boundary and must never be introduced by weakening static workers.

## Runtime Driver contract

The shared Runtime Driver owns:

- Docker/Podman selection;
- image inspect/pull;
- OCI provenance verification;
- immutable image-ID resolution;
- UID/GID mapping;
- network policy enforcement;
- read-only root;
- dropped Linux capabilities;
- `no-new-privileges`;
- CPU/memory/PID limits;
- bounded tmpfs;
- mount policy;
- bounded stdout/stderr capture;
- MCP stdin attachment where required.

Capability adapters must not reimplement container command construction.

## Image identity and immutable execution

A normal capability image publishes at least:

```text
org.opencontainers.image.version
io.safe-reverser.capability.id
io.safe-reverser.capability.api
io.safe-reverser.worker.abi
```

The Runtime Driver:

```text
requested image reference
        ↓
inspect / pull as provisioning policy
        ↓
verify required OCI labels
        ↓
resolve canonical sha256 image ID
        ↓
execute the immutable image ID
```

This closes the mutable-tag inspect/run TOCTOU gap.

Readiness exposes both requested `image` and verified `image_id`.

A long-lived control-plane instance keeps the verified immutable image identity for that worker instance; a tag mutation does not silently switch already-running code.

Generic development/test override:

```text
SAFE_REVERSER_CAPABILITY_IMAGE_<CAPABILITY_ID>
```

with `-` normalized to `_` and uppercase.

Legacy pre-0.3 image aliases may exist as configuration compatibility aliases only; image lifecycle remains Runtime Driver-owned.

## Exact runtime-cache identity

Frameworks that require compiler/runtime-specific analyzers may derive a registry-independent cache identity.

Flutter binds:

```text
cache schema
Capability API
Worker ABI
Dart version
snapshot hash
architecture
OS
compressed-pointers mode
Blutter commit
```

The host maps the cache tag to a configured repository, verifies all required labels, resolves an immutable image ID, and executes that ID.

The analyzer worker never clones/builds/downloads a missing Dart runtime during normal analysis.

## Path contract

Host filesystem operations use the shared Path SDK and reject:

- absolute user artifact paths where project-relative paths are required;
- lexical escape;
- resolved escape;
- symlinked path components;
- symlinked data roots;
- unsafe deletion targets;
- oversized metadata.

Directory roots are checked before creation/canonicalization so a symlinked parent is not intentionally traversed first and rejected afterward.

Current path policy addresses untrusted-artifact and ordinary symlink substitution. If hostile same-UID filesystem races enter the threat model, critical operations should move toward dirfd/openat/openat2-style primitives without changing Capability SPI.

## Analysis jobs

Capability-specific jobs use the shared `AnalysisJobStore`:

```text
<data-root>/<capability-id>/jobs/<12-hex-job-id>/
```

The store provides:

- non-predictable bounded IDs;
- private directories;
- atomic bounded metadata writes;
- metadata/directory identity checks;
- bounded returned job count;
- hard filesystem entry scan budget.

Capability-private artifacts/indexes may live in the job directory subject to capability-specific bounds.

## Private indexes and shared evidence

Optimized analyzer storage remains private:

```text
DEX SQLite
Flutter SQLite
future native/IR/Hermes/IL2CPP caches
```

The public compatibility descriptor includes:

```text
capability id
Capability API
Worker ABI
operation
EvidenceEnvelope version
```

When valid material provenance is available, the control plane emits an `EvidenceEnvelope` with:

```text
schema version
analysis id
artifact SHA-256
producer capability
producer version
evidence state
operation/provenance payload
limitations
```

Evidence state is strictly:

```text
observed
derived
hypothesized
```

No numeric confidence is fabricated by the platform.

PEG remains the long-lived semantic model. New data-flow/security/dynamic/native capabilities add evidence/relations rather than replacing the shared evidence architecture.

## Routing and readiness

Framework routing and deployment readiness are separate facts.

A route declares topology such as:

```text
primary_capability_id = framework-flutter
```

The host control plane enriches the shared `analysis_route` shape with runtime state:

```text
declared
installed
ready
degraded
unavailable
unsupported
```

A fingerprint worker must not claim an external analyzer image/runtime is ready merely because the framework is detected.

## Adding a capability

A normal new capability should require only:

1. a validated manifest;
2. an existing adapter kind, or a new narrowly scoped adapter registered behind the adapter factory;
3. an isolated worker image/analyzer implementation;
4. deterministic tests and capability-specific CI;
5. shared provenance/evidence normalization;
6. Worker ABI-compatible diagnostics.

It must not require:

- another public MCP;
- another generic Runtime Driver;
- another generic job store;
- another host path implementation;
- another evidence-state model;
- another top-level public health implementation;
- operation-name-specific dispatch branches;
- privilege expansion of unrelated capabilities.

## CI extension rule

Central platform CI validates **invariants and release baseline requirements**, not an exact forever set of all capability IDs.

For example, 0.3 may require at least:

```text
static-core
framework-flutter
```

but a compatible future optional manifest must not fail solely because it is an additional capability.

Capability-specific build/integration checks may still explicitly name the capability they test.

## Public operation schema compatibility

Worker ABI v1 currently validates declared public operation ownership/tool names and diagnostics behavior.

That is sufficient for the 0.3 foundation but is not the final 1.0 compatibility policy.

Before 1.0, public semantic operations must gain a stable compatibility rule for:

- input schema changes;
- required/optional arguments;
- externally meaningful output fields;
- error/partial/unsupported semantics.

A future implementation may use per-operation contract versions, normalized schema hashes, or another deterministic compatibility mechanism. Operation-name equality alone must not be treated as a permanent 1.0 ABI guarantee.

## Compatibility rules

The following require explicit platform review:

- Capability API change;
- Worker ABI change;
- EvidenceEnvelope breaking change;
- trust-boundary/activation semantic change;
- Runtime Driver privilege expansion;
- path/job security invariant change;
- operation ownership conflict;
- internal diagnostics ABI change;
- verified immutable-image execution change;
- runtime-cache identity change that could reuse incompatible code;
- externally breaking public operation schema change.

A capability-private parser/index may evolve without changing Capability API when externally observable semantics remain compatible.
