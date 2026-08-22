# Safe Reverser Capability SPI v1

## Purpose

Safe Reverser exposes one public MCP control plane and executes analyzers in isolated capability workers. This document defines the platform contract that 0.3.0 establishes and later milestones extend rather than replace.

The stable topology is:

```text
AI agent
   |
   v
safe-android-reverser MCP
host control plane
   |
   +-- Capability Registry
   +-- Runtime Driver
   +-- Path / Job / Evidence contracts
   |
   +-- static-core worker
   +-- framework-flutter worker
   +-- future native / Hermes / IL2CPP / .NET / dynamic workers
```

The agent never chooses Docker/Podman commands and never receives a raw analyzer console. The host control plane is the only layer allowed to invoke the container runtime.

## Versioned contracts

0.3.0 defines:

```text
Capability API       1
Worker ABI           1
EvidenceEnvelope     1
PEG schema           2
Flutter cache schema 2
```

These versions are independent. A future breaking change must use an explicit architecture decision, migration path, compatibility tests, and senior review. A milestone must not knowingly ship a mechanism that the next milestone is expected to replace.

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
  "operations": [
    "analyze_flutter_aot",
    "find_dart_symbols",
    "find_dart_strings"
  ],
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

Unknown manifest fields are rejected. Operation ownership is unique across all declared capabilities.

## Activation contract

`activation` is part of Capability SPI v1:

```text
required
  The release depends on this capability. Its failure degrades overall health.

optional
  The capability is active when installed, but its failure does not make the
  required platform unhealthy.

opt-in
  The capability is declared but inactive until its exact id is explicitly
  enabled through SAFE_REVERSER_ENABLE_CAPABILITIES.
```

A `dynamic-opt-in` trust boundary must use `activation=opt-in`. This rule exists in 0.3.0 so the future dynamic milestone does not need a new orchestration model or public MCP server.

Disabled opt-in capabilities do not expose analyzer tools. They remain visible in `list_capabilities` as declared/not enabled.

## Adapter vs worker protocol

These are deliberately separate concepts.

### `adapter`

The host adapter owns capability-specific orchestration that cannot be expressed by a generic worker transport.

Current adapter kinds:

```text
mcp-container
  Generic MCP-over-stdio worker adapter. Used by static-core.

flutter-aot
  Flutter-specific host orchestration for exact Dart runtime-cache selection,
  followed by bounded CLI JSON worker operations.
```

Adding a new adapter kind extends the adapter factory behind Capability SPI. It must not require changes to public MCP topology, capability dispatch, health aggregation, job ownership, or EvidenceEnvelope semantics.

### `protocol`

The worker protocol describes communication with an analyzer image:

```text
mcp-stdio
cli-json
```

Protocol is not equivalent to framework identity. Multiple capabilities may share a protocol or a generic adapter.

## Runtime Driver contract

The Runtime Driver owns:

- Docker/Podman selection;
- image inspect/pull;
- OCI label verification;
- UID/GID mapping;
- network policy enforcement;
- read-only root;
- dropped Linux capabilities;
- `no-new-privileges`;
- CPU/memory/PID limits;
- bounded tmpfs;
- read-only/read-write mount policy;
- bounded stdout/stderr capture;
- MCP stdin attachment for stdio workers.

Capability adapters must not reimplement container command construction.

### Network policy

Capability SPI v1 reserves two policy values:

```text
none
controlled
```

Rules:

- `static`, `framework-static`, and `native-static` must use `none`;
- only `dynamic-opt-in` may declare `controlled`;
- the 0.3 static Runtime Driver deliberately rejects execution of `controlled` network policy.

A later dynamic Runtime Driver may implement the already-defined `controlled` policy behind the same manifest schema. This is an implementation extension, not a contract replacement.

## Trust boundaries

Current trust-boundary identifiers:

```text
static
framework-static
native-static
dynamic-opt-in
```

Static-style workers keep:

```text
network = none
read-only root = true
cap-drop = ALL
no-new-privileges = true
bounded memory / CPU / PIDs / tmpfs
```

No worker receives a Docker/Podman socket.

## Image identity

A normal capability image must publish at least:

```text
org.opencontainers.image.version
io.safe-reverser.capability.id
io.safe-reverser.capability.api
io.safe-reverser.worker.abi
```

The control plane verifies these labels before execution.

Image repository policy belongs to the host control plane. Workers return analyzer/runtime identity, not deployment repository choices.

Generic test/development override:

```text
SAFE_REVERSER_CAPABILITY_IMAGE_<CAPABILITY_ID>
```

with `-` normalized to `_` and uppercase. Pre-0.3 static/Flutter aliases may remain as compatibility input aliases, but they do not own image lifecycle.

## Exact runtime-cache identity

Frameworks that require compiler/runtime-specific analyzers may return a registry-independent cache key. For Flutter, the immutable cache tag is derived from:

```text
cache schema
Capability API
Worker ABI
Dart version
Dart snapshot hash
architecture
OS
compressed-pointers mode
Blutter commit
```

The host maps the cache tag to the configured repository and verifies all relevant OCI provenance labels before running the image.

The analyzer sandbox never clones/builds/downloads a missing Dart runtime.

## Shared host path contract

Host filesystem operations use the shared path SDK. It rejects:

- absolute user artifact paths where only project-relative paths are allowed;
- lexical path escape;
- resolved path escape;
- symlinked path components;
- symlinked data roots;
- unsafe deletion targets;
- oversized metadata.

Directory roots are checked for existing symlink components before `mkdir`/`resolve`, so path validation does not first traverse an attacker-controlled symlink and reject it only afterward.

## Analysis jobs

Capability-specific jobs use `AnalysisJobStore`:

```text
<data-root>/<capability-id>/jobs/<12-hex-job-id>/
```

The store provides:

- non-predictable bounded job ids;
- private directories;
- atomic bounded `job.json` writes;
- metadata/directory identity checks;
- bounded job listing and a hard directory scan budget.

Analyzer-specific persistent data may live inside the job directory, subject to capability-specific export limits.

## Private indexes and shared evidence

Capability implementations may keep optimized private storage:

```text
DEX SQLite
Flutter SQLite
Ghidra project/cache
Hermes index
future data-flow IR
```

These are implementation details, not competing platform models.

The control plane adds a shared compatibility descriptor to capability results. When a result contains valid provenance, it emits an `EvidenceEnvelope` containing:

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

Evidence states are strictly:

```text
observed
derived
hypothesized
```

The control plane does not invent numeric confidence or fabricate an evidence state when the producer did not provide one.

PEG remains the long-lived semantic model. Later data-flow/security/dynamic capabilities add new evidence and relations; they do not replace private indexes or the EvidenceEnvelope contract.

## Routing and readiness

Framework routing and deployment readiness are separate facts.

A fingerprint route returns topology such as:

```text
primary_capability_id = framework-flutter
primary_profile_status = declared
```

The host control plane then enriches it with runtime state:

```text
primary_capability_state = ready | degraded | unavailable | declared | unsupported
```

A static worker must never claim a framework image is ready merely because the framework was detected.

## Adding another capability

A new capability should normally require only:

1. a validated capability manifest;
2. an existing adapter kind, or a new adapter implementation behind the adapter factory;
3. its isolated worker image and analyzer code;
4. deterministic tests and capability-specific CI;
5. evidence/provenance normalization through the shared contracts.

It must not require:

- another public MCP server;
- another Docker/Podman implementation;
- another generic job store;
- another host path security implementation;
- another evidence-state model;
- changes to agent-facing orchestration topology.

## Compatibility rules

The following are platform-level changes and require explicit review:

- Capability API version change;
- Worker ABI version change;
- EvidenceEnvelope breaking change;
- trust-boundary or activation semantic change;
- Runtime Driver privilege expansion;
- path/job security invariant change;
- operation ownership conflict;
- runtime-cache identity change that could reuse an incompatible image.

A private analyzer parser/index may evolve without changing Capability API when its externally observable contract remains compatible.
