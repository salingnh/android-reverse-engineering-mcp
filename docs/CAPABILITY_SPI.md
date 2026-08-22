# Capability SPI v1

## Purpose

Safe Android Reverser uses a single host-side MCP control plane and isolated analyzer workers. This document defines the stable extension contract introduced for release 0.3.0.

The architectural invariant is:

> The agent reasons. The MCP control plane controls. Capability workers execute.

A framework, native backend, security engine, or dynamic backend is added as a **capability module** behind this contract. It must not introduce another public MCP control plane or require the agent to select a container/runtime implementation directly.

## Stability rule

From 0.3.0 onward, do not introduce a mechanism that is already known to be replaced by the next roadmap milestone. Later milestones extend implementations behind these contracts:

- Capability SPI;
- Worker ABI;
- Runtime Driver;
- analysis/job lifecycle;
- artifact/path safety primitives;
- evidence/PEG contracts.

A breaking change to one of these contracts requires:

1. an Architecture Decision Record or equivalent decision-log entry;
2. an explicit migration path;
3. compatibility/regression tests;
4. senior architecture/security review;
5. a versioned contract transition rather than silent behavior drift.

Internal implementation details may evolve without being a breaking architecture change. For example, replacing one-process-per-call worker scheduling with a bounded worker pool is allowed if the public MCP surface, Capability SPI, Worker ABI, sandbox policy, analysis IDs, and evidence contracts remain compatible.

## Topology

```text
AI agent
   |
   v
safe-android-reverser MCP
host control plane
   |
   +-- Capability Registry
   +-- Runtime Driver
   +-- shared path/artifact policy
   +-- shared analysis job store
   +-- shared evidence contracts / PEG
   |
   +-- static-core worker
   +-- framework-flutter worker
   +-- future native worker
   +-- future framework-hermes worker
   +-- future framework-il2cpp worker
   +-- future dynamic worker
```

Only the host control plane may invoke Docker or Podman. A worker does not receive a Docker/Podman socket and does not spawn another capability worker.

## Capability manifest

Capability manifests live under:

```text
plugins/safe-android-reverser/capabilities/
```

A manifest declares topology and compatibility, not runtime readiness.

Example:

```json
{
  "id": "framework-flutter",
  "capability_api": 1,
  "worker_abi": 1,
  "representations": ["dart-aot", "libapp.so", "flutter-assets"],
  "trust_boundary": "framework-static",
  "protocol": "cli-json",
  "image": {
    "repository": "ghcr.io/salingnh/safe-android-reverser-flutter",
    "role": "framework-flutter"
  },
  "operations": [
    "analyze_flutter_aot",
    "find_dart_symbols"
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

The registry rejects duplicate public operation ownership. A capability cannot silently shadow another capability's operation.

## Capability API v1

`capability_api=1` defines the host/control-plane contract. It covers:

- manifest structure;
- operation ownership;
- runtime readiness states;
- sandbox-policy interpretation;
- result compatibility metadata;
- host-owned image selection.

Runtime readiness states are:

```text
declared
installed
ready
degraded
unavailable
unsupported
```

Framework routing may declare a capability without claiming that the corresponding worker image is currently ready. The host control plane is the authority for actual readiness.

## Worker ABI v1

Every worker image must carry OCI labels:

```text
io.safe-reverser.capability.id
io.safe-reverser.capability.api
io.safe-reverser.worker.abi
org.opencontainers.image.version
```

The control plane verifies these labels before executing the worker.

Exact runtime-cache workers may add compatibility labels. Flutter runtime workers currently bind:

```text
io.safe-reverser.runtime-cache.schema
io.safe-reverser.blutter.commit
io.safe-reverser.dart.version
io.safe-reverser.dart.snapshot
io.safe-reverser.dart.arch
io.safe-reverser.dart.compressed-pointers
```

The exact cache tag is derived from the runtime identity and cache schema. Changing the runtime worker ABI/cache contract therefore produces a new immutable cache namespace rather than reusing an incompatible old image.

## Worker protocols

Capability SPI v1 supports worker protocols including:

- `mcp-stdio` for a worker that already exposes bounded MCP semantics;
- `cli-json` for a narrowly scoped capability command adapter.

The protocol is an implementation transport behind the control plane. It is not exposed to the AI agent.

`static-core` currently uses `mcp-stdio`; `framework-flutter` uses `cli-json`.

## Runtime Driver

Container lifecycle is centralized in the shared Runtime Driver. Capability-specific code must not duplicate Docker/Podman orchestration.

For static/framework-static workers the invariant is:

```text
network = none
read-only root = true
capabilities = dropped
no-new-privileges = true
non-root user
bounded CPU/memory/PIDs/tmpfs
explicit read-only/read-write mounts
```

Runtime image pulling is host-side provisioning. Analyzer code remains offline. Runtime build-on-demand inside an analysis worker is forbidden.

## Artifact and path safety

Host-side modules use shared path-policy primitives for:

- project-relative artifact resolution;
- symlink rejection;
- containment checks;
- atomic bounded metadata writes;
- safe cleanup of direct job children.

Worker-side archive parsers still enforce their own untrusted-input limits because workers must not trust the host to sanitize archive contents.

Archive limits include entry count, path length, per-member size, aggregate extraction size, and explicit supported artifact formats.

## Analysis jobs

Persistent analysis state uses the shared `AnalysisJobStore` abstraction. Capability-specific analyzers may keep optimized local indexes inside their job directories.

Example:

```text
plugin data
  +-- static-core/jobs/<job-id>/...
  +-- framework-flutter/jobs/<job-id>/
      +-- job.json
      +-- analysis/
          +-- flutter-index.sqlite
```

The optimized index format is private to the capability. It is not the cross-capability platform contract.

## Evidence contract

Analyzer-native result schemas may remain optimized for their domain. Before returning material results to the agent, the control plane adds:

```text
safe_reverser_contract
```

containing:

```text
capability_id
capability_api
worker_abi
operation
evidence_envelope_version
```

When the producer provides a valid `analysis_id`, artifact SHA-256, and evidence state, the control plane also attaches a common `evidence_envelope`.

Evidence states remain strictly:

```text
observed
derived
hypothesized
```

The platform never manufactures a numeric confidence value.

The private Flutter SQLite index therefore remains valid across later milestones. Data-flow, security, native, and dynamic capabilities add evidence producers and PEG relations; they do not require replacing the Flutter index or the host orchestration architecture.

## Framework routing

Framework routing answers:

> Which representation and capability should be primary?

It does not answer:

> Is that worker installed and ready right now?

The static-core router returns `primary_capability_id`. The host control plane enriches the route with current capability state.

This separation avoids hard-coding deployment/runtime conditions in package fingerprinting logic.

## Adding a new capability

A new capability should normally require only:

1. a manifest under `capabilities/`;
2. a worker image or isolated implementation;
3. a small capability-specific adapter if its protocol is not MCP;
4. deterministic tests and fixtures;
5. its own worker CI;
6. participation in control-plane contract/integration tests;
7. PEG/evidence normalization for material facts.

It must not require:

- a second public MCP server;
- a new generic Docker/Podman wrapper;
- copied job/path/image lifecycle code;
- a new evidence architecture;
- analyzer downloads/builds during normal offline analysis.

## Planned reuse

Roadmap milestones consume the same foundation:

```text
0.3  platform foundation + Flutter
0.4  data-flow capability/engine -> same evidence/PEG contract
0.5  security intelligence -> same evidence/PEG contract
0.6  dynamic capability -> same control plane and capability registry
0.7  native/JNI capability -> same Runtime Driver and contracts
0.8  Hermes/IL2CPP/.NET capabilities -> same SPI
0.9  verifier/pattern discovery -> shared evidence graph
1.0  compatibility and contract stability
```

No milestone is planned to replace the single-control-plane/capability architecture established in 0.3.0.
