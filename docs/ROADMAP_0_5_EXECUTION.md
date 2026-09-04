# Safe Android Reverser 0.5 Execution Plan

This document is the durable, stage-gated execution plan for milestone **0.5.0 — Security Intelligence**. It refines `ROADMAP.md`; it does not replace the release train or the long-term architecture in `PROJECT_DIRECTION.md`.

All work here is governed by `ARCHITECTURE_EVOLUTION_RULES.md`: incomplete feature coverage is acceptable; knowingly temporary production architecture is not.

Current production baseline: **0.4.0**.

## Execution discipline

Implement exactly one stage at a time:

```text
design
  -> Long-Term Architecture Review
  -> implementation
  -> unit/regression tests
  -> integration tests
  -> architecture/security review
  -> fix Blocker/High
  -> dead-reference sweep
  -> exact-head CI
  -> inspect real CI logs
  -> Gate Report
  -> STOP for senior acceptance
```

Do not begin the next stage automatically. Exact-head means the exact commit under review; an older green run is not sufficient.

Every stage must preserve:

```text
one public MCP control plane                           YES
Program Model / Flow IR / Evidence reused             YES
analyzers remain replaceable evidence producers       YES
rule hit automatically means verified vulnerability   NO
numeric confidence manufactured                       NO
backend/storage schema leaked publicly                 NO
static worker network privileges expanded              NO
temporary compatibility/fallback architecture          NO
```

## Stage 0 — 0.4 Production Baseline Audit

Purpose: prove the released 0.4 platform is a valid base for security intelligence.

Required checks:

- production `VERSION` is `0.4.0`;
- release tag `safe-v0.4.0` and GitHub Release exist;
- release commit is reachable from `master`;
- static-core and framework-flutter immutable release images were published and post-release verified;
- one public MCP and host-owned Runtime Driver remain unchanged;
- `SecuritySemantics` from 0.4 consumes canonical Flow IR and does not treat XREF/CALL adjacency as flow;
- `FlowGap` remains non-traversable evidence of uncertainty;
- EvidenceEnvelope/PEG contracts remain the semantic integration layer;
- no new network privilege is required for 0.5 static analysis;
- exact-head CI baseline is green before Stage A merge.

Stage 0 is an audit, not a new production mechanism.

## Stage A — Durable Security Finding Contract

Define the long-lived finding/lifecycle contract before integrating scanners.

Durable concepts:

```text
RuleIdentity
KnowledgeRef
SemanticAnchor
SecurityFinding
VerificationRecord
```

Lifecycle:

```text
candidate -> probable -> verified / refuted / unknown
```

Rules:

- finding identity is deterministic and stable across lifecycle changes;
- identity is based on analysis snapshot + versioned rule identity + canonical semantic anchor, not title, severity, producer output ordering, or verification result;
- `candidate` and `probable` do not imply verification;
- `verified`, `refuted`, and `unknown` require a `VerificationRecord`;
- terminal verification must be logically independent from the candidate producer;
- findings may reference Program Model entities, Flow IR nodes/edges/paths/gaps, EvidenceEnvelope-compatible evidence, and 0.4 security semantic evidence;
- CWE/MASWE/MASVS/MASTG references are knowledge metadata, not verdicts;
- no numeric confidence field;
- bounded text, reference counts, anchors, paths and limitations;
- no public `scan_security` operation yet in Stage A.

The existing 0.4 `security_semantics.SecurityFinding` is a proven semantic-flow result, not the 0.5 vulnerability lifecycle record. Stage A deliberately keeps these concepts separate and allows the 0.5 finding to reference 0.4 semantic evidence.

Gate branch: `feat/0.5-security-finding-model`.

## Stage B — Security Knowledge Registry

Introduce a versioned, backend-independent security knowledge layer.

Conceptual data:

```text
SecurityRule
RuleRevision
Source/Sink/Sanitizer expectations
CWE / MASWE / MASVS / MASTG mappings
applicability / representation constraints
verification requirements
```

Rules are data, not dispatch architecture. Semgrep/mobsfscan rule IDs may be mapped as producer metadata, but public behavior must not depend on those engines existing.

Required properties:

- deterministic rule identity/versioning;
- bounded loading and validation;
- no arbitrary executable rule payload in MCP requests;
- explicit positive and negative fixture ownership;
- future rule revisions do not silently mutate historical finding identity.

Gate branch: `feat/0.5-security-knowledge`.

## Stage C — Candidate Evidence Producers

Add replaceable static candidate producers behind the existing capability architecture.

Candidate producer classes may include:

```text
Semgrep adapter
mobsfscan adapter
project-native semantic rules
manifest/resource/package checks
```

They produce normalized candidate evidence; they do not own the finding lifecycle or verification verdict.

Required properties:

- workers remain `network=none`;
- no raw analyzer console exposed publicly;
- analyzer-specific storage/output remains private;
- candidate outputs normalize into the Stage A contract;
- malformed or oversized analyzer output fails closed;
- duplicate candidates deterministically coalesce by finding identity.

Gate branch: `feat/0.5-security-producers`.

## Stage D — Security Investigator and `scan_security`

Introduce the durable semantic operation:

```text
scan_security
```

Architecture:

```text
scan_security
    -> Security Investigator
         -> knowledge registry
         -> candidate producer(s)
         -> Program Model / Flow IR / 0.4 security semantics
         -> normalized candidate/probable findings
```

`scan_security` returns bounded semantic findings and coverage/provenance metadata. It never reports a producer hit as verified by default.

Planner/investigator logic must localize expensive analysis using application map, ownership, existing flow evidence and representation routing.

Gate branch: `feat/0.5-security-investigator`.

## Stage E — Finding Explanation and `explain_finding`

Add:

```text
explain_finding
```

Explanation is a bounded evidence projection, not free-form decompiler output.

It should surface:

- rule/version and knowledge mappings;
- semantic anchors and ownership;
- relevant Program Model neighborhood;
- proven Flow IR path/gaps when present;
- producer provenance;
- limitations and missing evidence;
- verification status without inventing confidence.

Gate branch: `feat/0.5-security-explanation`.

## Stage F — Independent Verifier and `verify_finding`

Add a logically independent verification path:

```text
verify_finding
    -> Security Verifier
         -> deterministic reachability/data-flow/semantic checks
         -> later optional runtime evidence from 0.6
         -> VerificationRecord
```

The verifier must not merely replay the candidate producer and call agreement verification.

Supported outcomes:

```text
verified
refuted
unknown
```

`unknown` is a first-class result when reflection/native/framework/runtime gaps prevent a sound conclusion.

Required regression: XREF-only adjacency, string-only markers and untraversable FlowGap evidence cannot promote a finding to `verified`.

Gate branch: `feat/0.5-security-verifier`.

## Stage G — Coverage Model, False-positive Corpus and `coverage_report`

Add:

```text
coverage_report
```

Coverage is explicit about what was and was not analyzed:

- representations covered/unsupported;
- rules applicable/executed/skipped;
- semantic prerequisites available/missing;
- ownership scope;
- flow/reachability coverage;
- truncation/resource-limit effects;
- analyzer/verification limitations.

Promoted rules require deterministic positive and negative regression fixtures. False-positive regressions are release gates for rules allowed to reach `probable` or verification workflows.

Gate branch: `feat/0.5-security-coverage`.

## Stage H — Integrated Security Capability and Cross-operation Consistency

Integrate the four public security operations behind existing manifest/adapter routing:

```text
scan_security
explain_finding
verify_finding
coverage_report
```

Required consistency:

- all operations use the same finding identity and schema;
- no duplicate public MCP or generic runtime wrapper;
- findings link back to canonical Program Model/Flow IR/Evidence;
- producer and verifier roles remain logically distinct;
- bounded output and explicit partial/unsupported states;
- static workers remain offline and unprivileged;
- analyzer names remain provenance, never the semantic API.

Gate branch: `feat/0.5-security-integration`.

## 0.5 Milestone Acceptance

Only after Stages A-H are individually accepted.

Run clean end-to-end validation covering:

- MCP discovery and one-public-MCP invariant;
- deterministic candidate finding identity;
- candidate/probable/verified/refuted/unknown lifecycle;
- positive and negative security corpus;
- Semgrep/mobsfscan/project-native producer substitution where packaged;
- explanation evidence fidelity;
- independent verification;
- XREF-only/string-only/FlowGap false-positive regressions;
- coverage reporting;
- native Android and available Flutter semantic evidence integration;
- cleanup, resource bounds, sandbox and network policy;
- exact-head CI and locked-image tests where capability images change.

Verify:

- no analyzer/provider/storage-specific public API;
- no producer hit automatically becomes verified;
- no numeric confidence;
- no static worker network;
- no leaked secrets or raw token/key material in findings;
- no temporary architecture expected to be replaced by 0.6/0.7/0.8/0.9;
- durable docs match implementation.

Do not release 0.5.0 until a separate senior milestone/release acceptance is recorded.

## Required Gate Report

Every stage reports at least:

- stage, branch and exact head SHA;
- implemented scope and non-goals;
- files and public operations changed;
- schema/platform contract impact;
- trust-boundary/resource-bound impact;
- exact unit/regression/integration/E2E tests and results;
- architecture/security reviews;
- Blocker/High/Medium findings and known limitations;
- dead-code/reference sweep;
- exact-head workflow/run/result;
- Long-Term Architecture Review result;
- final verdict `READY FOR SENIOR REVIEW` or `BLOCKED`;
- proposed next stage;
- then STOP.
