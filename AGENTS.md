# Repository Rules for Coding Agents

Read these before changing code:

1. `docs/PROJECT_DIRECTION.md` — canonical architecture/product direction.
2. `docs/ARCHITECTURE_EVOLUTION_RULES.md` — mandatory no-throwaway architecture and long-term evolution gate.
3. `docs/CAPABILITY_SPI.md` — Capability API, Worker ABI, sandbox and evidence contracts.
4. `docs/DEVELOPMENT.md` — mandatory development/review/CI rules.
5. `docs/ROADMAP.md` — current milestone and acceptance criteria.

Mandatory invariants:

- Keep exactly one public `safe-android-reverser` MCP control plane.
- Do not create framework-specific public MCP servers.
- Only the host Runtime Driver may invoke Docker/Podman; never mount runtime sockets into workers.
- Keep static/framework/native-static workers offline (`network=none`) and locked down.
- Dynamic privileges require `dynamic-opt-in` + `activation=opt-in`; do not weaken static workers.
- Dispatch public operations through manifest ownership and adapters; do not add operation-name/framework switches to the control plane.
- Reuse shared runtime/path/job/evidence infrastructure; do not duplicate it in capability modules.
- Keep framework-specific semantics in framework capabilities. `static-core` owns generic Android/DEX/JVM/resource triage and routing preflight, not deep semantics for every framework.
- Prefer semantic bounded operations over raw analyzer consoles or generic shell/exec surfaces.
- Preserve provenance and `observed` / `derived` / `hypothesized` evidence states. Never invent numeric confidence.
- CALLS/XREFS are not proven data flow.
- Bound traversal, archive entries, bytes, CPU/time, memory/storage, process output, filesystem scans, and returned results.
- Verify worker/runtime images by required OCI labels and execute immutable image IDs.
- CI should validate invariants and required baseline capabilities, not hard-code the forever-complete capability set.
- **Do not merge temporary production architecture. Every accepted mechanism must be expected to survive as a valid abstraction through the intended 1.0 architecture and be extensible without planned replacement.**
- Feature coverage may be incomplete; architectural direction may not knowingly be temporary.
- Analyzer, provider, registry, CI, or storage implementation details must not leak into durable public semantic contracts.
- Do not add temporary fallback/compatibility paths merely to preserve a product model that project direction has rejected.

Before implementing any non-trivial stage, perform the pre-implementation review in `docs/ARCHITECTURE_EVOLUTION_RULES.md`. If the design is already known to require replacement in a later milestone, stop and redesign before writing production code.

Before considering work complete:

- run relevant unit/regression/integration checks;
- perform architecture and security review;
- fix all Blocker and High findings;
- perform dead-reference/code sweep;
- update all affected durable docs in the same change;
- report remaining Blocker/High/Medium findings explicitly;
- require exact-head CI before merge;
- complete the Long-Term Architecture Review from `docs/ARCHITECTURE_EVOLUTION_RULES.md`;
- require senior acceptance for platform/milestone contract changes.

The required Long-Term Architecture Review result is:

```text
1. Component expected to survive to 1.0:                 YES
2. Future roadmap extension requires replacement:        NO
3. Knowingly transitional public API introduced:         NO
4. Known schema/data migration already required:          NO
5. Analyzer/provider/storage detail leaked publicly:      NO
6. Temporary production fallback/compatibility path:      NO
7. Technical debt intentionally deferred in architecture: NO
```

Any other result means `VERDICT = BLOCKED`.

Do not bypass these rules to make a test pass. If a change requires a breaking platform/security contract change, document the architecture decision, migration path, compatibility tests, version impact, and senior approval first.
