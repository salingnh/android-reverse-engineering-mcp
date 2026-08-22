# Repository Rules for Coding Agents

Read these before changing code:

1. `docs/PROJECT_DIRECTION.md` — canonical architecture/product direction.
2. `docs/CAPABILITY_SPI.md` — Capability API, Worker ABI, sandbox and evidence contracts.
3. `docs/DEVELOPMENT.md` — mandatory development/review/CI rules.
4. `docs/ROADMAP.md` — current milestone and acceptance criteria.

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
- Do not introduce a mechanism known to be replaced in the next roadmap milestone.

Before considering work complete:

- run relevant unit/regression/integration checks;
- perform dead-reference/code sweep;
- update all affected durable docs in the same change;
- report remaining Blocker/High/Medium findings explicitly;
- require exact-head CI before merge;
- require senior acceptance for platform/milestone contract changes.

Do not bypass these rules to make a test pass. If a change requires a breaking platform/security contract change, document the architecture decision, migration path, compatibility tests, and version impact first.
