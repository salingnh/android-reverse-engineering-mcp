# Invoke Gap Materialization Invariant

Localized DEX value tracing must preserve uncertainty at the invocation site even when a caller ignores the result or the callee returns `void`.

## Required behavior

For dynamic dispatch, reflection, missing exact targets, native bodies, external ownership boundaries, and resource-budget cutoffs:

- the corresponding `FlowGap` is materialized at the `invoke-*` instruction;
- argument-side known nodes remain gap sources;
- an exact callee return node is used as the gap target when available;
- otherwise a deterministic `UNKNOWN` call-result node anchors the uncertainty;
- a later `move-result*`, when present, may connect the known/unknown result node to the caller-local definition using `RETURN_TO_CALLSITE`;
- absence of `move-result*` must never erase the gap.

A gap remains non-traversable and is never converted into `FLOWS_TO`.

This is a correctness repair to Stage G semantics, not a new public operation or compatibility path.
