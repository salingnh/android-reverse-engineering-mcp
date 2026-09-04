# Auth, Token, Signing, and Crypto Semantics

Stage H adds a bounded security-semantic overlay on top of the canonical Program Model and the Stage F/G Flow IR. It does **not** add a second data-flow engine, a grep-based security architecture, or backend-specific public MCP operations.

## Architecture

```text
Public semantic query
  find_auth_flow / trace_crypto
              ↓
Security Semantic Query Layer
              ↓
SecuritySignal overlay anchored to Flow IR
              ↓
FlowDocument + explicit FlowGap records
              ↓
representation-owned evidence producer
              ↓
Canonical Program Model / structured analyzer evidence
```

The security layer consumes proven value-flow evidence. Structural `CALLS` / `XREF` topology may localize analysis but is never promoted to a security flow.

Stage H keeps Flow IR generic. Security-specific categories are represented in an independent, bounded overlay rather than adding auth/vendor/crypto fields to `FlowNode` or `FlowEdge`.

## Durable security overlay

A `SecuritySignal` is a deterministic semantic annotation anchored to exactly one existing Flow IR record:

- `FLOW_NODE`
- `FLOW_EDGE`
- `FLOW_GAP`

A signal contains only bounded semantic categories, safe enum-like metadata and evidence references. It never contains raw token, API-key, signing-key, password, IV/key material, request body, or arbitrary source text.

Initial signal kinds are grouped by semantic role rather than analyzer implementation:

### Authentication / token

- `AUTHORIZATION_HEADER_SINK`
- `API_KEY_HEADER_SINK`
- `API_KEY_QUERY_SINK`
- `TOKEN_SOURCE_BOUNDARY`
- `REFRESH_TOKEN_SOURCE_BOUNDARY`
- `TOKEN_EXCHANGE_SINK`
- `BEARER_SCHEME_MARKER`

### Signing / crypto

- `HMAC_KEY_INPUT`
- `HMAC_PAYLOAD_INPUT`
- `HMAC_OUTPUT_BOUNDARY`
- `SIGNATURE_HEADER_SINK`
- `SIGNATURE_QUERY_SINK`
- `CRYPTO_KEY_INPUT`
- `CRYPTO_IV_INPUT`
- `AES_PAYLOAD_INPUT`
- `AES_OUTPUT_BOUNDARY`
- `CRYPTO_ALGORITHM_MARKER`

### External boundaries

- `IDENTITY_SDK_BOUNDARY`
- `PAYMENT_SDK_BOUNDARY`

Vendor identity is evidence/rule data, not a public architecture dimension. A future provider can add new vendor rules without changing the semantic operation contract.

## Signal evidence versus findings

A string, field name, method signature, annotation or SDK call can create a **signal**, but cannot by itself create a complete security finding.

A complete finding requires a bounded path over real `FlowEdge` records. `FlowGap` records are never silently traversed.

The result therefore separates:

1. `findings`: proven semantic flows whose contributing path contains only Flow edges;
2. `signals`: bounded semantic evidence that may help localize a flow;
3. `boundaries`: relevant `FlowGap` records, including external crypto/SDK calls;
4. `truncated`: explicit resource-limit state.

Known standard-library or SDK calls can classify a boundary (for example a `Mac.doFinal` invocation), but the boundary does not become a generic `FLOWS_TO` edge. Input and output evidence remain separated when the external implementation or receiver alias is not proven.

This distinction prevents Stage H from laundering a call-site heuristic into a proven data-flow claim.

## Public operations

### `find_auth_flow`

Find bounded authentication/token flows rooted at one canonical function.

The operation supports durable focus values:

- `any`
- `authorization_header`
- `bearer`
- `refresh_token`
- `api_key`

Initial DEX semantics include:

- value reaching an `Authorization` header-value argument;
- bearer-scheme evidence when the scheme participates in the same bounded flow neighborhood;
- API-key value reaching a recognized header/query parameter sink;
- refresh/access token source boundaries identified from structured storage/identity SDK contracts;
- token-exchange sink evidence when a recognized structured call contract is present.

A mention of `Authorization`, `Bearer`, `access_token`, `refresh_token`, or `x-api-key` with no proven value path produces at most a signal and never a complete finding.

### `trace_crypto`

Find bounded signing/cryptographic semantics rooted at one canonical function.

The operation supports durable family values:

- `any`
- `hmac`
- `aes`

Initial DEX semantics include structured evidence around standard cryptographic call contracts, including HMAC key/payload/output boundaries and AES key/IV/payload/output boundaries.

Because Java crypto implementations are normally platform/external code, Stage H preserves those calls as explicit boundaries. The operation reports the app-side proven paths into and out of the boundary without inventing a complete path through the external body. If future receiver-alias or library-summary evidence proves the boundary contract, it can extend the same overlay without replacing the public API or Flow IR.

## Rule registry

Representation-owned producers use immutable versioned rule data for protocol labels and structured method contracts. Rules are data, not branching public architecture.

Rules may classify:

- safe protocol/header names (`Authorization`, `x-api-key`, signature headers);
- token-storage key names (`access_token`, `refresh_token`);
- non-secret algorithm labels (`HmacSHA256`, `AES/GCM/NoPadding`);
- known HTTP builder method contracts;
- standard Java crypto method contracts;
- identity/payment SDK boundaries.

Rules must never publish matched raw values. Constant-derived output is limited to an allowlisted semantic marker and the existing SHA-256 constant fingerprint.

## DEX evidence producer

The initial producer extends the existing structured Androguard/Dalvik normalization path. It must use instruction operands, normalized exact call targets, Flow IR argument/return nodes and canonical Program Model ownership.

It must **not** use decompiler-text grep as the source of truth for a finding.

Existing source/network heuristics can be used only as bounded localization hints; a security finding still requires the Stage H signal + Flow IR evidence model.

The producer remains offline inside `static-core` and does not change runtime sandbox policy.

## SDK boundaries

Identity and payment SDK crossings remain visible as explicit external boundaries. Stage H does not recursively analyze third-party implementation code by default and does not convert SDK presence into an authentication/payment finding.

Representative examples:

- Firebase token retrieval is represented as an identity-token source boundary plus app-side flow evidence;
- Stripe/Braintree/payment SDK calls remain payment boundaries unless app-side value evidence establishes an additional semantic relationship.

## Secret handling

Security output is deliberately non-secret:

- raw token/API-key/password/key/IV values are forbidden;
- constant Flow IR nodes remain opaque and fingerprinted;
- protocol/algorithm markers are enum-like categories, not arbitrary strings;
- evidence references remain bounded canonical references;
- no decompiled source text is embedded into security findings.

## Resource bounds

Initial hard bounds:

- signals per analysis: 512;
- findings per query: 100;
- relevant boundaries per query: 256;
- security path depth: 32;
- security path exploration states: 10,000;
- serialized security result: 256 KiB hard maximum.

Exhausted limits fail closed or set `truncated=true`; they never silently broaden search or omit uncertainty while claiming completeness.

## Representative Stage H scenarios

Acceptance fixtures must cover:

1. bearer/access-token value -> Authorization header sink;
2. refresh-token source boundary -> token exchange sink;
3. API-key value -> header sink;
4. API-key value -> query parameter sink;
5. HMAC key and payload inputs around a signing boundary, with signature sink evidence;
6. AES key/IV/payload around a crypto boundary and output use;
7. Firebase/identity SDK token boundary preservation;
8. payment SDK boundary preservation;
9. negative string-only mentions of `Authorization`, `HMAC`, `AES`, `Bearer`, or token names -> zero complete findings;
10. CALLS/XREF-only evidence -> zero complete findings;
11. raw secret literals absent from serialized output;
12. gaps never become complete Flow paths;
13. resource limits fail closed.

## Public ownership and routing

`find_auth_flow` and `trace_crypto` are control-plane-owned semantic operations. Capability manifests do not publicly own them. The host routes by `job_id + representation` to internal worker ABI hooks.

Stage H initially advertises only `representation="dex"`. Flutter/native providers can later implement the same security overlay and operations without replacing the public contract.

MCP `initialize` / `tools/list` remain host-local and zero-container.

## Non-goals

Stage H does not:

- expose `run_flowdroid`, `run_soot`, Androguard or SQLite operations publicly;
- claim whole-app taint soundness/completeness;
- treat string matches, CALLS or XREF as data flow;
- silently traverse reflection/native/dynamic/external gaps;
- persist a second security graph/database;
- add worker network/build privileges;
- expose raw secrets;
- claim receiver-alias proof that Stage G does not provide.

## Long-Term Architecture Review

1. Component expected to survive to 1.0: **YES** — security semantics remain an overlay over canonical Program Model + Flow IR.
2. Future roadmap extension requires replacement: **NO** — new producers/rules add evidence to the same signal/query contracts.
3. Knowingly transitional public API introduced: **NO** — `find_auth_flow` and `trace_crypto` are representation-neutral semantic operations.
4. Known schema/data migration already required: **NO** — no persistent security schema is introduced.
5. Analyzer/provider/storage detail leaked publicly: **NO**.
6. Temporary production fallback/compatibility path: **NO**.
7. Technical debt intentionally deferred in architecture: **NO** — unsupported proof is represented explicitly as signals/boundaries rather than hidden fallback behavior.

**Design verdict: PASS.**
