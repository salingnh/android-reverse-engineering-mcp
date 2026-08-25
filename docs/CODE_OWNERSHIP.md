# Code Ownership Semantics

Status: Stage B durable platform contract for program-understanding queries.

This document defines how Safe Android Reverser separates application code from packaged SDK, platform and generated implementation noise without deleting evidence. The classifier is a semantic platform component, not a package-filtering workaround. Future application-map, context-retrieval, data-flow, security and native/framework correlation stages consume this model and may add evidence producers without replacing its scope semantics.

## Ownership scopes

Every class/method ownership decision uses exactly one of:

- `FIRST_PARTY`: evidence identifies code as belonging to the analyzed application.
- `THIRD_PARTY`: evidence identifies a packaged library/SDK implementation.
- `PLATFORM`: Android/Java/Kotlin platform or framework infrastructure.
- `GENERATED`: compiler/build/code-generation output whose implementation is normally not an application reasoning target.
- `UNKNOWN`: evidence is insufficient. Unknown is not treated as third-party.

`Androguard external` is not an ownership signal. It only states that a method implementation is absent from the analyzed DEX graph.

## Query scopes

Ownership is exposed through stable semantic query scopes:

- `application` (default): `FIRST_PARTY + UNKNOWN`
- `all`
- `first_party`
- `third_party`
- `platform`
- `generated`
- `unknown`

The default intentionally includes `UNKNOWN`. This is fail-conservative behavior: obfuscated application code must remain visible unless stronger evidence proves another scope.

## Evidence and precedence

`CodeOwnershipClassifier` consumes bounded evidence. Stage B uses decoded Android manifest context plus a versioned ownership-rule registry and generated-code name patterns. Future evidence such as resource namespace, BuildConfig evidence, entrypoint reachability or framework-specific metadata can be added behind the same classifier contract.

Current precedence is designed to avoid common false ownership claims:

1. A known third-party/platform namespace remains authoritative over a merged manifest component. For example, `FirebaseInitProvider` appearing in the merged app manifest remains Firebase code.
2. A genuinely more-specific application namespace can override a broader known vendor prefix. For example, an application whose real namespace is `com.google.firebase.demo` remains first-party under that namespace while `com.google.firebase.auth.*` remains Firebase.
3. Strong generated-code naming evidence classifies generated implementation after vendor/platform precedence, so generated-looking names inside an SDK do not overwrite SDK ownership.
4. Application namespace evidence classifies ordinary code under the app namespace as first-party.
5. An exact manifest component can identify an obfuscated component such as `a.a` as first-party even when it is outside the application package namespace.
6. Otherwise the result is `UNKNOWN`. Short/obfuscated package names are never guessed to be third-party.

Classification results include scope, owner/SDK when known, reasons and evidence. Rule data is versioned and hashed so an analysis response can state which classifier model produced the result.

## Rule registry

`sandbox/ownership_rules.json` is data, not architecture. It contains known namespace ownership and narrowly defined generated-code patterns. Adding a new SDK means extending the registry; it must not require adding vendor-specific conditionals to symbol, XREF, network or future data-flow tools.

Generated patterns must be conservative. Broad patterns such as generic `*_Impl` are prohibited because legitimate application implementations commonly use that naming convention.

## Boundary preservation

Third-party implementation is suppressed from default application-oriented root searches, but direct application-to-non-application XREF edges remain evidence.

Example:

```text
AuthRepository.loginWithFacebook()
        |
        v
[Facebook SDK boundary]
```

The default view must not expand hundreds of Facebook implementation methods merely because the SDK is packaged in the APK. An analyst may explicitly use `scope=third_party` or `scope=all` when investigating the integration itself.

Boundary retention is structural evidence only. A `CALLS`/XREF edge must never be relabeled as true value/data flow.

## Network reconstruction

`extract_network_model` defaults to `scope=application`. Source files that are definitely `THIRD_PARTY`, `PLATFORM` or `GENERATED` are not scanned in that mode. `FIRST_PARTY` and `UNKNOWN` remain eligible. Endpoint/URL/auth evidence is annotated with ownership.

This reduces Firebase/Facebook/OkHttp/etc. implementation noise without deleting their existence from the program graph. Explicit scope expansion remains available.

## Resource and safety rules

- Ownership rules are bounded and schema-validated.
- Decoded manifests are bounded before parsing.
- DTD/entity declarations are rejected because ownership extraction never needs them and the manifest is attacker-controlled artifact data.
- Manifest traversal has a component-count bound.
- Symbol ownership filtering uses a bounded scan no larger than the program-index method ceiling; third-party rows cannot consume the response limit before an application row is considered.
- Ownership metadata does not include secret values.

## Long-term evolution

The following are extensions, not replacements:

```text
CodeOwnershipClassifier
        |
        +-- current manifest evidence
        +-- current namespace/rule evidence
        +-- future resource namespace evidence
        +-- future entrypoint/reachability evidence
        +-- future framework ownership producers
        +-- future native/JNI ownership evidence
```

The consumers remain the same:

```text
ownership
  -> symbol/XREF queries
  -> network reconstruction
  -> Canonical Program Model
  -> Application Map
  -> Context Retrieval
  -> Data-flow IR / localized tracing
  -> Security Intelligence
```

No future stage should replace ownership with a separate SDK filtering system.

## Known Stage B coverage limits

Stage B deliberately does not guess ownership for shaded, relocated or fully obfuscated libraries when evidence is insufficient. Those classes remain `UNKNOWN` and therefore visible in the default application scope. Improving recognition requires adding stronger evidence to `CodeOwnershipClassifier`, not weakening the `UNKNOWN` contract or introducing a second filter path.
