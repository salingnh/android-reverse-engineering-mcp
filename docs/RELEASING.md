# Releasing Safe Android Reverser

Safe Android Reverser uses immutable semantic-version releases. From 0.3 onward, one plugin release may require multiple capability images plus exact runtime-cache images.

The release must keep plugin metadata, control-plane version, required capability image provenance, Worker ABI/Capability API, and Git tag consistent.

## Source of truth

Canonical release version:

```text
plugins/safe-android-reverser/VERSION
```

The following must match it:

- plugin manifest version;
- marketplace entry version;
- normal required capability image `org.opencontainers.image.version` labels;
- public MCP `serverInfo.version`.

## 0.3 release topology

```text
safe-android-reverser plugin VERSION
      |
      +-- host control plane
      +-- static-core image
      +-- framework-flutter base image
      +-- exact Flutter runtime-cache images
```

Required baseline capability repositories are defined in manifests, not hard-coded into the launcher.

For 0.3:

```text
ghcr.io/salingnh/safe-android-reverser:<VERSION>
ghcr.io/salingnh/safe-android-reverser-flutter:<VERSION>
```

Exact Flutter runtime-cache images use deterministic runtime identities rather than the plugin semver tag alone.

## Immutable image rule

Published semver images are immutable.

Do not overwrite a broken release tag. Fix source and publish a new patch release.

Runtime Driver verifies requested image labels, resolves canonical image ID, and executes:

```text
sha256:<64 hex image id>
```

rather than re-running the mutable tag after verification.

## Development builds

Pull requests may build/load/test images but do not publish release semver tags.

Pushes to `master` may publish moving development references such as:

```text
<repository>:master
<repository>:sha-<commit>
```

`master` must not overwrite/publish a hard-coded semver release tag.

Capability-specific workflows may publish their own `master`/`sha-*` development references while preserving the same release/version labels.

## Local development overrides

Use generic capability image overrides:

```bash
export SAFE_REVERSER_CAPABILITY_IMAGE_STATIC_CORE=safe-android-reverser:ci
export SAFE_REVERSER_CAPABILITY_IMAGE_FRAMEWORK_FLUTTER=safe-android-reverser-flutter:ci
```

The generic naming convention is:

```text
SAFE_REVERSER_CAPABILITY_IMAGE_<CAPABILITY_ID>
```

with `-` converted to `_` and uppercase.

Do not add new release tooling around pre-0.3 single-image variables.

## Milestone acceptance before release work

A milestone release branch is not the place to finish architecture work.

Before preparing 0.3.0 release metadata:

- final platform PR is merged;
- exact-head CI was green;
- architecture/security review passed;
- senior milestone acceptance is recorded;
- required release docs match implementation;
- known Blocker/High findings are closed.

## Release procedure

### 1. Prepare exact release commit

Create a dedicated release branch from accepted `master` and select a new semver.

Update:

```text
plugins/safe-android-reverser/VERSION
plugins/safe-android-reverser/.claude-plugin/plugin.json
.claude-plugin/marketplace.json
README/docs release references when applicable
```

Do not reuse an already-published version.

### 2. Run consistency/contract tests

At minimum:

```bash
python3 scripts/check_release_consistency.py
PYTHONPATH=plugins/safe-android-reverser/lib \
  python3 plugins/safe-android-reverser/tests/test_platform_architecture.py
PYTHONPATH=plugins/safe-android-reverser/lib \
  python3 plugins/safe-android-reverser/tests/test_public_operation_contract.py
PYTHONPATH=plugins/safe-android-reverser/lib \
  python3 plugins/safe-android-reverser/tests/test_cross_worker_contracts.py
PYTHONPATH=plugins/safe-android-reverser/lib \
  python3 plugins/safe-android-reverser/tests/test_runtime_image_pinning.py
bash sandbox/test_wrapper.sh
```

Run static-core and Flutter capability-specific suites as well.

### 3. Push release branch and require exact-head PR CI

The CI run must correspond to the exact commit intended for release/tagging.

A green run from an earlier branch head is not sufficient.

### 4. Verify controlled exact Flutter runtime-cache build

Before a production release that changes runtime-cache resolution, verify at least one controlled exact-runtime cache build end-to-end:

- deterministic cache tag;
- Dart version/snapshot/arch/OS/compressed-pointer identity;
- full Blutter commit;
- Capability API;
- Worker ABI;
- runtime-cache schema;
- expected OCI provenance labels;
- immutable image execution readiness.

This does not require building every possible Dart runtime before release; cache misses remain an explicit supported state.

From Flutter cache schema 3 onward, the controlled build request contains the provider-independent runtime identity and every exact identity field. The stable request identity identifies the cache; a separate private attempt identity identifies only the current bounded build attempt. Workflow run names carry both identities so reconciliation cannot attach a retry to a historical run, while concurrency by stable request identity remains defense-in-depth rather than an idempotency claim. Provider workflow/run identifiers, attempt identity and authoritative creation metadata remain private. A successful workflow run is insufficient until Runtime Driver verifies the published labels, source revision, and immutable image ID.

Schema-2 cache images are not retagged or overwritten. Rebuild the same compatible Dart runtime under schema 3 so the OS label and new deterministic identity are present.

### 5. Tag the exact tested release commit

```bash
VERSION="$(tr -d '[:space:]' < plugins/safe-android-reverser/VERSION)"
git tag -a "safe-v$VERSION" -m "Safe Android Reverser $VERSION"
git push origin "safe-v$VERSION"
```

The tag must resolve to the exact tree that passed release CI.

### 6. Tag workflows publish required semver capability images

The release workflows should rerun required validation and publish semver images only for a matching `safe-vX.Y.Z` tag.

For required baseline capabilities, 0.3 should publish at least:

```text
ghcr.io/salingnh/safe-android-reverser:X.Y.Z
ghcr.io/salingnh/safe-android-reverser:sha-<release-commit>

ghcr.io/salingnh/safe-android-reverser-flutter:X.Y.Z
ghcr.io/salingnh/safe-android-reverser-flutter:sha-<release-commit>
```

Release workflows must refuse to overwrite an existing semver image.

### 7. Verify published images

For each required baseline image verify:

```text
org.opencontainers.image.version = X.Y.Z
io.safe-reverser.capability.id    = expected capability
io.safe-reverser.capability.api   = 1
io.safe-reverser.worker.abi       = 1
org.opencontainers.image.revision = expected release commit (where configured)
```

Also verify the runtime returns a canonical immutable image ID.

### 8. Make marketplace-visible release reachable from master

After required semver images are available, merge the already-tested release change according to repository merge policy.

Avoid a window where marketplace/plugin metadata advertises a version whose required images do not exist.

If policy requires release tags to be reachable from `master`, use a merge strategy that preserves/reaches the exact tagged release tree. Do not create a materially different tree under the same semver.

## Why images are published before marketplace visibility

If plugin metadata is visible first, users can install a version whose required workers are not yet available.

Correct ordering:

```text
exact release commit tested
        ↓
safe-vX.Y.Z tag
        ↓
required semver images published/verified
        ↓
marketplace-visible release merged
```

## Release consistency gate

`scripts/check_release_consistency.py` is an architecture/release gate, not merely a version-string check.

It should verify invariants including:

- valid canonical VERSION;
- plugin/marketplace version equality;
- exactly one public `safe-android-reverser` MCP;
- legacy dual-MCP/server files do not return;
- canonical static worker path exists;
- launcher delegates image lifecycle to Runtime Driver;
- launcher does not create data root before Path SDK validation;
- required baseline capability manifests exist and validate;
- additional compatible capability manifests are not rejected solely for being additional;
- operation ownership does not collide;
- Capability API/Worker ABI constants agree across host/workers/cache identity;
- worker images carry required labels;
- immutable image-ID execution markers remain present;
- workflows publish `sha-*` development references and derive semver only from `safe-v*` tags;
- tag version equals `VERSION`.

## Baseline capability rule

A release may define **required baseline capabilities**, for example 0.3:

```text
static-core
framework-flutter
```

Release gates should require that baseline as a subset, not require that it is the complete forever list of capability manifests.

This allows later compatible optional/native/framework/security capability modules without rewriting central architecture gates merely because the set grew.

## Runtime-cache release rule

Exact runtime caches are not normal plugin semver images.

They use deterministic identities bound to the runtime/analyzer ABI inputs. Never retag an incompatible runtime under an existing cache identity.

If any identity input changes in a compatibility-significant way, increment the relevant cache/ABI contract so a new immutable identity is produced.

## Rollback

Never mutate a published semver image.

Example:

```text
0.3.0 contains a release defect
      ↓
fix source
      ↓
release 0.3.1
```

A plugin rollback can select an older marketplace/plugin release whose immutable images remain available.

## Post-release checks

After release:

1. install/update through the documented plugin path;
2. run `/mcp`;
3. call `health` and `list_capabilities`;
4. verify required capability states and immutable image IDs;
5. fingerprint a known native Android fixture;
6. fingerprint/analyze a known Flutter fixture;
7. verify a runtime cache miss is explicit rather than triggering an in-sandbox build;
8. update roadmap release status and start the next milestone only after acceptance is complete.
