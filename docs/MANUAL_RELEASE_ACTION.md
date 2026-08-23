# Manual release action

Safe Android Reverser now exposes a **tag-only** production release entry point:

```text
Release Safe Android Reverser
```

Workflow file:

```text
.github/workflows/release-safe-reverser-by-tag.yml
```

It must exist on the repository default branch so GitHub exposes the **Run workflow** button.

## Recommended input

Provide exactly **one value**:

```text
tag = safe-v0.3.0
```

For convenience this is also accepted:

```text
tag = 0.3.0
```

The workflow normalizes `0.3.0` to `safe-v0.3.0` automatically.

You do **not** need to know or enter a commit SHA.

## What is resolved automatically

For a tag `safe-vX.Y.Z`, the entry workflow derives:

```text
version     = X.Y.Z
release_ref = release/safe-vX.Y.Z
release_sha = current HEAD of release/safe-vX.Y.Z
```

The release branch must already exist. Its current HEAD becomes the only candidate release SHA.

The entry workflow then dispatches the guarded internal orchestrator:

```text
.github/workflows/release-safe-reverser.yml
```

with the derived `version`, `release_ref`, and `expected_sha`.

`expected_sha` still exists internally as a safety guard, but users no longer type it manually.

## Why this remains safe

The guarded orchestrator still refuses to release unless all of these agree:

```text
requested tag/version
plugins/safe-android-reverser/VERSION
release branch HEAD
exact release SHA
existing Git tag, if any
published image provenance, if any
```

Before creating/publishing a release it also requires successful exact-head GitHub Actions on the automatically resolved release SHA for:

```text
Build static-core capability
Build framework-flutter capability
Test Safe Reverser control plane
Test Flutter runtime-cache build
```

It reruns:

```text
python3 scripts/check_release_consistency.py
```

on that release tree.

Therefore removing the manual SHA field does not remove the exact-head release gate. The SHA is derived from GitHub rather than copied by a human.

## What gets published

For `safe-vX.Y.Z`, the guarded release flow creates or verifies:

```text
Git tag
safe-vX.Y.Z

GHCR
ghcr.io/salingnh/safe-android-reverser:X.Y.Z
ghcr.io/salingnh/safe-android-reverser:sha-<release-commit>

ghcr.io/salingnh/safe-android-reverser-flutter:X.Y.Z
ghcr.io/salingnh/safe-android-reverser-flutter:sha-<release-commit>
```

Published images must carry the expected:

```text
org.opencontainers.image.version
org.opencontainers.image.revision
io.safe-reverser.capability.id
io.safe-reverser.capability.api = 1
io.safe-reverser.worker.abi = 1
```

and must expose an immutable repository digest.

The workflow then creates/updates the GitHub Release with:

```text
safe-android-reverser-X.Y.Z.zip
SHA256SUMS
```

## Why package workflows are explicitly dispatched

GitHub intentionally prevents most recursive workflow triggering for events created with a workflow `GITHUB_TOKEN`.

Therefore creating the Git tag inside the release orchestrator does not rely on a tag `push` event. The orchestrator explicitly dispatches:

```text
build-safe-sandbox.yml
build-flutter-profile.yml
```

against the release tag and waits for both to finish.

## Safe reruns

The release flow is resumable after an infrastructure interruption:

- an existing tag is accepted only when it resolves to the same automatically resolved release SHA;
- an existing semver image is accepted only when version, revision SHA, capability ID, Capability API and Worker ABI match;
- a mismatched immutable image causes the release to fail rather than overwrite it;
- an existing GitHub Release can receive the verified ZIP/checksum assets again.

## Release sequence

```text
user enters safe-vX.Y.Z
        |
        v
derive release/safe-vX.Y.Z
        |
        v
resolve exact branch HEAD SHA automatically
        |
        v
require exact-head release CI
        |
        v
release consistency gate
        |
        v
create/verify annotated safe-vX.Y.Z tag
        |
        v
publish/verify capability images
        |
        v
build plugin ZIP + SHA256SUMS
        |
        v
create/update GitHub Release
```

Marketplace visibility remains a separate final gate: merge the release metadata PR into `master` only after this workflow is green.

## Running 0.3.0

Go to:

```text
Actions
  -> Release Safe Android Reverser
  -> Run workflow
```

Choose `master` and enter either:

```text
safe-v0.3.0
```

or simply:

```text
0.3.0
```

The workflow automatically resolves:

```text
release/safe-v0.3.0
```

and its exact HEAD SHA. After the action is green, verify the release/package links and merge PR #12 so marketplace metadata `0.3.0` becomes reachable from `master`.
