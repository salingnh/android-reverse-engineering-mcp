# Manual release action

`Manual release Safe Android Reverser` is the supported one-click release orchestrator for production semver releases.

The workflow file lives at:

```text
.github/workflows/release-safe-reverser.yml
```

It must exist on the repository default branch so GitHub exposes the **Run workflow** button.

## Inputs

Provide exactly three values:

```text
version       semantic version, for example 0.3.0
release_ref   accepted release branch/ref, for example release/safe-v0.3.0
expected_sha  exact 40-character commit SHA that already passed release CI
```

The workflow refuses to continue when the checked-out release ref, `VERSION`, and `expected_sha` do not describe the same release.

## Required exact-head CI

Before creating a tag, the workflow queries GitHub Actions and requires successful runs on the exact release SHA for:

```text
Build static-core capability
Build framework-flutter capability
Test Safe Reverser control plane
Test Flutter runtime-cache build
```

It also reruns `scripts/check_release_consistency.py` after checking out the requested release ref.

## What the workflow publishes

For `VERSION=X.Y.Z`, it creates or verifies:

```text
safe-vX.Y.Z

ghcr.io/salingnh/safe-android-reverser:X.Y.Z
ghcr.io/salingnh/safe-android-reverser:sha-<release-commit>

ghcr.io/salingnh/safe-android-reverser-flutter:X.Y.Z
ghcr.io/salingnh/safe-android-reverser-flutter:sha-<release-commit>
```

It verifies the published semver images carry the expected:

```text
org.opencontainers.image.version
org.opencontainers.image.revision
io.safe-reverser.capability.id
io.safe-reverser.capability.api = 1
io.safe-reverser.worker.abi = 1
```

The workflow then creates a GitHub Release with:

```text
safe-android-reverser-X.Y.Z.zip
SHA256SUMS
```

The ZIP contains the complete `plugins/safe-android-reverser` plugin directory.

## Why it explicitly dispatches package workflows

GitHub intentionally prevents events created with the workflow `GITHUB_TOKEN` from recursively triggering most other workflows. Therefore creating `safe-vX.Y.Z` inside the manual workflow cannot rely on the tag `push` event to publish images.

The release orchestrator explicitly dispatches:

```text
build-safe-sandbox.yml
build-flutter-profile.yml
```

against the newly created tag and waits for both runs to finish successfully.

This keeps the existing capability-specific build/test/publish workflows as the package source of truth instead of duplicating their image build logic in the release orchestrator.

## Safe reruns

The action is designed to resume after a partial infrastructure failure.

If the Git tag already exists, it is accepted only when it resolves to `expected_sha`.

If a semver GHCR image already exists, it is accepted only when its version, revision SHA, capability ID, Capability API, and Worker ABI match the requested release. A mismatched existing immutable package causes the release to fail instead of overwriting it.

If the GitHub Release already exists, release assets are uploaded again with `--clobber` after package provenance verification.

## Release sequence

```text
accepted release ref + exact SHA
        |
        v
exact-head CI evidence required
        |
        v
release consistency gate
        |
        v
create/verify annotated safe-vX.Y.Z tag
        |
        v
explicitly dispatch package workflows on the tag
        |
        v
verify GHCR semver images + immutable digests
        |
        v
build plugin ZIP + SHA256SUMS
        |
        v
create/update GitHub Release
```

Marketplace visibility remains a separate final gate: merge the release metadata PR into `master` only after this workflow has successfully created the tag, packages, and GitHub Release.

## Running 0.3.0

For the current 0.3.0 release candidate use:

```text
version       = 0.3.0
release_ref   = release/safe-v0.3.0
expected_sha  = e279e0f26488e1ce214d45d7f3a512a807ff07ba
```

After the action is green, verify the release/package links and then merge PR #12 so marketplace metadata `0.3.0` becomes reachable from `master`.
