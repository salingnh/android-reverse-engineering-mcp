# Release automation

The standard production release path is now the one-click workflow:

```text
Ship Safe Android Reverser
```

Workflow file:

```text
.github/workflows/ship-safe-reverser.yml
```

## Normal operation

Go to:

```text
Actions
  -> Ship Safe Android Reverser
  -> Run workflow
```

Choose `master` and enter exactly one value:

```text
0.4.0
```

The `safe-v` form is also accepted:

```text
safe-v0.4.0
```

No branch name, commit SHA, PR number, image tag, or package name is entered manually.

## What the workflow automates

For `X.Y.Z`, it automatically:

```text
validate X.Y.Z
  -> resolve/create release/safe-vX.Y.Z
  -> synchronize VERSION/plugin/marketplace/release docs
  -> create/reuse release PR
  -> resolve exact release HEAD SHA
  -> run/reuse exact-head release CI
  -> call guarded publication orchestrator
  -> create/verify safe-vX.Y.Z
  -> publish/verify static-core and framework-flutter images
  -> verify OCI version/revision/API/ABI + immutable digests
  -> build plugin ZIP + SHA256SUMS
  -> create/update GitHub Release
  -> merge release PR with --match-head-commit
  -> verify release commit is reachable from master
  -> smoke-test published images offline
  -> normalize published release status on master
```

The release source remains the exact tested release-branch HEAD. A release PR is not merged until immutable packages and the GitHub Release exist.

## Safety properties

Automation does not weaken release gates:

- one global production-release concurrency lock prevents overlapping releases;
- semantic version must be valid and cannot move backwards when creating a release branch;
- an existing release branch is reused rather than silently rewritten;
- release PR head must equal the resolved exact release SHA;
- exact-head CI is required for static-core, framework-flutter, control-plane integration, and Flutter runtime-cache smoke;
- the internal publisher rejects tag/SHA mismatches and immutable semver-image provenance mismatches;
- release PR merge uses `--match-head-commit` so a moved head cannot be merged accidentally;
- post-release verification requires the tagged release commit to be reachable from `master`;
- published static and Flutter images are pulled again and smoke-tested with offline/read-only/cap-drop restrictions.

## Internal / recovery workflows

These remain intentionally available as lower-level recovery building blocks:

```text
Release Safe Android Reverser
Manual release Safe Android Reverser
```

Normal releases should not start there. They are useful only when resuming or diagnosing a partially completed release.

The guarded internal orchestrator continues to accept explicit `version`, `release_ref`, and `expected_sha` because those are machine-to-machine safety inputs. The one-click workflow derives them automatically.

## GitHub token behavior

GitHub does not recursively trigger most workflows from events created with the repository `GITHUB_TOKEN`. Therefore the release pipeline explicitly dispatches required validation and package workflows instead of assuming that a bot-created branch, PR, or tag will trigger the next stage automatically.

## Operator responsibility

The remaining human decision is intentionally narrow:

```text
Is master accepted/frozen for this release?
```

If yes, run `Ship Safe Android Reverser` with the new version. Everything after that is automated and fail-closed.
