# Releasing Safe Android Reverser

Safe Android Reverser uses immutable semantic-version releases. A release must keep the Claude plugin, wrapper, sandbox image and MCP server on the same version.

## Source of truth

The canonical release version is:

```text
plugins/safe-android-reverser/VERSION
```

For example:

```text
0.2.1
```

The marketplace and plugin manifests must contain the same version. CI checks this automatically.

The wrapper does not hard-code a semver image tag. It reads `VERSION` and derives:

```text
ghcr.io/salingnh/safe-android-reverser:<VERSION>
```

The Docker build receives the same version as `SAFE_REVERSER_VERSION`, embeds it as an OCI label and runtime environment variable, and verifies that it matches the copied `VERSION` file.

## Development builds

Pull requests build and test the image but do not publish it.

A push to `master` may publish only moving development references:

```text
ghcr.io/salingnh/safe-android-reverser:master
ghcr.io/salingnh/safe-android-reverser:sha-<commit>
```

`master` must never publish or overwrite a semver tag.

For a local image build:

```bash
VERSION="$(tr -d '[:space:]' < plugins/safe-android-reverser/VERSION)"

docker build \
  --build-arg "SAFE_REVERSER_VERSION=$VERSION" \
  --build-arg "SAFE_REVERSER_BUILD_COMMIT=$(git rev-parse HEAD)" \
  -f sandbox/Dockerfile \
  -t safe-android-reverser:dev \
  .
```

If you explicitly test a custom image with the plugin wrapper:

```bash
export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
```

Explicit custom images are treated as development overrides; default release-image version-label enforcement is skipped for that override.

## Release procedure

1. Choose the next semver. Never reuse a version that has already been released.
2. Update `plugins/safe-android-reverser/VERSION`.
3. Update the safe plugin version in:
   - `plugins/safe-android-reverser/.claude-plugin/plugin.json`
   - `.claude-plugin/marketplace.json`
4. Update user-facing release references if required.
5. Run:

```bash
python3 scripts/check_release_consistency.py
bash sandbox/test_wrapper.sh
python3 sandbox/tests.py
python3 sandbox/tests_program_understanding.py
PYTHONPATH=sandbox python3 sandbox/tests_program_understanding_scopes.py
```

6. Merge the release changes to `master` and wait for CI to pass.
7. Create an annotated release tag matching `VERSION` exactly:

```bash
VERSION="$(tr -d '[:space:]' < plugins/safe-android-reverser/VERSION)"
git tag -a "safe-v$VERSION" -m "Safe Android Reverser $VERSION"
git push origin "safe-v$VERSION"
```

8. The tag workflow reruns the full test/image integration gate, verifies `safe-vX.Y.Z == VERSION`, refuses to overwrite an existing semver image, then publishes:

```text
ghcr.io/salingnh/safe-android-reverser:X.Y.Z
ghcr.io/salingnh/safe-android-reverser:sha-<commit>
```

The semver image is immutable after publication.

## CI release consistency gate

`scripts/check_release_consistency.py` verifies:

```text
VERSION
  == plugin.json version
  == marketplace safe-android-reverser version
```

It also verifies that:

- the wrapper derives its default image from `VERSION`;
- the wrapper propagates plugin release metadata;
- the Dockerfile embeds OCI/runtime release metadata;
- the image entrypoint is release-aware;
- the workflow does not contain a mutable hard-coded semver image tag;
- the workflow emits commit-addressable `sha-*` tags;
- a `safe-vX.Y.Z` Git tag matches `VERSION` exactly.

## Runtime consistency

For a normal plugin release the wrapper checks the OCI image label before starting the container:

```text
plugin VERSION
      ==
org.opencontainers.image.version
```

The MCP `health` response additionally reports:

```json
{
  "release": {
    "server_version": "X.Y.Z",
    "plugin_version": "X.Y.Z",
    "image_version": "X.Y.Z",
    "image_ref": "ghcr.io/salingnh/safe-android-reverser:X.Y.Z",
    "image_id": "...",
    "build_commit": "...",
    "version_consistent": true
  }
}
```

This metadata is the first diagnostic to inspect when an installed plugin behaves differently from the expected release.

## Rollback

Do not overwrite a broken semver image. Publish a new patch version instead.

For example, if `0.2.1` is broken:

```text
Do not replace :0.2.1.
Fix the source.
Release 0.2.2.
```

This preserves reproducibility for existing installations and prevents wrapper/image cache drift.
