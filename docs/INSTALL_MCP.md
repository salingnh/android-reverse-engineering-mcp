# Install, update and use Safe Android Reverser MCP

This is the supported installation/update path for Safe Android Reverser.

Current published release is **0.2.1**. The 0.3 branch documented here introduces the long-term single-control-plane capability architecture and becomes the normal runtime model when 0.3.0 is released.

## Distribution model from 0.3

The plugin is one user-facing release, but it may require multiple capability images:

```text
Claude plugin VERSION
        |
        +-- host MCP control plane version
        |
        +-- static-core capability image version
        |
        +-- framework-flutter base image version
        |
        +-- exact immutable Flutter runtime-cache images
```

A normal user still installs **one plugin** and sees **one public MCP server**.

The host control plane owns image discovery/pull/verification and starts isolated capability workers as needed.

Normal users should not clone the repository, manually run worker containers, or register framework-specific MCP servers.

## 1. Prerequisites

You need:

- Claude Code with plugin/marketplace support;
- Podman or Docker;
- an APK/XAPK/APKS/APKM/JAR/AAR that you are authorized to analyze.

Rootless Podman is recommended:

```bash
podman --version
podman info
```

Docker is supported:

```bash
docker --version
docker info
```

Do not run Claude Code/plugin with `sudo`.

## 2. Install once

Inside Claude Code:

```text
/plugin marketplace add salingnh/android-reverse-engineering-mcp
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Then inspect:

```text
/mcp
```

The plugin bundles its MCP registration. Do not run a separate `claude mcp add` for Flutter or static workers.

The only public server is:

```text
safe-android-reverser
```

## 3. What starts in 0.3+

The plugin launcher starts a **host-side Python MCP control plane**. It does not parse untrusted APK contents itself.

```text
Claude / AI agent
      ↓ stdio
safe-reverser-mcp launcher
      ↓
host control plane
      ↓
Capability Registry + Runtime Driver
      ↓
isolated worker containers
```

The launcher:

- reads bundled `VERSION`;
- selects rootless Podman first or Docker;
- resolves the project directory;
- passes the data-root path to the shared Path SDK;
- does **not** create/canonicalize the data root before Python path-policy validation;
- starts the host control plane.

The Runtime Driver then owns worker image inspect/pull/verification/execution.

## 4. Capability images

0.3 requires the release baseline capabilities:

```text
static-core
framework-flutter
```

Default repositories are declared by capability manifests:

```text
ghcr.io/salingnh/safe-android-reverser:<VERSION>
ghcr.io/salingnh/safe-android-reverser-flutter:<VERSION>
```

Flutter AOT may additionally require an exact runtime-cache image derived from the analyzed Dart runtime identity.

The host verifies required OCI labels and executes the immutable `sha256:<image-id>` it inspected, not the mutable tag.

A missing normal capability image is pulled automatically when `SAFE_REVERSER_AUTO_PULL=1` (default).

A missing exact Flutter runtime cache is reported as an explicit cache miss. Normal analysis does **not** build/download that runtime inside the sandbox.

## 5. Update the plugin

Inside Claude Code:

```text
/plugin marketplace update salingnh-reverse-tools
/plugin update safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

You normally do not need to manually `podman pull`, delete old images, or edit MCP configuration.

A new plugin release reads its new `VERSION`; capability manifests select matching repositories/tags; Runtime Driver pulls missing release images and verifies their labels.

Old plugin cache directories and old immutable container images may remain on disk. They are not selected by the active release unless explicitly configured.

## 6. Verify with `health`

After install/update:

```text
Use only safe-android-reverser MCP.
Call health and list_capabilities.
Do not analyze an artifact yet.
Report architecture, version, capability states and image identities.
```

Healthy 0.3 architecture should include:

```text
architecture = single-host-control-plane
control_plane.capability_api = 1
control_plane.worker_abi = 1
control_plane.runtime_socket_mounted_into_workers = false
```

Required baseline capability states should be `ready` for an overall `status=ok`.

Readiness is separate from framework detection. A Flutter artifact may route to `framework-flutter` even when an exact Dart runtime cache is unavailable; the capability/job response should report that boundary explicitly.

## 7. Put artifacts under the project root

The project is mounted read-only into workers at `/workspace`.

Keep input artifacts under the active project and pass project-relative paths:

```bash
mkdir -p artifacts
cp /path/to/app.xapk artifacts/app.xapk
```

Do not pass arbitrary absolute host paths.

## 8. First smoke test

```text
Use only safe-android-reverser MCP.

1. Call health.
2. Call list_capabilities.
3. Fingerprint artifacts/app.xapk.
4. Report framework, package members, native libraries, SDK/network clues and analysis_route.
5. Do not decompile until the primary capability/representation is known.
```

## 9. Full framework-aware analysis prompt

```text
Analyze artifacts/app.xapk using only safe-android-reverser MCP.

Required workflow:
1. Call health and inspect required capability readiness.
2. Call fingerprint and follow analysis_route.primary_capability_id.
3. Do not silently substitute Java/Kotlin analysis for a framework whose business logic uses another representation.
4. If primary capability is static-core, use decompile/build_program_index and semantic XREF/CFG/network queries as needed.
5. If primary capability is framework-flutter, call analyze_flutter_aot and retain job_id, then query Dart symbols/strings/XREF/native mappings/network model.
6. Preserve analyzer provenance and evidence_state.
7. Treat CALLS/XREFS as adjacency, not proven data flow.
8. Read only bounded high-signal source/analyzer evidence required to verify conclusions.
9. Report unavailable, cache-miss, degraded or unsupported boundaries explicitly.
10. Never use host shell/JADX/Androguard/Blutter as a fallback around MCP policy.
```

## 10. Runtime configuration

Most users should not set runtime variables manually.

Useful supported variables include:

```text
SAFE_REVERSER_RUNTIME=auto|podman|docker
SAFE_REVERSER_AUTO_PULL=1|0
SAFE_REVERSER_PROJECT_DIR=<project root>
SAFE_REVERSER_DATA_DIR=<plugin data root>
SAFE_REVERSER_ENABLE_CAPABILITIES=<comma-separated opt-in capability ids>
```

The launcher resolves `auto` to Podman first, then Docker.

Advanced development image overrides are generic:

```text
SAFE_REVERSER_CAPABILITY_IMAGE_STATIC_CORE=<repository:tag>
SAFE_REVERSER_CAPABILITY_IMAGE_FRAMEWORK_FLUTTER=<repository:tag>
```

The naming rule is:

```text
SAFE_REVERSER_CAPABILITY_IMAGE_<CAPABILITY_ID>
```

with capability ID uppercased and `-` converted to `_`.

Pre-0.3 static/Flutter aliases may remain temporarily as compatibility aliases, but new tooling/documentation should use the generic override names.

## 11. Opt-in capabilities

0.3 defines activation semantics even though the release baseline contains required static capabilities.

A future opt-in capability remains disabled unless explicitly enabled:

```bash
export SAFE_REVERSER_ENABLE_CAPABILITIES=dynamic-runtime
```

Unknown IDs are rejected.

`dynamic-opt-in` capabilities are required by contract to use explicit opt-in activation. Enabling a future dynamic capability does not grant privileges to static workers.

## 12. Worker security profile

For a static MCP worker, Runtime Driver constructs an effective profile equivalent to:

```bash
podman run --rm -i \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=<manifest limit> \
  --memory=<manifest limit> \
  --cpus=<manifest limit> \
  --tmpfs=/tmp:rw,nosuid,nodev,size=<manifest limit> \
  --tmpfs=/work:rw,nosuid,nodev,size=<manifest limit> \
  --userns=keep-id \
  --user="$(id -u):$(id -g)" \
  --volume="<project>:/workspace:ro,z" \
  --volume="<capability-data>:/data:rw,z" \
  sha256:<verified-image-id>
```

Docker uses equivalent restrictions without Podman's `:z`/`--userns=keep-id` behavior where not applicable.

No worker receives `docker.sock` or `podman.sock`.

## 13. Data-root/path safety

The shared Path SDK validates the configured data root before creating missing directories. Existing symlink components are rejected.

Do not work around path failures with `chmod 777` or by pointing the data root through symlinked directories.

Default data root:

```text
~/.local/share/safe-android-reverser
```

Capability jobs live below capability-specific private directories.

## 14. Troubleshooting MCP connection

Run:

```text
/reload-plugins
/mcp
```

If a plugin update left a stale MCP process in your client, restart Claude Code and inspect the active plugin version.

## 15. Test the exact active wrapper with MCP Inspector

Claude may keep historical plugin versions in its plugin cache. Do not choose an arbitrary wrapper returned by `find ... | head -n1`.

List candidates:

```bash
find ~/.claude/plugins/cache -type f -name safe-reverser-mcp -print
```

Select the wrapper belonging to the active version shown by `/plugin`/`/mcp`:

```bash
MCP_WRAPPER="/exact/path/to/active/plugin/bin/safe-reverser-mcp"

SAFE_REVERSER_PROJECT_DIR="$PWD" \
SAFE_REVERSER_DATA_DIR="$HOME/.local/share/safe-android-reverser-inspector" \
npx @modelcontextprotocol/inspector "$MCP_WRAPPER"
```

Then call:

```text
Tools -> health -> Run Tool
Tools -> list_capabilities -> Run Tool
```

Successful `initialize`, `tools/list`, `health`, and `list_capabilities` prove the public MCP/control-plane path independently of agent behavior.

## 16. Trace launcher startup

For troubleshooting only:

```bash
SAFE_REVERSER_PROJECT_DIR="$PWD" \
SAFE_REVERSER_DATA_DIR="$HOME/.local/share/safe-android-reverser-inspector" \
SAFE_REVERSER_RUNTIME=podman \
timeout 5 bash -x "$MCP_WRAPPER" </dev/null 2>/tmp/safe-reverser-wrapper.trace

cat /tmp/safe-reverser-wrapper.trace
```

In 0.3 the launcher trace should end by executing `mcp-control-plane.py`. It should **not** contain `mkdir -p` for the data root or direct worker `image inspect/pull/run` lifecycle. Those responsibilities belong to shared Python services.

## 17. Diagnose capability readiness

Use `health`/`list_capabilities` before manually inspecting images.

Typical states:

```text
declared     manifest exists but capability is not enabled
ready        image/runtime verified and worker protocol is compatible
degraded     worker exists but diagnostics/protocol are not healthy
unavailable  image/runtime/provisioning is unavailable
unsupported  route/capability cannot support the requested artifact/runtime
```

For exact Flutter runtime analysis, a cache miss is expected for previously unseen Dart runtime identities until the controlled runtime-cache workflow has produced the required immutable image.

## Security boundary

Automatic startup does not expose Podman, Docker, generic shell, or arbitrary analyzer commands as MCP tools.

```text
Agent
  -> allow-listed semantic public MCP
      -> host control plane
          -> verified immutable isolated workers
              -> read-only project input
              -> private bounded analysis data
              -> no network for static capabilities
```

If this path fails, fix the capability/runtime/setup problem. Do not bypass the control plane with host-executed reverse-engineering tools.
