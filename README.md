# Safe Android Reverse Engineering — Claude Code plugin + MCP sandbox

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

This fork keeps the original `android-reverse-engineering` Claude Code plugin and adds a new
**`safe-android-reverser`** plugin whose reverse-engineering execution happens through an MCP
server inside a locked-down container.

The goal is simple: an LLM can fingerprint, decompile, search, and extract API evidence from an
untrusted APK without installing JADX/Java on the host and without giving the analyzed artifact
normal host/network access.

> The original project is by [SimoneAvogadro](https://github.com/SimoneAvogadro/android-reverse-engineering-skill)
> and remains available in this fork. The sandbox/MCP architecture is an additional plugin.

## Plugins in this marketplace

| Plugin | Execution model | Recommended use |
|---|---|---|
| `safe-android-reverser` | MCP → rootless Podman/Docker sandbox | **Recommended** for APK/JAR/AAR analysis |
| `android-reverse-engineering` | Host scripts and locally installed tools | Legacy/upstream-compatible workflow |

The marketplace name in this fork is **`salingnh-reverse-tools`**.

## Safe architecture

```text
Claude Code
    │
    │ plugin MCP (stdio)
    ▼
safe-reverser-mcp wrapper
    │
    ▼
rootless Podman / Docker
    │
    ├── network = none
    ├── root filesystem = read-only
    ├── capabilities = none
    ├── no-new-privileges
    ├── CPU / RAM / PID limits
    ├── project -> /workspace (read-only)
    └── plugin data -> /data (read-write)
           │
           ▼
    MCP server allowlist
      ├── health
      ├── fingerprint
      ├── decompile
      ├── extract_api
      ├── search_source
      ├── read_source_file
      ├── recover_kotlin_names
      └── list_jobs
           │
           ▼
       JADX / Vineflower
```

The MCP server never exposes an arbitrary shell tool and all subprocesses are invoked with fixed
argument arrays (`shell=False`). The runtime image does not contain `curl`, `wget`, ADB, Frida,
or a package manager.

## Install `safe-android-reverser`

After the safe plugin is merged to `master`:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Install the sandbox image separately. Rootless Podman is preferred on Linux/Fedora:

```bash
podman pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

Docker is also supported:

```bash
docker pull ghcr.io/salingnh/safe-android-reverser:0.1.0
```

The plugin does **not** auto-pull images by default. This prevents merely enabling a plugin from
silently downloading executable artifacts. Set `SAFE_REVERSER_AUTO_PULL=1` only if that behavior
is explicitly desired.

## Test the feature branch

Before merge, add the marketplace pinned to the branch:

```text
/plugin marketplace add salingnh/android-reverse-engineering-skill@feat/safe-sandbox-plugin
/plugin install safe-android-reverser@salingnh-reverse-tools
/reload-plugins
```

Build the image locally from the same branch:

```bash
git clone --branch feat/safe-sandbox-plugin https://github.com/salingnh/android-reverse-engineering-skill.git
cd android-reverse-engineering-skill

set -a
source sandbox/tools.lock.env
set +a

docker build -f sandbox/Dockerfile \
  --build-arg JADX_VERSION="$JADX_VERSION" \
  --build-arg JADX_SHA256="$JADX_SHA256" \
  --build-arg VINEFLOWER_VERSION="$VINEFLOWER_VERSION" \
  -t safe-android-reverser:dev .

export SAFE_REVERSER_IMAGE=safe-android-reverser:dev
```

Use `podman build` instead of `docker build` if desired.

## Safe workflow

The new skill instructs the agent to use MCP only:

1. `health` — verify the sandbox toolchain.
2. `fingerprint` — inspect APK/XAPK/APKS/APKM before expensive decompilation.
3. `decompile` — JADX for Android packages; Vineflower for JAR/AAR.
4. `extract_api` — collect URLs, Retrofit endpoints, endpoint-shaped strings, and network/auth signals.
5. `search_source` / `read_source_file` — retrieve only relevant evidence from decompiled output.
6. `recover_kotlin_names` — produce confidence-scored name candidates when Kotlin metadata survives.
7. Claude builds a Tier-1 endpoint inventory and selected Tier-2 call-flow deep dives.

### Why fingerprint first?

Java decompilation is often the wrong first move for Flutter, React Native, Cordova/Capacitor,
or Xamarin/.NET MAUI applications. Fingerprinting lets the agent stop early and recommend the
framework-appropriate analyzer rather than wasting time on host-shell Java classes.

## Fixes included in the safe implementation

The MCP implementation also avoids several correctness problems found while reviewing the
upstream shell workflow:

- obfuscation level is calculated from **DEX type descriptors**, not APK ZIP entry paths;
- `BuildConfig` is detected from DEX descriptors rather than looking for a nonexistent
  `BuildConfig.class` ZIP entry;
- AAR + Vineflower extracts `classes.jar` and `libs/*.jar` instead of treating the AAR as DEX;
- third-party URL matching covers both apex hosts (`stripe.com`) and subdomains
  (`api.stripe.com`);
- auth extraction uses structured Python scanning rather than the broken shell helper option
  path;
- Kotlin metadata recovery is treated as **opportunistic evidence with confidence**, not a
  guarantee. Shrinkers such as R8 can remove metadata/annotations depending on keep rules.

## Toolchain and supply-chain policy

The static image currently uses:

- Java 21 runtime
- **JADX 1.5.6**, version-pinned and SHA-256 verified
- Vineflower 1.12.0, version-pinned
- Python standard library MCP server implementation

No tool resolves a `latest` release at runtime. The current remaining supply-chain hardening item
is to independently record and enforce the Vineflower release JAR SHA-256 as well.

The feature-branch workflow runs tests and builds the image but does not publish the production
GHCR tag. On `master` / `safe-v*` tags it is configured to publish the image with BuildKit SBOM
and provenance metadata.

## Repository layout

```text
android-reverse-engineering-skill/
├── .claude-plugin/
│   └── marketplace.json
├── .github/workflows/
│   └── build-safe-sandbox.yml
├── plugins/
│   ├── android-reverse-engineering/        # original/upstream plugin
│   └── safe-android-reverser/              # new sandboxed plugin
│       ├── .claude-plugin/plugin.json
│       ├── .mcp.json
│       ├── bin/safe-reverser-mcp
│       ├── commands/safe-decompile.md
│       └── skills/safe-android-reverser/SKILL.md
├── sandbox/
│   ├── Dockerfile
│   ├── mcp_server.py
│   ├── tests.py
│   ├── tools.lock.env
│   └── README.md
├── LICENSE
└── README.md
```

## Legacy plugin

The upstream-compatible plugin is still located at `plugins/android-reverse-engineering` and
retains its original shell/PowerShell scripts, including dependency installation. It is preserved
for compatibility, but the new `safe-android-reverser` skill explicitly forbids falling back to
those host execution paths.

If you intentionally want the legacy plugin, install:

```text
/plugin install android-reverse-engineering@salingnh-reverse-tools
```

## Dynamic analysis

Dynamic analysis is deliberately **not** included in the static sandbox. A future dynamic profile
should be a separate MCP server/image with a different threat model and controlled access to:

- Android emulator/device via ADB
- Frida/Objection
- interception proxy
- explicitly scoped network

Keeping static and dynamic execution separate prevents the normal static-analysis path from
acquiring device or network privileges.

## Legal use

Use this project only for lawful reverse engineering, interoperability, security research,
malware analysis, incident response, education, or systems you are authorized to inspect.
You are responsible for compliance with applicable law and software terms.

## License and attribution

Apache-2.0 — see [LICENSE](LICENSE).

Original project and substantial upstream workflow/code:
[SimoneAvogadro/android-reverse-engineering-skill](https://github.com/SimoneAvogadro/android-reverse-engineering-skill).
