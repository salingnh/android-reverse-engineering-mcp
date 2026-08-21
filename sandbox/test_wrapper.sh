#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WRAPPER="$ROOT/plugins/safe-android-reverser/bin/safe-reverser-mcp"
PLUGIN_VERSION="$(tr -d '[:space:]' < "$ROOT/plugins/safe-android-reverser/VERSION")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/project" "$TMP/data"
LOG="$TMP/podman.log"
STATE="$TMP/image-present"

cat > "$TMP/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'CALL' >> "$PODMAN_LOG"
for arg in "$@"; do printf ' <%s>' "$arg" >> "$PODMAN_LOG"; done
printf '\n' >> "$PODMAN_LOG"

if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
  [[ -f "$PODMAN_STATE" ]] || exit 1
  if [[ "$*" == *'org.opencontainers.image.version'* ]]; then
    printf '%s\n' "$PODMAN_IMAGE_VERSION"
  elif [[ "$*" == *'--format'* ]]; then
    printf 'sha256:test-image\n'
  fi
  exit 0
fi
if [[ "${1:-}" == "pull" ]]; then
  touch "$PODMAN_STATE"
  exit 0
fi
if [[ "${1:-}" == "run" ]]; then
  exit 0
fi
exit 0
EOF
chmod +x "$TMP/bin/podman"

# Custom image override: automatic pull, UID/GID mapping, writable data mount and release metadata.
PODMAN_LOG="$LOG" \
PODMAN_STATE="$STATE" \
PODMAN_IMAGE_VERSION="$PLUGIN_VERSION" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=podman \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data" \
SAFE_REVERSER_IMAGE=test.local/safe-reverser:1 \
"$WRAPPER"

grep -F 'CALL <image> <inspect> <test.local/safe-reverser:1>' "$LOG" >/dev/null
grep -F 'CALL <pull> <test.local/safe-reverser:1>' "$LOG" >/dev/null
grep -F '<--userns=keep-id>' "$LOG" >/dev/null
grep -F "<--user=$(id -u):$(id -g)>" "$LOG" >/dev/null
grep -F "<--volume=$TMP/project:/workspace:ro,z>" "$LOG" >/dev/null
grep -F "<--volume=$TMP/data:/data:rw,z>" "$LOG" >/dev/null
grep -F "<--env=SAFE_REVERSER_PLUGIN_VERSION=$PLUGIN_VERSION>" "$LOG" >/dev/null
test -d "$TMP/data/jobs"

# Default image must derive its immutable semver tag from the bundled VERSION file.
: > "$LOG"
touch "$STATE"
PODMAN_LOG="$LOG" \
PODMAN_STATE="$STATE" \
PODMAN_IMAGE_VERSION="$PLUGIN_VERSION" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=podman \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data" \
"$WRAPPER"

grep -F "<ghcr.io/salingnh/safe-android-reverser:$PLUGIN_VERSION>" "$LOG" >/dev/null
grep -F "<--env=SAFE_REVERSER_IMAGE_REF=ghcr.io/salingnh/safe-android-reverser:$PLUGIN_VERSION>" "$LOG" >/dev/null

# Disabling automatic pull must fail before running a missing image.
rm -f "$STATE"
: > "$LOG"
set +e
PODMAN_LOG="$LOG" \
PODMAN_STATE="$STATE" \
PODMAN_IMAGE_VERSION="$PLUGIN_VERSION" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=podman \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data" \
SAFE_REVERSER_IMAGE=test.local/safe-reverser:1 \
SAFE_REVERSER_AUTO_PULL=0 \
"$WRAPPER" >"$TMP/stdout" 2>"$TMP/stderr"
STATUS=$?
set -e

[[ "$STATUS" -ne 0 ]]
grep -F 'sandbox image is not installed' "$TMP/stderr" >/dev/null
if grep -F 'CALL <pull>' "$LOG" >/dev/null; then
  echo 'wrapper unexpectedly pulled image with SAFE_REVERSER_AUTO_PULL=0' >&2
  exit 1
fi

echo 'safe-reverser-mcp wrapper tests passed'
