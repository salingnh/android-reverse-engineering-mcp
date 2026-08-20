#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WRAPPER="$ROOT/plugins/safe-android-reverser/bin/safe-reverser-mcp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/project" "$TMP/data"
LOG="$TMP/podman.log"

cat > "$TMP/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'CALL' >> "$PODMAN_LOG"
for arg in "$@"; do printf ' <%s>' "$arg" >> "$PODMAN_LOG"; done
printf '\n' >> "$PODMAN_LOG"

if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
  exit 1
fi
if [[ "${1:-}" == "pull" ]]; then
  exit 0
fi
if [[ "${1:-}" == "run" ]]; then
  exit 0
fi
exit 0
EOF
chmod +x "$TMP/bin/podman"

PODMAN_LOG="$LOG" \
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

: > "$LOG"
set +e
PODMAN_LOG="$LOG" \
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
