#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WRAPPER="$ROOT/plugins/safe-android-reverser/bin/safe-reverser-mcp"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/project" "$TMP/data"
PYLOG="$TMP/python.log"

cat > "$TMP/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'unexpected podman call:' >&2
printf ' <%s>' "$@" >&2
printf '\n' >&2
exit 99
EOF
chmod +x "$TMP/bin/podman"

cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'ARGV'
  for arg in "$@"; do printf ' <%s>' "$arg"; done
  printf '\nRUNTIME <%s>\n' "${SAFE_REVERSER_RUNTIME:-}"
  printf 'PROJECT <%s>\n' "${SAFE_REVERSER_PROJECT_DIR:-}"
  printf 'DATA <%s>\n' "${SAFE_REVERSER_DATA_DIR:-}"
  printf 'VERSION <%s>\n' "${SAFE_REVERSER_PLUGIN_VERSION:-}"
} > "$PYTHON_LOG"
EOF
chmod +x "$TMP/bin/python3"

PYTHON_LOG="$PYLOG" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=podman \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data" \
"$WRAPPER" </dev/null

grep -F 'ARGV' "$PYLOG" | grep -F '/bin/mcp-control-plane.py>' >/dev/null
grep -F 'RUNTIME <podman>' "$PYLOG" >/dev/null
grep -F "PROJECT <$TMP/project>" "$PYLOG" >/dev/null
grep -F "DATA <$TMP/data>" "$PYLOG" >/dev/null
VERSION="$(tr -d '[:space:]' < "$ROOT/plugins/safe-android-reverser/VERSION")"
grep -F "VERSION <$VERSION>" "$PYLOG" >/dev/null

# The launcher must not own image/container lifecycle anymore.
# If it accidentally invokes the fake runtime the test exits with status 99.

# A symlinked plugin data root must be rejected before the control plane starts.
rm -f "$PYLOG"
mkdir -p "$TMP/outside"
ln -s "$TMP/outside" "$TMP/data-link"
set +e
PYTHON_LOG="$PYLOG" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=podman \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data-link" \
"$WRAPPER" </dev/null >"$TMP/stdout" 2>"$TMP/stderr"
STATUS=$?
set -e
[[ "$STATUS" -ne 0 ]]
grep -F 'plugin data directory must not be a symlink' "$TMP/stderr" >/dev/null
test ! -f "$PYLOG"

# Runtime selection remains constrained to Podman or Docker.
set +e
PYTHON_LOG="$PYLOG" \
PATH="$TMP/bin:$PATH" \
SAFE_REVERSER_RUNTIME=not-a-runtime \
SAFE_REVERSER_PROJECT_DIR="$TMP/project" \
SAFE_REVERSER_DATA_DIR="$TMP/data" \
"$WRAPPER" </dev/null >"$TMP/stdout" 2>"$TMP/stderr"
STATUS=$?
set -e
[[ "$STATUS" -ne 0 ]]
grep -F 'runtime must be podman, docker, or auto' "$TMP/stderr" >/dev/null

echo 'safe-reverser host control-plane launcher tests passed'
