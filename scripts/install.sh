#!/usr/bin/env bash
# Install or update Jev Guard from this repo into ~/.claude/jev-guard (the copy the hook runs).
# Settings are a separate step: scripts/configure_settings.py adds or removes the hook entry.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${JEV_GUARD_HOME:-$HOME/.claude/jev-guard}"

echo "Running unit tests before installing..."
(cd "$REPO" && .venv/bin/python -m pytest -q)

mkdir -p "$DEST"
rm -rf "$DEST/jev_guard"                 # replace code; keep decisions.jsonl and .venv
cp -r "$REPO/jev_guard" "$DEST/jev_guard"
find "$DEST/jev_guard" -name __pycache__ -type d -prune -exec rm -rf {} +
cp "$REPO/pyproject.toml" "$REPO/uv.lock" "$DEST/"
(cd "$DEST" && uv sync --frozen --no-dev --quiet)

# Smoke test the installed copy: a hard-rule deny needs no network.
out=$(echo '{"cwd":"/","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' \
      | JEV_GUARD_HOME="$(mktemp -d)" "$DEST/.venv/bin/python" "$DEST/jev_guard/hook.py")
if ! grep -q '"permissionDecision": "deny"' <<<"$out"; then
    echo "Smoke test failed: $out" >&2
    exit 1
fi

echo "Installed Jev Guard to $DEST"
echo "Hook command: $DEST/.venv/bin/python $DEST/jev_guard/hook.py"
