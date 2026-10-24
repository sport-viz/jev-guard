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

# Smoke test the installed copy across Claude Code, Antigravity (agy), and Pi:
SMOKE_HOME="$(mktemp -d)"
trap 'rm -rf "$SMOKE_HOME"' EXIT

out=$(echo '{"cwd":"/","tool_name":"Bash","tool_input":{"command":"rm -rf ~"}}' \
      | JEV_GUARD_HOME="$SMOKE_HOME" "$DEST/.venv/bin/python" "$DEST/jev_guard/hook.py")
if ! grep -q '"permissionDecision": "deny"' <<<"$out"; then
    echo "Claude smoke test failed: $out" >&2
    exit 1
fi

out_agy=$(echo '{"workspacePaths":["/"],"toolCall":{"name":"run_command","args":{"CommandLine":"rm -rf ~"}}}' \
      | JEV_GUARD_HOME="$SMOKE_HOME" "$DEST/.venv/bin/python" "$DEST/jev_guard/hook.py" --host agy)
if ! grep -q '"decision": "deny"' <<<"$out_agy"; then
    echo "Antigravity smoke test failed: $out_agy" >&2
    exit 1
fi

out_agy_pass=$(echo '{"workspacePaths":["/z"],"toolCall":{"name":"read_file","args":{"Path":"/z/a.py"}}}' \
      | JEV_GUARD_HOME="$SMOKE_HOME" "$DEST/.venv/bin/python" "$DEST/jev_guard/hook.py" --host agy)
if ! grep -q '"decision": "allow"' <<<"$out_agy_pass"; then
    echo "Antigravity fast-path smoke test failed: $out_agy_pass" >&2
    exit 1
fi

out_pi=$(echo '{"host":"pi","cwd":"/","tool_name":"bash","tool_input":{"command":"rm -rf ~"}}' \
      | JEV_GUARD_HOME="$SMOKE_HOME" "$DEST/.venv/bin/python" "$DEST/jev_guard/hook.py" --host pi)
if ! grep -q '"decision": "deny"' <<<"$out_pi"; then
    echo "Pi smoke test failed: $out_pi" >&2
    exit 1
fi

echo "Installed Jev Guard to $DEST"
echo "Hook command: $DEST/.venv/bin/python $DEST/jev_guard/hook.py"
