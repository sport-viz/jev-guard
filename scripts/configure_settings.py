"""Add (or remove) the Jev Guard PreToolUse hook in a Claude Code settings file.

    python scripts/configure_settings.py              # add to ~/.claude/settings.json
    python scripts/configure_settings.py --dry-run    # print the result, change nothing
    python scripts/configure_settings.py --remove     # take the hook out again

Idempotent: an existing Jev Guard entry is replaced, other settings and hooks are kept.
A timestamped backup is written to ~/.claude/backups/ before any change.
"""

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

HOME = Path.home()
GUARD = Path(os.environ.get("JEV_GUARD_HOME", HOME / ".claude" / "jev-guard"))
COMMAND = f"{GUARD}/.venv/bin/python {GUARD}/jev_guard/hook.py"
ENTRY = {
    "matcher": "*",
    "hooks": [{"type": "command", "command": COMMAND, "timeout": 20, "onFailure": "block"}],
}


def is_guard_group(group: dict) -> bool:
    return any("jev_guard/hook.py" in h.get("command", "") for h in group.get("hooks", []))


def configure(settings: dict, remove: bool) -> dict:
    hooks = settings.setdefault("hooks", {})
    groups = [g for g in hooks.get("PreToolUse", []) if not is_guard_group(g)]
    if not remove:
        groups.append(ENTRY)
    if groups:
        hooks["PreToolUse"] = groups
    else:
        hooks.pop("PreToolUse", None)
    if not hooks:
        settings.pop("hooks")
    return settings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--settings", type=Path, default=HOME / ".claude" / "settings.json")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.remove and not Path(COMMAND.split()[0]).exists():
        parser.error(f"{COMMAND.split()[0]} not found; run scripts/install.sh first")

    settings = json.loads(args.settings.read_text()) if args.settings.exists() else {}
    updated = configure(json.loads(json.dumps(settings)), args.remove)
    text = json.dumps(updated, indent=2, ensure_ascii=False) + "\n"
    if args.dry_run:
        print(json.dumps(updated.get("hooks", {}), indent=2))
        return 0

    if args.settings.exists():
        backups = HOME / ".claude" / "backups"
        backups.mkdir(parents=True, exist_ok=True)
        backup = backups / f"settings.json.{time.strftime('%Y%m%d-%H%M%S')}.jev-guard"
        shutil.copy2(args.settings, backup)
        print(f"Backup: {backup}")
    tmp = args.settings.with_suffix(".json.tmp")
    tmp.write_text(text)
    os.replace(tmp, args.settings)
    print(("Removed" if args.remove else "Added") + f" Jev Guard hook in {args.settings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
