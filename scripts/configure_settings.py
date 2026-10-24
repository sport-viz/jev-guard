"""Add (or remove) the Jev Guard hook for Claude Code, Antigravity (agy), and Pi.

    python scripts/configure_settings.py                    # configure claude, agy, and pi
    python scripts/configure_settings.py --target agy       # configure only ~/.gemini/config/hooks.json
    python scripts/configure_settings.py --target pi        # configure only ~/.pi/agent/extensions/jev-guard.ts
    python scripts/configure_settings.py --target claude    # configure only ~/.claude/settings.json
    python scripts/configure_settings.py --dry-run          # print the result, change nothing
    python scripts/configure_settings.py --remove           # take the hook out again

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
REPO = Path(__file__).resolve().parent.parent
GUARD = Path(os.environ.get("JEV_GUARD_HOME", HOME / ".claude" / "jev-guard"))
COMMAND = f"{GUARD}/.venv/bin/python {GUARD}/jev_guard/hook.py"
AGY_COMMAND = f"{COMMAND} --host agy"
ENTRY = {
    "matcher": "*",
    "hooks": [{"type": "command", "command": COMMAND, "timeout": 20, "onFailure": "block"}],
}
AGY_ENTRY = {
    "matcher": "*",
    "hooks": [{"type": "command", "command": AGY_COMMAND, "timeout": 20}],
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


def configure_agy(hooks_cfg: dict, remove: bool) -> dict:
    """Add or remove the `jev-guard` entry in Antigravity's `~/.gemini/config/hooks.json`."""
    for name in list(hooks_cfg.keys()):
        section = hooks_cfg.get(name)
        if not isinstance(section, dict):
            continue
        if "PreToolUse" in section and isinstance(section["PreToolUse"], list):
            kept = [g for g in section["PreToolUse"] if not is_guard_group(g)]
            if kept:
                section["PreToolUse"] = kept
            else:
                section.pop("PreToolUse", None)
        if not section:
            hooks_cfg.pop(name, None)

    hooks_cfg.pop("jev-guard", None)
    if not remove:
        hooks_cfg["jev-guard"] = {"PreToolUse": [AGY_ENTRY]}
    return hooks_cfg


def _backup_file(path: Path) -> None:
    if not path.exists():
        return
    backups = Path.home() / ".claude" / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    backup = backups / f"{path.name}.{time.strftime('%Y%m%d-%H%M%S')}.jev-guard"
    shutil.copy2(path, backup)
    print(f"Backup: {backup}")


def _write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _backup_file(path)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    os.replace(tmp, path)


def configure_pi(ext_path: Path, remove: bool, dry_run: bool = False,
                 src_path: Path | None = None) -> str:
    """Install or remove the Pi extension at `~/.pi/agent/extensions/jev-guard.ts`."""
    source = src_path or (GUARD / "jev_guard" / "pi_extension.ts")
    if not source.exists():
        source = REPO / "jev_guard" / "pi_extension.ts"
    content = source.read_text()
    if dry_run:
        return f"// {'remove' if remove else 'write'} {ext_path}\n" + ("" if remove else content)
    if remove:
        if ext_path.exists():
            _backup_file(ext_path)
            ext_path.unlink()
        return f"Removed Jev Guard Pi extension at {ext_path}"
    ext_path.parent.mkdir(parents=True, exist_ok=True)
    if ext_path.exists() and ext_path.read_text() != content:
        _backup_file(ext_path)
    tmp = ext_path.with_suffix(".ts.tmp")
    tmp.write_text(content)
    os.replace(tmp, ext_path)
    return f"Added Jev Guard Pi extension in {ext_path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=["claude", "agy", "pi", "all"], default="all",
                        help="which coding agent(s) to configure (default: all)")
    parser.add_argument("--settings", type=Path, default=HOME / ".claude" / "settings.json",
                        help="Claude Code settings.json path")
    parser.add_argument("--agy-hooks", type=Path, default=HOME / ".gemini" / "config" / "hooks.json",
                        help="Antigravity hooks.json path")
    parser.add_argument("--pi-extension", type=Path,
                        default=HOME / ".pi" / "agent" / "extensions" / "jev-guard.ts",
                        help="Pi extension path")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.remove and not Path(COMMAND.split()[0]).exists():
        parser.error(f"{COMMAND.split()[0]} not found; run scripts/install.sh first")

    targets = {"claude", "agy", "pi"} if args.target == "all" else {args.target}

    if "claude" in targets:
        settings = json.loads(args.settings.read_text()) if args.settings.exists() else {}
        updated = configure(json.loads(json.dumps(settings)), args.remove)
        if args.dry_run:
            print(json.dumps(updated.get("hooks", {}), indent=2))
        else:
            _write_json_atomic(args.settings, updated)
            print(("Removed" if args.remove else "Added") + f" Jev Guard hook in {args.settings}")

    if "agy" in targets:
        agy_cfg = json.loads(args.agy_hooks.read_text()) if args.agy_hooks.exists() else {}
        updated_agy = configure_agy(json.loads(json.dumps(agy_cfg)), args.remove)
        if args.dry_run:
            print(json.dumps(updated_agy, indent=2))
        else:
            _write_json_atomic(args.agy_hooks, updated_agy)
            print(("Removed" if args.remove else "Added") + f" Jev Guard hook in {args.agy_hooks}")

    if "pi" in targets:
        msg = configure_pi(args.pi_extension, args.remove, dry_run=args.dry_run)
        print(msg)

    return 0


if __name__ == "__main__":
    sys.exit(main())
