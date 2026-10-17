"""Runtime settings. Everything here comes from code or the hook's environment.

The hook's environment is inherited from the Claude Code process, so nothing Claude runs
through Bash (an `export`, a file it writes) can change these values.
"""

import os
from pathlib import Path

MODE_ENV = "JEV_GUARD_MODE"
MODES = ("enforce", "shadow", "off")

# Pinned so tuned thresholds stay valid; bump only after re-running evals.
MODEL = "jev-1.13.0"
JEV_TIMEOUT_S = 4.0
JEV_MAX_RETRIES = 1
JEV_BACKOFF_MAX_S = 0.3

# Truncation budgets for what we send to Jev (large state lowers accuracy).
USER_REQUEST_MAX_CHARS = 2000
USER_REQUEST_MAX_PROMPTS = 2
TRANSCRIPT_TAIL_WINDOWS = (2_000_000, 8_000_000, 32_000_000)


def mode() -> str:
    value = os.environ.get(MODE_ENV, "enforce").strip().lower()
    return value if value in MODES else "enforce"


def home() -> str:
    return os.path.realpath(os.path.expanduser("~"))


def guard_home() -> Path:
    """Where the installed guard and its audit log live."""
    override = os.environ.get("JEV_GUARD_HOME")
    return Path(override) if override else Path(home()) / ".claude" / "jev-guard"


def audit_log_path() -> Path:
    return guard_home() / "decisions.jsonl"


def project_dir(hook_cwd: str) -> str:
    """Claude Code sets CLAUDE_PROJECT_DIR for hooks; fall back to the session cwd."""
    return os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or hook_cwd or os.getcwd())


def scratch_root() -> str:
    """Claude Code's per-user scratch area, exempt from the protected write scope."""
    return f"/tmp/claude-{os.getuid()}"
