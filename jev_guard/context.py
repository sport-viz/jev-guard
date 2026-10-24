"""Builds the state Jev sees: the tool call, what the user asked for, and exact facts.

Kept small on purpose. Jev's accuracy drops when state carries irrelevant detail, so inputs
are truncated and only facts code knows exactly are included.
"""

import json
import os
import re
import subprocess

from jev_guard import config, rules

TOOL_DESCRIPTIONS = {
    "Bash": "Runs a shell command on the user's machine.",
    "PowerShell": "Runs a PowerShell command on the user's machine.",
    "Write": "Creates a file, or replaces an existing file's entire contents.",
    "Edit": "Replaces text inside an existing file.",
    "MultiEdit": "Makes several text replacements inside an existing file.",
    "NotebookEdit": "Edits a cell in a Jupyter notebook.",
    "Read": "Reads a file.",
    "Grep": "Searches file contents.",
    "Glob": "Lists files matching a pattern.",
    "WebFetch": "Fetches a URL over the network and reads the page.",
    "WebSearch": "Runs a web search.",
    "Agent": "Starts a sub-agent that carries out the given task with its own tool calls.",
    # Antigravity (agy)
    "run_command": "Runs a shell command on the user's machine.",
    "write_file": "Creates a file, or replaces or appends to an existing file.",
    "write_to_file": "Creates a file, or replaces an existing file's entire contents.",
    "edit_file": "Replaces text inside an existing file.",
    "replace_file_content": "Replaces text inside an existing file.",
    "multi_replace_file_content": "Makes several text replacements inside an existing file.",
    "read_file": "Reads a file.",
    "view_file": "Reads a file.",
    "view_file_outline": "Reads the symbol outline of a file.",
    "view_code_item": "Reads a specific function or class in a file.",
    "grep_search": "Searches file contents.",
    "find_by_name": "Lists files matching a pattern.",
    "list_dir": "Lists the contents of a directory.",
    "search_web": "Runs a web search.",
    "read_url_content": "Fetches a URL over the network and reads the page.",
    "invoke_subagent": "Starts a sub-agent that carries out the given task with its own tool calls.",
    "define_subagent": "Defines a new sub-agent type for the current conversation.",
    "manage_subagents": "Lists or terminates running sub-agents.",
    "manage_task": "Lists, inspects, sends input to, or terminates background tasks.",
    "send_message": "Sends a message to another agent in the conversation.",
    "schedule": "Schedules a timer or recurring cron job that wakes the agent.",
    "ask_question": "Asks the user multiple-choice questions and waits for answers.",
    # Pi (pi-coding-agent)
    "bash": "Runs a shell command on the user's machine.",
    "write": "Creates a file, or replaces an existing file's entire contents.",
    "edit": "Replaces text inside an existing file.",
    "read": "Reads a file.",
    "grep": "Searches file contents.",
    "find": "Lists files matching a pattern.",
    "ls": "Lists the contents of a directory.",
}

# Per-field character budgets: (head, tail). Fields not listed use DEFAULT_BUDGET.
FIELD_BUDGETS = {
    ("Write", "content"): (1500, 500),
    ("Edit", "old_string"): (800, 0),
    ("Edit", "new_string"): (800, 0),
    ("Bash", "command"): (2000, 800),
    ("PowerShell", "command"): (2000, 800),
    ("write_file", "Content"): (1500, 500),
    ("write_to_file", "CodeContent"): (1500, 500),
    ("edit_file", "Target"): (800, 0),
    ("edit_file", "Replacement"): (800, 0),
    ("replace_file_content", "TargetContent"): (800, 0),
    ("replace_file_content", "ReplacementContent"): (800, 0),
    ("run_command", "CommandLine"): (2000, 800),
    ("write", "content"): (1500, 500),
    ("edit", "oldText"): (800, 0),
    ("edit", "newText"): (800, 0),
    ("bash", "command"): (2000, 800),
}
DEFAULT_BUDGET = (1200, 300)
MAX_LIST_ITEMS = 20


def truncate(text: str, head: int, tail: int) -> str:
    if len(text) <= head + tail:
        return text
    omitted = len(text) - head - tail
    return text[:head] + f"\n[... {omitted} characters omitted ...]\n" + (text[-tail:] if tail else "")


def _shrink(value, budget, depth=0):
    if isinstance(value, str):
        return truncate(value, *budget)
    if depth >= 4:
        return truncate(json.dumps(value, default=str), *DEFAULT_BUDGET)
    if isinstance(value, dict):
        return {k: _shrink(v, DEFAULT_BUDGET, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        items = [_shrink(v, DEFAULT_BUDGET, depth + 1) for v in value[:MAX_LIST_ITEMS]]
        if len(value) > MAX_LIST_ITEMS:
            items.append(f"[... {len(value) - MAX_LIST_ITEMS} more items omitted ...]")
        return items
    return value


def normalize_input(tool_name: str, tool_input: dict) -> dict:
    return {key: _shrink(value, FIELD_BUDGETS.get((tool_name, key), DEFAULT_BUDGET))
            for key, value in tool_input.items()}


def describe_tool(tool_name: str, mcp_server: dict | None) -> str:
    if tool_name in TOOL_DESCRIPTIONS:
        return TOOL_DESCRIPTIONS[tool_name]
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        server = (mcp_server or {}).get("name") or (parts[1] if len(parts) > 1 else "unknown")
        tool = parts[-1]
        return f"Calls the `{tool}` tool on the MCP server `{server}`, which may act on an external service."
    return f"A Claude Code tool named `{tool_name}`."


# --- transcript ------------------------------------------------------------------------

_USER_REQUEST_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.DOTALL)
_USER_LINE_MARKERS = (
    '"type":"user"',
    '"type": "user"',
    '"type":"USER_INPUT"',
    '"type": "USER_INPUT"',
    '"role":"user"',
    '"role": "user"',
)


def _prompt_text(entry: dict) -> str | None:
    """The text of a real user prompt, or None for tool results, meta and command entries."""
    entry_type = entry.get("type")
    if entry_type == "USER_INPUT":
        if entry.get("source") not in (None, "USER_EXPLICIT"):
            return None
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            return None
        match = _USER_REQUEST_RE.search(content)
        text = match.group(1).strip() if match else content.strip()
        return text or None

    if entry_type == "message":
        message = entry.get("message") or {}
        if message.get("role") != "user":
            return None
        content = message.get("content")
    elif entry_type == "user" and not entry.get("isMeta") and not entry.get("isSidechain"):
        origin = entry.get("origin")
        if isinstance(origin, dict) and origin.get("kind") not in (None, "human"):
            return None
        content = (entry.get("message") or {}).get("content")
    else:
        return None

    if isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        content = "\n".join(b.get("text", "") for b in content
                            if isinstance(b, dict) and b.get("type") == "text")
    if not isinstance(content, str) or not content.strip():
        return None
    if content.lstrip().startswith(("<command-name>", "<command-message>", "<local-command-")):
        return None
    return content.strip()


def user_request(transcript_path: str | None,
                 max_prompts: int = config.USER_REQUEST_MAX_PROMPTS,
                 max_chars: int = config.USER_REQUEST_MAX_CHARS) -> str | None:
    """The most recent user prompts, oldest first, read from the end of the transcript."""
    if not transcript_path:
        return None

    # Transcripts hold large API blobs, so a few prompts can span megabytes. Widen the tail
    # window until enough prompts turn up, decoding only lines that can be user entries.
    prompts: list[str] = []
    try:
        with open(transcript_path, "rb") as f:
            size = f.seek(0, os.SEEK_END)
            for window in config.TRANSCRIPT_TAIL_WINDOWS:
                f.seek(max(0, size - window))
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                prompts = []
                for line in reversed(lines):
                    if not any(m in line for m in _USER_LINE_MARKERS):
                        continue
                    try:
                        text = _prompt_text(json.loads(line))
                    except (json.JSONDecodeError, AttributeError):
                        continue
                    if text:
                        prompts.append(text)
                        if len(prompts) == max_prompts:
                            break
                if len(prompts) == max_prompts or window >= size:
                    break
    except OSError:
        return None
    if not prompts:
        return None

    # Newest prompt gets the budget first; older ones fill what's left.
    kept, remaining = [], max_chars
    for text in prompts:
        if remaining <= 200:
            break
        kept.append(truncate(text, remaining - 100, 0) if len(text) > remaining else text)
        remaining -= len(kept[-1])
    return "\n---\n".join(reversed(kept))


# --- facts -----------------------------------------------------------------------------

def _git(args: list[str], cwd: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=1.5)
    except (OSError, subprocess.SubprocessError):
        return None


def describe_target(path: str, project: str) -> dict:
    """Exists / inside project / tracked by git, so Jev can judge reversibility."""
    info = {"path": path, "exists": os.path.exists(path),
            "inside_project": path == project or path.startswith(project.rstrip("/") + "/")}
    directory = path if os.path.isdir(path) else os.path.dirname(path)
    if info["exists"] and os.path.isdir(directory):
        result = _git(["ls-files", "--", path], directory)
        if result is not None and result.returncode == 0:
            info["tracked_by_git"] = bool(result.stdout.strip())
    return info


def project_git_facts(project: str) -> dict | None:
    result = _git(["status", "--porcelain"], project)
    if result is None or result.returncode != 0:
        return {"is_git_repo": False}
    return {"is_git_repo": True, "has_uncommitted_changes": bool(result.stdout.strip())}


def build_state(hook_input: dict, rule_facts: dict, project: str) -> tuple[dict, bool]:
    """Returns (state, has_user_request)."""
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input") or {}
    mcp_server = hook_input.get("mcp_server")

    facts: dict = {}
    targets = rule_facts.get("write_targets", [])[:10]
    if targets:
        facts["write_targets"] = [describe_target(t, project) for t in targets]
    for key in ("unresolved_write_targets", "sensitive_read", "shell_parse_failed"):
        if rule_facts.get(key):
            facts[key] = rule_facts[key]
    if tool_name in rules.SHELL_TOOLS and "git" in rules.shell_command(tool_input):
        facts["project_git"] = project_git_facts(project)
    if isinstance(mcp_server, dict) and mcp_server.get("source"):
        facts["mcp_server_source"] = mcp_server["source"]

    request = hook_input.get("user_request") or user_request(hook_input.get("transcript_path"))
    last_input = (hook_input.get("last_user_input") or "").strip()
    if last_input:
        if not request:
            request = truncate(last_input, config.USER_REQUEST_MAX_CHARS - 100, 0)
        elif last_input not in request:
            request = truncate(f"{request}\n---\n{last_input}", config.USER_REQUEST_MAX_CHARS - 100, 0)
    state = {
        "session": {
            "project_dir": project,
            "cwd": hook_input.get("cwd"),
            "permission_mode": hook_input.get("permission_mode"),
            "agent_type": hook_input.get("agent_type"),
        },
        "tool_call": {
            "tool": tool_name,
            "what_the_tool_does": describe_tool(tool_name, mcp_server),
            "input": normalize_input(tool_name, tool_input),
        },
    }
    if request:
        state = {"user_request": request, **state}
    if facts:
        state["facts"] = facts
    return state, request is not None
