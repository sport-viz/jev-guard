"""Code-side rules that run before Jev and can't be argued with.

`check()` returns a RuleResult:
- action "deny": a catastrophe we never need a model to recognize. Jev is skipped.
- action "ask": a floor. Jev still runs and may raise it to deny, but never lower it.
- action "pass" with fast_path=True: known harmless, so Jev is skipped.
- action "pass" with fast_path=False: no rule fired, so Jev decides.
"""

import fnmatch
import os
import re
from dataclasses import dataclass, field

from jev_guard import config, shell

READ_ONLY_TOOLS = {
    # Claude Code
    "Read", "Glob", "Grep", "LS", "NotebookRead", "LSP", "ToolSearch", "Skill",
    "TodoWrite", "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput",
    "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "ListAgents", "CronList",
    # Antigravity (agy)
    "read_file", "view_file", "view_file_outline", "view_code_item", "view_content_chunk",
    "grep_search", "find_by_name", "list_dir", "list_directory", "list_resources",
    "read_resource", "read_notebook", "command_status", "ask_question",
    "code_search", "trajectory_search", "tool_search", "find_all_references",
    # Pi (pi-coding-agent)
    "read", "grep", "find", "ls",
}
FILE_WRITE_TOOLS = {
    # Claude Code
    "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
    # Antigravity (agy)
    "write_file": "Path", "edit_file": "Path", "write_to_file": "TargetFile",
    "replace_file_content": "TargetFile", "multi_replace_file_content": "TargetFile",
    "edit_notebook": "Path",
    # Pi (pi-coding-agent)
    "write": "path", "edit": "path",
}
FILE_READ_TOOLS = {
    # Claude Code
    "Read": "file_path", "Grep": "path", "Glob": "path", "LS": "path",
    "NotebookRead": "notebook_path",
    # Antigravity (agy)
    "read_file": "Path", "view_file": "AbsolutePath", "view_file_outline": "AbsolutePath",
    "view_code_item": "File", "grep_search": "SearchPath", "find_by_name": "SearchDirectory",
    "list_dir": "DirectoryPath", "list_directory": "DirectoryPath", "read_notebook": "Path",
    # Pi (pi-coding-agent)
    "read": "path", "grep": "path", "find": "path", "ls": "path",
}
SHELL_TOOLS = {"Bash", "PowerShell", "run_command", "bash"}

# Single read-only commands that skip Jev when they have no operators or redirections.
SAFE_COMMANDS = {
    "ls", "pwd", "echo", "which", "whoami", "date", "cat", "head", "tail", "wc", "file",
    "stat", "du", "df", "tree", "uname", "type", "realpath", "basename", "dirname", "true",
    "grep", "rg", "diff", "sort", "uniq", "hostname", "id",
}
SAFE_GIT_SUBCOMMANDS = {"status", "diff", "log", "show", "rev-parse", "ls-files", "blame",
                        "describe", "shortlog"}
# Reading these through a "safe" command still goes to Jev's secrets question.
SENSITIVE_PATTERNS = [
    "~/.ssh/*", "~/.aws/*", "~/.gnupg/*", "~/.config/gcloud/*", "~/.kube/*", "~/.azure/*",
    "~/.docker/config.json", "~/.netrc", "~/.npmrc", "~/.pypirc", "~/.git-credentials",
    "*/.env", "*/.env.*", "*credential*", "*secret*", "*.pem", "*.key", "*/id_rsa*",
    "*/id_ed25519*", "*/id_ecdsa*", "*.p12", "*.keystore",
]

SYSTEM_DIRS = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt",
               "/proc", "/root", "/sbin", "/sys", "/usr", "/var", "/srv", "/mnt"}
DISK_DEVICE = re.compile(r"^/dev/(sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|xvd[a-z]|mmcblk\d|disk\d)")
FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")
GUARD_MARKERS = (
    "jev-guard", "jev_guard_mode", ".claude/settings",
    "hooks.json", ".pi/agent/extensions", ".pi/extensions", "jev-guard.ts",
)


@dataclass
class RuleResult:
    action: str = "pass"  # "deny" | "ask" | "pass"
    reasons: list[str] = field(default_factory=list)
    fast_path: bool = False
    facts: dict = field(default_factory=dict)


# --- paths -----------------------------------------------------------------------------

def resolve(path: str, cwd: str, home: str) -> str | None:
    """Absolute, symlink-resolved path, or None if it depends on an unknown variable.

    Globs are cut at the first wildcard segment so `~/.config/*` resolves to `~/.config`.
    """
    if not path:
        return None
    p = path
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    p = re.sub(r"^\$\{?HOME\}?(?=/|$)", home, p)
    if "$" in p or p.startswith("~"):  # $OTHER_VAR or ~otheruser
        return None
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    parts = p.split("/")
    for i, part in enumerate(parts):
        if any(c in part for c in "*?["):
            p = "/".join(parts[:i]) or "/"
            break
    return os.path.realpath(p)


def within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def is_sensitive(path: str, home: str) -> bool:
    patterns = [p.replace("~", home, 1) if p.startswith("~") else p for p in SENSITIVE_PATTERNS]
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path + "/", p) for p in patterns)


def is_protected(path: str, home: str) -> bool:
    """The guard itself and agent hook/extension settings: the agent must not disable its own guard."""
    guard = os.path.realpath(str(config.guard_home()))
    name = os.path.basename(path)
    parent_dir = os.path.dirname(path)
    parent = os.path.basename(parent_dir)
    grandparent = os.path.basename(os.path.dirname(parent_dir))
    if within(path, guard):
        return True
    # Claude Code settings
    if fnmatch.fnmatch(name, "settings*.json") and parent == ".claude":
        return True
    # Antigravity (agy) hooks and customization settings
    if name == "hooks.json":
        return True
    if name in {"settings.json", "config.json", "plugins.json"} and (
        parent in {".agents", ".agent", "_agents", "_agent"}
        or within(path, os.path.join(home, ".gemini"))
    ):
        return True
    # Pi extensions and settings
    if within(path, os.path.join(home, ".pi", "agent", "extensions")):
        return True
    if parent == "extensions" and grandparent == ".pi":
        return True
    if fnmatch.fnmatch(name, "settings*.json") and (
        parent == ".pi" or within(path, os.path.join(home, ".pi"))
    ):
        return True
    return False


def scope_violation(path: str, project: str, home: str,
                    artifact_dir: str | None = None) -> str | None:
    """Why a write to `path` needs the user's confirmation, or None if it's in scope."""
    exempt_roots = [
        config.scratch_root(),
        os.path.join(home, ".claude", "projects"),
        os.path.join(home, ".gemini", "antigravity", "brain"),
        os.path.join(home, ".gemini", "antigravity-cli", "brain"),
        os.path.join(home, ".gemini", "antigravity-ide", "brain"),
        os.path.join(home, ".gemini", "antigravity", "conversations"),
        os.path.join(home, ".gemini", "antigravity-cli", "conversations"),
        os.path.join(home, ".gemini", "antigravity-ide", "conversations"),
        os.path.join(home, ".pi", "agent", "sessions"),
    ]
    if artifact_dir:
        exempt_roots.append(os.path.realpath(artifact_dir))
    if any(within(path, root) for root in exempt_roots):
        return None
    if within(path, home) and path != home:
        first = os.path.relpath(path, home).split("/")[0]
        if first.startswith("."):
            return f"writes to dotfile {path}"
    if not within(path, project) and os.path.basename(path).startswith("."):
        return f"writes to dotfile {path}"
    parent = os.path.dirname(project.rstrip("/")) or "/"
    if not within(path, parent):
        return f"writes outside {parent}: {path}"
    return None


# --- shell rules -----------------------------------------------------------------------

def _is_catastrophic_target(target: str, cwd: str, home: str) -> bool:
    if target in {"*", ".", "./*", "./", ".*"}:
        resolved = os.path.realpath(cwd)
        return resolved in SYSTEM_DIRS or resolved == home
    resolved = resolve(target, cwd, home)
    return resolved is not None and (resolved in SYSTEM_DIRS or resolved == home)


def catastrophic(parsed: shell.ParsedCommand, cwd: str, home: str) -> str | None:
    if FORK_BOMB.search(parsed.raw):
        return "fork bomb"
    for cmd in parsed.commands:
        name, flags = cmd.name, cmd.short_flags()
        recursive = bool({"-r", "-R", "--recursive"} & flags)
        if name == "rm":
            if "--no-preserve-root" in cmd.args:
                return "rm --no-preserve-root"
            if recursive and any(_is_catastrophic_target(t, cwd, home) for t in cmd.operands()):
                return "recursive delete of a system directory or your home directory"
        if name.startswith("mkfs") or name == "wipefs":
            return f"{name} formats or wipes a disk"
        if name in {"dd", "shred"} and any(DISK_DEVICE.match(t) for t in shell.write_targets(cmd)):
            return f"{name} writes directly to a disk device"
        if any(DISK_DEVICE.match(t) for op, t in cmd.redirects if op in shell.WRITE_REDIRECTS):
            return "redirect onto a disk device"
        if name in {"chmod", "chown", "chgrp"} and recursive:
            if any(_is_catastrophic_target(t, cwd, home) for t in cmd.operands()):
                return f"recursive {name} on a system directory or your home directory"
        source = cmd.piped_from
        if name in shell.SHELLS and cmd.sudo and source and source.name in {"curl", "wget"}:
            return "downloaded script piped into a root shell"
    return None


def mentions_guard(parsed: shell.ParsedCommand) -> bool:
    """Whether the command refers to the guard or Claude settings outside of message text.

    Scans parsed words (heredoc bodies already dropped) and skips git commit/tag messages,
    so describing the guard in a commit doesn't trip self-protection. If the command
    couldn't be parsed, the raw text is scanned instead.
    """
    if not parsed.parsed:
        return any(m in parsed.raw.lower() for m in GUARD_MARKERS)
    for cmd in parsed.commands:
        words, skip = [t for _, t in cmd.redirects], False
        for arg in cmd.argv:
            if skip:
                skip = False
            elif cmd.name == "git" and arg in {"-m", "--message"}:
                skip = True
            elif not (cmd.name == "git" and arg.startswith("--message=")):
                words.append(arg)
        if any(m in word.lower() for word in words for m in GUARD_MARKERS):
            return True
    return False


def is_safe_command(parsed: shell.ParsedCommand, cwd: str, home: str) -> bool:
    """One plain read-only command with no operators, redirections or substitutions."""
    if not parsed.parsed or parsed.complex or len(parsed.commands) != 1:
        return False
    if any(marker in parsed.raw for marker in (";", "&", "|", ">", "<", "\n")):
        return False
    cmd = parsed.commands[0]
    if cmd.sudo or cmd.redirects:
        return False
    if cmd.name == "git":
        sub = next((a for a in cmd.args if not a.startswith("-")), None)
        if sub not in SAFE_GIT_SUBCOMMANDS or "--output" in " ".join(cmd.args):
            return False
    elif cmd.name not in SAFE_COMMANDS:
        return False
    for arg in cmd.operands():
        path = resolve(arg, cwd, home)
        if path and is_sensitive(path, home):
            return False
    return True


def shell_command(tool_input: dict) -> str:
    """Command string from a Claude/Pi (`command`) or Antigravity (`CommandLine`) shell tool."""
    if "command" in tool_input:
        return str(tool_input.get("command") or "")
    return str(tool_input.get("CommandLine") or "")


def _read_target(tool_name: str, tool_input: dict) -> str:
    key = FILE_READ_TOOLS.get(tool_name)
    if key and tool_input.get(key):
        return str(tool_input[key])
    for fallback in ("Path", "path", "file_path", "AbsolutePath", "SearchPath",
                     "SearchDirectory", "DirectoryPath"):
        if tool_input.get(fallback):
            return str(tool_input[fallback])
    return ""


# --- entry point -----------------------------------------------------------------------

def check(tool_name: str, tool_input: dict, cwd: str, project: str, home: str,
          artifact_dir: str | None = None) -> RuleResult:
    result = RuleResult()
    cwd = os.path.realpath(cwd or project)

    if tool_name in SHELL_TOOLS:
        command = shell_command(tool_input)
        if tool_name == "PowerShell":
            return result  # not parsed; Jev decides
        parsed = shell.parse(command)
        result.facts["shell_parse_failed"] = not parsed.parsed

        reason = catastrophic(parsed, cwd, home)
        if reason:
            return RuleResult("deny", [reason], facts=result.facts)

        targets, unresolved = [], []
        for cmd in parsed.commands:
            for raw in shell.write_targets(cmd):
                path = resolve(raw, cwd, home)
                (targets if path else unresolved).append(path or raw)
        if targets:
            result.facts["write_targets"] = sorted(set(targets))
        if unresolved:
            result.facts["unresolved_write_targets"] = sorted(set(unresolved))

        safe = is_safe_command(parsed, cwd, home) and not tool_input.get("BypassSandbox")
        if any(is_protected(t, home) for t in targets) or (mentions_guard(parsed) and not safe):
            result.action = "ask"
            result.reasons.append("touches the guard or Claude Code settings")
        for path in targets:
            violation = scope_violation(path, project, home, artifact_dir)
            if violation:
                result.action = "ask"
                result.reasons.append(violation)
        if result.action == "pass" and safe:
            result.fast_path = True
        return result

    if tool_name in FILE_WRITE_TOOLS:
        path = resolve(str(tool_input.get(FILE_WRITE_TOOLS[tool_name], "")), cwd, home)
        if path:
            result.facts["write_targets"] = [path]
            if is_protected(path, home):
                result.action = "ask"
                result.reasons.append("touches the guard or Claude Code settings")
            violation = scope_violation(path, project, home, artifact_dir)
            if violation:
                result.action = "ask"
                result.reasons.append(violation)
        return result

    if tool_name in READ_ONLY_TOOLS:
        raw_target = _read_target(tool_name, tool_input)
        path = resolve(raw_target, cwd, home) if raw_target else None
        if path and is_sensitive(path, home):
            result.facts["sensitive_read"] = path
            return result  # Jev's secrets question decides
        result.fast_path = True
        return result

    if tool_name == "manage_task" and tool_input.get("Action") in {"list", "status"}:
        result.fast_path = True
        return result

    if tool_name == "manage_subagents" and tool_input.get("Action") == "list":
        result.fast_path = True
        return result

    if (tool_name == "Agent" and tool_input.get("isolation") != "remote") or tool_name == "invoke_subagent":
        # A local sub-agent's own tool calls each pass through this hook.
        result.fast_path = True
    return result
