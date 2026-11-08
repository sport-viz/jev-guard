"""PreToolUse hook entry point: stdin hook JSON in, decision JSON out, always exit 0.

Pipeline: mode → hard rules → fast path → Jev → policy → audit. Any failure on the way
becomes "ask" (fail to ask): the user decides when the guard can't.
"""

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):  # run as a script by Claude Code / agy / pi
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_guard import audit, config, context, jev, policy, rules, summary  # noqa: E402

RANK = {"pass": 0, "ask": 1, "deny": 2}
HOSTS = {"claude", "agy", "pi"}
CLAUDE_SHELL_TOOLS = {"Bash", "PowerShell"}


@dataclass
class Decision:
    action: str  # "deny" | "ask" | "pass"
    reason: str = ""
    stage: str = ""  # "hard_rule" | "rule" | "fast_path" | "jev" | "jev_unavailable" | "error"
    log: dict = field(default_factory=dict)
    updated_input: dict | None = None


def _build_updated_input(tool_name: str, tool_input: dict, tool_summary: summary.ToolSummary) -> dict | None:
    if tool_name not in CLAUDE_SHELL_TOOLS or not tool_summary.description:
        return None
    return {**tool_input, "description": tool_summary.description}


def _cli_host(argv: list[str] | None = None) -> str:
    args = sys.argv[1:] if argv is None else argv
    for i, arg in enumerate(args):
        if arg == "--host" and i + 1 < len(args) and args[i + 1] in HOSTS:
            return args[i + 1]
        if arg.startswith("--host="):
            val = arg.split("=", 1)[1]
            if val in HOSTS:
                return val
    env_host = os.environ.get("JEV_GUARD_HOST", "").strip().lower()
    return env_host if env_host in HOSTS else "claude"


def normalize_hook_input(parsed: dict, default_host: str = "claude") -> tuple[str, dict]:
    """Detect host format (`claude`, `agy`, `pi`) and return `(host, normalized_hook_input)`."""
    if not isinstance(parsed, dict):
        raise ValueError("hook input is not a PreToolUse JSON object")

    if "toolCall" in parsed or parsed.get("host") == "agy":
        host = "agy"
    elif parsed.get("host") == "pi" or "toolName" in parsed:
        host = "pi"
    else:
        host = default_host

    if host == "agy":
        if "toolCall" in parsed:
            tool_call = parsed.get("toolCall")
            if not isinstance(tool_call, dict):
                raise ValueError("agy toolCall is not a JSON object")
            tool_name = tool_call.get("name", "")
            tool_input = tool_call.get("args") if "args" in tool_call else {}
        else:
            tool_name = parsed.get("tool_name", "")
            tool_input = parsed.get("tool_input", {})
        if not isinstance(tool_input, dict):
            raise ValueError("agy tool input is not a JSON object")
        workspaces = parsed.get("workspacePaths") or []
        cwd = parsed.get("cwd") or (workspaces[0] if workspaces else os.getcwd())
        return "agy", {
            "cwd": cwd,
            "tool_name": tool_name,
            "tool_input": tool_input,
            "transcript_path": parsed.get("transcriptPath") or parsed.get("transcript_path"),
            "artifact_dir": parsed.get("artifactDirectoryPath") or parsed.get("artifact_dir"),
            "session_id": parsed.get("conversationId") or parsed.get("session_id"),
            "agent_type": parsed.get("agent_type") or "agy",
            "permission_mode": parsed.get("permission_mode"),
            "last_user_input": parsed.get("lastUserInput") or parsed.get("last_user_input"),
        }

    if host == "pi":
        tool_name = parsed.get("tool_name") or parsed.get("toolName") or ""
        tool_input = parsed.get("tool_input") if "tool_input" in parsed else parsed.get("input", {})
        if not isinstance(tool_input, dict):
            raise ValueError("pi tool input is not a JSON object")
        return "pi", {
            "cwd": parsed.get("cwd") or os.getcwd(),
            "tool_name": tool_name,
            "tool_input": tool_input,
            "transcript_path": parsed.get("transcript_path") or parsed.get("sessionFile"),
            "user_request": parsed.get("user_request"),
            "session_id": parsed.get("session_id") or parsed.get("sessionId"),
            "agent_type": parsed.get("agent_type") or "pi",
            "permission_mode": parsed.get("permission_mode"),
        }

    if not isinstance(parsed.get("tool_input", {}), dict):
        raise ValueError("hook input is not a PreToolUse JSON object")
    return "claude", parsed


def evaluate(hook_input: dict, assess=jev.assess) -> Decision:
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input") or {}
    project = config.project_dir(hook_input.get("cwd", ""))
    cwd = hook_input.get("cwd") or project
    home = config.home()
    artifact_dir = hook_input.get("artifact_dir")

    rule = rules.check(tool_name, tool_input, cwd, project, home,
                       artifact_dir=artifact_dir)
    log: dict = {"rule_action": rule.action, "rule_reasons": rule.reasons}

    if rule.action == "deny":
        tool_summary = summary.summarize(tool_name, tool_input, cwd, project, home,
                                         artifact_dir=artifact_dir, allow_llm=False)
        log["summary"] = tool_summary.reason_detail
        if tool_summary.risky:
            log["risky"] = tool_summary.risky
        detail = f" ({tool_summary.reason_detail})" if tool_summary.reason_detail else ""
        reason = (f"Jev guard blocked this command: {'; '.join(rule.reasons)}{detail}. This is never "
                  "run automatically. If the user really wants it, they must run it themselves.")
        return Decision("deny", reason, "hard_rule", log)
    if rule.fast_path:
        return Decision("pass", "", "fast_path", log)

    state, has_request = context.build_state(hook_input, rule.facts, project)
    log["has_user_request"] = has_request
    if has_request:
        log["user_request"] = context.truncate(state["user_request"], 600, 0)
    try:
        assessment = assess(state, has_request)
    except jev.JevUnavailable as exc:
        log["error"] = str(exc)
        tool_summary = summary.summarize(tool_name, tool_input, cwd, project, home,
                                         artifact_dir=artifact_dir, allow_llm=True)
        log["summary"] = tool_summary.reason_detail
        if tool_summary.risky:
            log["risky"] = tool_summary.risky
        if tool_summary.used_llm:
            log["summary_used_llm"] = True
        reason = f"Jev guard unavailable ({exc}); confirm manually."
        if rule.reasons:
            reason += f" Also: {'; '.join(rule.reasons)}."
        if tool_summary.reason_detail:
            reason += f" · {tool_summary.reason_detail}"
        updated_input = _build_updated_input(tool_name, tool_input, tool_summary)
        return Decision("ask", reason, "jev_unavailable", log, updated_input)

    verdict = policy.route(assessment.nouls, assessment.severity, assessment.severity_confidence)
    log.update(nouls=assessment.nouls, severity=assessment.severity,
               severity_confidence=assessment.severity_confidence,
               severity_probabilities=assessment.severity_probabilities,
               model=assessment.model, jev_latency_ms=assessment.latency_ms,
               jev_action=verdict.action, fired=verdict.fired)

    action = max(rule.action, verdict.action, key=RANK.__getitem__)
    if action == "pass":
        return Decision("pass", "", "jev", log)

    tool_summary = summary.summarize(tool_name, tool_input, cwd, project, home,
                                     artifact_dir=artifact_dir, allow_llm=(action == "ask"))
    log["summary"] = tool_summary.reason_detail
    if tool_summary.risky:
        log["risky"] = tool_summary.risky
    if tool_summary.used_llm:
        log["summary_used_llm"] = True

    signals = policy.format_signals(verdict.fired, assessment.severity)
    updated_input = None
    if action == "deny":
        detail = f"{signals} · {tool_summary.reason_detail}" if tool_summary.reason_detail else signals
        reason = (f"Jev guard blocked this {tool_name} call ({detail}). Find a safer way to do "
                  "the same job: narrower scope, reversible, inside the project. If the user "
                  "really wants this exact action, ask them to confirm or run it themselves.")
    else:
        parts = ([signals] if verdict.action != "pass" else []) + rule.reasons
        base = "; ".join(parts)
        if tool_summary.reason_detail:
            reason = f"Jev guard: {base} · {tool_summary.reason_detail}" if base else f"Jev guard: {tool_summary.reason_detail}"
        else:
            reason = f"Jev guard: {base}"
        updated_input = _build_updated_input(tool_name, tool_input, tool_summary)
    return Decision(action, reason, "jev" if action == verdict.action else "rule", log, updated_input)


def output(decision: Decision, host: str = "claude") -> str:
    if host in ("agy", "pi"):
        action = "allow" if decision.action == "pass" else decision.action
        payload: dict = {"decision": action}
        if decision.action != "pass" and decision.reason:
            payload["reason"] = decision.reason
        return json.dumps(payload)
    hook_output: dict = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision.action,
        "permissionDecisionReason": decision.reason,
    }
    if decision.updated_input is not None:
        hook_output["updatedInput"] = decision.updated_input
    return json.dumps({"hookSpecificOutput": hook_output})


def main(stdin=sys.stdin, stdout=sys.stdout, assess=jev.assess, argv: list[str] | None = None) -> int:
    started = time.monotonic()
    host = _cli_host(argv)
    mode = config.mode()
    if mode == "off":
        if host in ("agy", "pi"):
            stdout.write(output(Decision("pass"), host) + "\n")
        return 0
    hook_input: dict = {}
    try:
        parsed = json.load(stdin)
        host, hook_input = normalize_hook_input(parsed, default_host=host)
        decision = evaluate(hook_input, assess)
    except Exception as exc:  # fail to ask: never let a guard bug silently allow or crash
        decision = Decision("ask", f"Jev guard error ({type(exc).__name__}: {exc}); confirm manually.",
                            "error", {"error": repr(exc)})

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input") or {}
    if decision.stage != "fast_path":
        audit.record({
            "mode": mode,
            "session_id": hook_input.get("session_id"),
            "agent_type": hook_input.get("agent_type"),
            "tool": tool_name,
            "input_hash": audit.input_hash(tool_name, tool_input),
            "input": context.normalize_input(tool_name, tool_input),
            "decision": decision.action,
            "stage": decision.stage,
            "reason": decision.reason,
            "total_ms": int((time.monotonic() - started) * 1000),
            **decision.log,
        })

    if host in ("agy", "pi"):
        effective = decision if mode == "enforce" else Decision("pass")
        stdout.write(output(effective, host) + "\n")
    elif mode == "enforce" and decision.action != "pass":
        stdout.write(output(decision, host) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
