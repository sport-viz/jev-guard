"""PreToolUse hook entry point: stdin hook JSON in, decision JSON out, always exit 0.

Pipeline: mode → hard rules → fast path → Jev → policy → audit. Any failure on the way
becomes "ask" (fail to ask): the user decides when the guard can't.
"""

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

if __package__ in (None, ""):  # run as a script by Claude Code
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jev_guard import audit, config, context, jev, policy, rules  # noqa: E402

RANK = {"pass": 0, "ask": 1, "deny": 2}


@dataclass
class Decision:
    action: str  # "deny" | "ask" | "pass"
    reason: str = ""
    stage: str = ""  # "hard_rule" | "rule" | "fast_path" | "jev" | "jev_unavailable" | "error"
    log: dict = field(default_factory=dict)


def evaluate(hook_input: dict, assess=jev.assess) -> Decision:
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input") or {}
    project = config.project_dir(hook_input.get("cwd", ""))
    home = config.home()

    rule = rules.check(tool_name, tool_input, hook_input.get("cwd") or project, project, home)
    log: dict = {"rule_action": rule.action, "rule_reasons": rule.reasons}

    if rule.action == "deny":
        reason = (f"Jev guard blocked this command: {'; '.join(rule.reasons)}. This is never "
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
        reason = f"Jev guard unavailable ({exc}); confirm manually."
        if rule.reasons:
            reason += f" Also: {'; '.join(rule.reasons)}."
        return Decision("ask", reason, "jev_unavailable", log)

    verdict = policy.route(assessment.nouls, assessment.severity, assessment.severity_confidence)
    log.update(nouls=assessment.nouls, severity=assessment.severity,
               severity_confidence=assessment.severity_confidence,
               severity_probabilities=assessment.severity_probabilities,
               model=assessment.model, jev_latency_ms=assessment.latency_ms,
               jev_action=verdict.action, fired=verdict.fired)

    action = max(rule.action, verdict.action, key=RANK.__getitem__)
    signals = policy.format_signals(verdict.fired, assessment.severity)
    if action == "deny":
        reason = (f"Jev guard blocked this {tool_name} call ({signals}). Find a safer way to do "
                  "the same job: narrower scope, reversible, inside the project. If the user "
                  "really wants this exact action, ask them to confirm or run it themselves.")
    elif action == "ask":
        parts = ([signals] if verdict.action != "pass" else []) + rule.reasons
        reason = "Jev guard: " + "; ".join(parts)
    else:
        reason = ""
    return Decision(action, reason, "jev" if action == verdict.action else "rule", log)


def output(decision: Decision) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision.action,
        "permissionDecisionReason": decision.reason,
    }})


def main(stdin=sys.stdin, stdout=sys.stdout, assess=jev.assess) -> int:
    started = time.monotonic()
    mode = config.mode()
    if mode == "off":
        return 0
    hook_input: dict = {}
    try:
        parsed = json.load(stdin)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("tool_input", {}), dict):
            raise ValueError("hook input is not a PreToolUse JSON object")
        hook_input = parsed
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

    if mode == "enforce" and decision.action != "pass":
        stdout.write(output(decision) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
