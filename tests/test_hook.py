import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from jev_guard import hook, jev

REPO = Path(__file__).resolve().parent.parent


def fake_assess(nouls=None, severity=0.1, confidence=0.9):
    calls = []

    def assess(state, include_unrequested):
        calls.append((state, include_unrequested))
        return jev.Assessment(nouls=nouls or {"data_loss": 0.02}, severity=severity,
                              severity_confidence=confidence, model="jev-test", latency_ms=12)
    assess.calls = calls
    return assess


def run(env, tool, assess=jev.assess, **tool_input):
    payload = {"session_id": "s1", "hook_event_name": "PreToolUse", "cwd": env.project,
               "permission_mode": "auto", "tool_name": tool, "tool_input": tool_input}
    out = io.StringIO()
    assert hook.main(io.StringIO(json.dumps(payload)), out, assess) == 0
    text = out.getvalue().strip()
    return json.loads(text)["hookSpecificOutput"] if text else None


def audit_entries(env):
    path = Path(env.guard_home) / "decisions.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_fast_path_emits_nothing_and_skips_jev(env):
    assess = fake_assess()
    assert run(env, "Bash", assess, command="git status") is None
    assert assess.calls == [] and audit_entries(env) == []


def test_hard_rule_denies_without_jev(env):
    assess = fake_assess()
    out = run(env, "Bash", assess, command="rm -rf ~")
    assert out["permissionDecision"] == "deny" and out["hookEventName"] == "PreToolUse"
    assert "never run automatically" in out["permissionDecisionReason"]
    assert assess.calls == []


def test_safe_verdict_has_no_opinion(env):
    assess = fake_assess()
    assert run(env, "Bash", assess, command="npm test") is None
    assert len(assess.calls) == 1
    assert audit_entries(env)[0]["decision"] == "pass"


def test_risky_verdict_denies_with_reason_for_claude(env):
    out = run(env, "Bash", fake_assess({"data_loss": 0.93}, 2.4), command="git reset --hard")
    assert out["permissionDecision"] == "deny"
    assert "data_loss 0.93" in out["permissionDecisionReason"]
    assert "safer way" in out["permissionDecisionReason"]


def test_borderline_verdict_asks(env):
    out = run(env, "Bash", fake_assess({"external_effect": 0.6}, 1.0), command="git push")
    assert out["permissionDecision"] == "ask"
    assert out["permissionDecisionReason"].startswith("Jev guard: external_effect 0.60")


def test_rule_floor_survives_a_safe_verdict(env):
    out = run(env, "Write", fake_assess(), file_path=f"{env.home}/.bashrc", content="alias x=y")
    assert out["permissionDecision"] == "ask"
    assert "dotfile" in out["permissionDecisionReason"]


def test_jev_can_raise_a_rule_floor_to_deny(env):
    out = run(env, "Bash", fake_assess({"data_loss": 0.95}, 2.5), command="rm -rf /etc/nginx")
    assert out["permissionDecision"] == "deny"


def test_jev_unavailable_fails_to_ask(env):
    out = run(env, "Bash", command="npm test")  # phase-1 stub always raises
    assert out["permissionDecision"] == "ask"
    assert "Jev guard unavailable" in out["permissionDecisionReason"]
    assert audit_entries(env)[0]["stage"] == "jev_unavailable"


def test_unexpected_exception_fails_to_ask(env):
    def broken(state, include_unrequested):
        raise RuntimeError("boom")
    out = run(env, "Bash", broken, command="npm test")
    assert out["permissionDecision"] == "ask" and "RuntimeError: boom" in out["permissionDecisionReason"]


@pytest.mark.parametrize("stdin", ["not json", "[1, 2]", '{"tool_name": "Bash", "tool_input": "x"}'])
def test_malformed_input_fails_to_ask(env, stdin):
    out = io.StringIO()
    assert hook.main(io.StringIO(stdin), out, fake_assess()) == 0
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_shadow_mode_logs_but_never_decides(env, monkeypatch):
    monkeypatch.setenv("JEV_GUARD_MODE", "shadow")
    assert run(env, "Bash", fake_assess({"data_loss": 0.95}, 2.5), command="git clean -fdx") is None
    entry = audit_entries(env)[0]
    assert entry["mode"] == "shadow" and entry["decision"] == "deny"
    assert entry["nouls"] == {"data_loss": 0.95} and entry["model"] == "jev-test"


def test_off_mode_does_nothing(env, monkeypatch):
    monkeypatch.setenv("JEV_GUARD_MODE", "off")
    assess = fake_assess()
    assert run(env, "Bash", assess, command="rm -rf ~") is None
    assert assess.calls == [] and audit_entries(env) == []


def test_unrequested_question_only_when_request_known(env, tmp_path):
    transcript = tmp_path / "t.jsonl"
    transcript.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": "run tests"}}))
    assess = fake_assess()
    payload = {"cwd": env.project, "tool_name": "Bash", "tool_input": {"command": "npm test"},
               "transcript_path": str(transcript)}
    hook.main(io.StringIO(json.dumps(payload)), io.StringIO(), assess)
    payload.pop("transcript_path")
    hook.main(io.StringIO(json.dumps(payload)), io.StringIO(), assess)
    assert [include for _, include in assess.calls] == [True, False]
    assert assess.calls[0][0]["user_request"] == "run tests"


def test_script_entry_point_runs_standalone(env):
    payload = json.dumps({"cwd": env.project, "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}})
    result = subprocess.run([sys.executable, str(REPO / "jev_guard" / "hook.py")], input=payload,
                            capture_output=True, text=True, cwd="/", env=os.environ.copy(), timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
