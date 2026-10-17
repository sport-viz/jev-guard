import json
import subprocess

from jev_guard import context


def write_transcript(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return str(path)


def user(content, **extra):
    return {"type": "user", "message": {"role": "user", "content": content}, **extra}


def test_user_request_keeps_only_real_prompts(tmp_path):
    transcript = write_transcript(tmp_path / "t.jsonl", [
        user("Clean up the build output", origin={"kind": "human"}),
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "ok"}]}},
        user([{"type": "tool_result", "content": "rm: done"}]),
        user("<command-name>/effort</command-name>"),
        user("<local-command-stdout>Set effort</local-command-stdout>"),
        user("Base directory for this skill: ...", isMeta=True),
        user("sub-agent prompt", isSidechain=True),
        user("task notification", origin={"kind": "task-notification"}),
        user([{"type": "text", "text": "and delete the old logs too"}], origin={"kind": "human"}),
        {"type": "last-prompt", "lastPrompt": "ignored"},
        "not even json",
    ])
    assert context.user_request(transcript) == "Clean up the build output\n---\nand delete the old logs too"


def test_user_request_limits_prompts_and_chars(tmp_path):
    transcript = write_transcript(tmp_path / "t.jsonl", [user(f"prompt {i}") for i in range(5)])
    assert context.user_request(transcript) == "prompt 3\n---\nprompt 4"
    long = write_transcript(tmp_path / "long.jsonl", [user("x" * 5000)])
    assert len(context.user_request(long, max_chars=2000)) < 2100


def test_user_request_widens_window_past_large_blobs(tmp_path, monkeypatch):
    monkeypatch.setattr(context.config, "TRANSCRIPT_TAIL_WINDOWS", (1_000, 100_000))
    blob = {"type": "api-request-blob", "message": {"role": "system", "content": "x" * 5_000}}
    transcript = write_transcript(tmp_path / "t.jsonl", [user("first"), blob, user("second")])
    assert context.user_request(transcript) == "first\n---\nsecond"


def test_user_request_missing_or_empty(tmp_path):
    assert context.user_request(None) is None
    assert context.user_request(str(tmp_path / "missing.jsonl")) is None
    assert context.user_request(write_transcript(tmp_path / "t.jsonl", [user([{"type": "tool_result"}])])) is None


def test_normalize_input_truncates_large_fields():
    big = "a" * 10_000
    out = context.normalize_input("Write", {"file_path": "/x", "content": big})
    assert out["file_path"] == "/x"
    assert len(out["content"]) < 2100 and "characters omitted" in out["content"]
    assert out["content"].endswith("a" * 500)
    nested = context.normalize_input("mcp__x__y", {"items": list(range(50))})
    assert len(nested["items"]) == 21


def test_describe_tool():
    assert "shell command" in context.describe_tool("Bash", None)
    mcp = context.describe_tool("mcp__gmail__send_email", {"name": "gmail", "source": "user"})
    assert "`send_email`" in mcp and "`gmail`" in mcp
    assert "`Mystery`" in context.describe_tool("Mystery", None)


def test_describe_target_reports_git_tracking(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "tracked.txt").write_text("x")
    (repo / "untracked.txt").write_text("x")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    assert context.describe_target(str(repo / "tracked.txt"), str(repo))["tracked_by_git"] is True
    assert context.describe_target(str(repo / "untracked.txt"), str(repo))["tracked_by_git"] is False
    missing = context.describe_target(str(tmp_path / "nope"), str(repo))
    assert missing["exists"] is False and missing["inside_project"] is False


def test_build_state_shape(env, tmp_path):
    transcript = write_transcript(tmp_path / "t.jsonl", [user("remove the build dir")])
    hook_input = {"tool_name": "Bash", "tool_input": {"command": "rm -rf build"},
                  "cwd": env.project, "permission_mode": "auto", "transcript_path": transcript}
    state, has_request = context.build_state(hook_input, {"write_targets": [f"{env.project}/build"]}, env.project)
    assert has_request
    assert list(state) == ["user_request", "session", "tool_call", "facts"]
    assert state["tool_call"]["input"] == {"command": "rm -rf build"}
    assert state["facts"]["write_targets"][0]["inside_project"] is True
    assert "project_git" not in state["facts"]  # only for commands that mention git

    hook_input.pop("transcript_path")
    state, has_request = context.build_state(hook_input, {}, env.project)
    assert not has_request and "user_request" not in state and "facts" not in state
