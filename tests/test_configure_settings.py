import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "configure_settings", Path(__file__).resolve().parent.parent / "scripts" / "configure_settings.py")
configure_settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure_settings)

OTHER_HOOK = {"matcher": "Bash", "hooks": [{"type": "command", "command": "./lint.sh"}]}


def test_add_keeps_other_settings_and_hooks():
    settings = {"theme": "dark", "hooks": {"PreToolUse": [OTHER_HOOK], "Stop": [OTHER_HOOK]}}
    out = configure_settings.configure(settings, remove=False)
    assert out["theme"] == "dark" and out["hooks"]["Stop"] == [OTHER_HOOK]
    assert out["hooks"]["PreToolUse"] == [OTHER_HOOK, configure_settings.ENTRY]


def test_add_is_idempotent():
    once = configure_settings.configure({}, remove=False)
    twice = configure_settings.configure(once, remove=False)
    assert twice["hooks"]["PreToolUse"] == [configure_settings.ENTRY]


def test_remove_restores_original_shape():
    added = configure_settings.configure({"theme": "dark"}, remove=False)
    assert configure_settings.configure(added, remove=True) == {"theme": "dark"}
    mixed = configure_settings.configure({"hooks": {"PreToolUse": [OTHER_HOOK]}}, remove=False)
    assert configure_settings.configure(mixed, remove=True) == {"hooks": {"PreToolUse": [OTHER_HOOK]}}


def test_entry_fails_closed_on_broken_install():
    hook = configure_settings.ENTRY["hooks"][0]
    assert hook["onFailure"] == "block" and hook["timeout"] == 20
    assert configure_settings.ENTRY["matcher"] == "*"
