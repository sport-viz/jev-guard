import os
from dataclasses import dataclass

import pytest


@dataclass
class Env:
    home: str
    project: str       # <tmp>/z/proj
    sibling: str       # <tmp>/z/other: same parent as the project
    elsewhere: str     # <tmp>/elsewhere: outside the project's parent
    guard_home: str


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Unit tests never call TypeSafe; a test that reaches the live client sees a failure."""
    from jev_guard import jev

    def offline(*args, **kwargs):
        raise ConnectionError("network disabled in unit tests")
    monkeypatch.setattr(jev, "ask_jev", offline)


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    root = os.path.realpath(tmp_path)
    paths = Env(
        home=f"{root}/home",
        project=f"{root}/z/proj",
        sibling=f"{root}/z/other",
        elsewhere=f"{root}/elsewhere",
        guard_home=f"{root}/home/.claude/jev-guard",
    )
    for p in (paths.home, paths.project, paths.sibling, paths.elsewhere, paths.guard_home):
        os.makedirs(p, exist_ok=True)
    monkeypatch.setenv("HOME", paths.home)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", paths.project)
    monkeypatch.setenv("JEV_GUARD_HOME", paths.guard_home)
    monkeypatch.delenv("JEV_GUARD_MODE", raising=False)
    return paths
