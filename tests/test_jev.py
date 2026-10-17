from types import SimpleNamespace

import pytest

from jev_guard import jev, questions


def response(nouls, score=0.4, confidence=0.8, model="jev-1.13.0"):
    return SimpleNamespace(
        nouls={k: SimpleNamespace(noul=v) for k, v in nouls.items()},
        scores={"severity": SimpleNamespace(score=score, confidence=confidence,
                                            probabilities={"0": 0.6, "1": 0.4, "2": 0.0, "3": 0.0})},
        model=model,
    )


def test_battery_includes_unrequested_only_on_request():
    assert "unrequested" not in questions.battery(False)
    full = questions.battery(True)
    assert set(full) == set(questions.HAZARDS) | {"severity", "unrequested"}


def test_every_question_tells_jev_to_ignore_claims():
    for question in questions.battery(True).values():
        assert questions.JUDGE_EFFECTS in question.instructions


def test_assess_parses_answers(monkeypatch):
    qs = questions.battery(False)
    answers = {qid: 0.1 for qid in qs if qid != "severity"}
    monkeypatch.setattr(jev, "ask_jev", lambda state, q, model: response(answers, 1.2, 0.7))
    result = jev.assess({"tool_call": {}}, False)
    assert result.nouls == answers and result.severity == 1.2 and result.severity_confidence == 0.7
    assert result.model == "jev-1.13.0" and result.severity_probabilities["1"] == 0.4


@pytest.mark.parametrize("fake", [
    lambda state, q, model: (_ for _ in ()).throw(TimeoutError("slow")),
    lambda state, q, model: response({}),                     # missing answers
    lambda state, q, model: response({qid: 1.7 for qid in questions.HAZARDS}),  # out of range
])
def test_assess_wraps_every_failure(monkeypatch, fake):
    monkeypatch.setattr(jev, "ask_jev", fake)
    with pytest.raises(jev.JevUnavailable):
        jev.assess({"tool_call": {}}, False)
