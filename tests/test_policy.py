import pytest

from jev_guard import policy

QUIET = {h: 0.02 for h in policy.HAZARD_ACTION}


def nouls(**overrides):
    return {**QUIET, **overrides}


@pytest.mark.parametrize("hazards,severity,confidence,expected", [
    ({}, 0.1, 0.9, "pass"),
    ({"data_loss": 0.92}, 2.3, 0.8, "deny"),          # deny hazard + high severity
    ({"data_loss": 0.92}, 1.2, 0.8, "ask"),           # deny hazard, but low severity
    ({"secrets": 0.90}, 2.1, 0.7, "deny"),
    ({"external_effect": 0.97}, 2.4, 0.8, "ask"),     # ask hazards never deny on their own
    ({"unrequested": 0.99}, 0.5, 0.9, "pass"),        # out of scope but easily reversible
    ({"unrequested": 0.60}, 1.5, 0.9, "ask"),         # out of scope and not trivial
    ({"system_change": 0.50}, 0.8, 0.9, "ask"),       # near 0.5 means unsure: ask
    ({"obfuscated": 0.39}, 0.3, 0.9, "pass"),         # just below ask_at
    ({}, 2.8, 0.9, "deny"),                           # severity alone denies
    ({}, 1.7, 0.9, "ask"),                            # severity alone asks
    ({}, 1.2, 0.2, "ask"),                            # unsure and not trivial
    ({}, 1.2, 0.8, "pass"),
    ({}, 0.6, 0.1, "pass"),                           # unsure but trivial
    # A confident ask-hazard escalates to deny when the action is also clearly unrequested.
    ({"external_effect": 0.95, "unrequested": 0.90}, 2.3, 0.8, "deny"),
    ({"external_effect": 0.95, "unrequested": 0.90}, 1.8, 0.8, "ask"),   # not severe enough
    ({"external_effect": 0.95, "unrequested": 0.60}, 2.3, 0.8, "ask"),   # not clearly unrequested
    ({"unrequested": 0.95}, 2.3, 0.8, "ask"),                            # never denies on its own
])
def test_route(hazards, severity, confidence, expected):
    assert policy.route(nouls(**hazards), severity, confidence).action == expected


def test_fired_signals_are_sorted_and_include_asks_on_deny():
    verdict = policy.route(nouls(data_loss=0.91, unrequested=0.6), 2.2, 0.8)
    assert verdict.action == "deny"
    assert [name for name, _ in verdict.fired] == ["data_loss", "unrequested", "severity"]


def test_custom_policy_changes_decision_not_inputs():
    strict = {**policy.POLICIES["default"], "ask_at": 0.2}
    assert policy.route(nouls(system_change=0.3), 0.5, 0.9).action == "pass"
    assert policy.route(nouls(system_change=0.3), 0.5, 0.9, strict).action == "ask"


def test_format_signals():
    text = policy.format_signals([("data_loss", 0.912), ("severity", 2.4)], 2.4)
    assert text == "data_loss 0.91 · severity 2.4 (hard to undo)"
