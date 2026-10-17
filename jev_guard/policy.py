"""Turns Jev's raw assessment into a decision. Jev supplies probabilities; this owns policy.

Thresholds are starting values until evals/run_eval.py tunes them on labeled cases.
"""

from dataclasses import dataclass, field

# What a high-probability hazard may escalate to. "ask" hazards deny only when the action
# is also clearly unrequested (see route()).
HAZARD_ACTION = {
    "data_loss": "deny",
    "external_effect": "ask",
    "system_change": "ask",
    "secrets": "deny",
    "security_weakening": "deny",
    "obfuscated": "deny",
    "unrequested": "ask",
}

POLICIES = {
    "default": {
        "ask_at": 0.40,               # hazard probability that earns a prompt
        "act_at": 0.85,               # hazard probability that triggers its HAZARD_ACTION
        "deny_severity": 2.0,         # a deny-hazard only denies at or above this severity
        "ask_severity": 1.6,          # severity alone that earns a prompt
        "always_deny_severity": 2.7,  # severity alone that denies
        "uncertain_confidence": 0.35, # below this Score confidence, severity >= 1 asks
        # Scope is fuzzy when requests are high level ("continue with the plan"), so
        # `unrequested` only counts once the action itself is more than easily reversible.
        "unrequested_min_severity": 1.5,
    },
}
DEFAULT_POLICY = "default"
PRECEDENCE = ("deny", "ask", "pass")


@dataclass
class Verdict:
    action: str  # "deny" | "ask" | "pass"
    fired: list[tuple[str, float]] = field(default_factory=list)


def route(nouls: dict[str, float], severity: float, severity_confidence: float,
          policy: dict | None = None) -> Verdict:
    p = policy or POLICIES[DEFAULT_POLICY]
    denies: list[tuple[str, float]] = []
    asks: list[tuple[str, float]] = []

    # A significant action the user clearly didn't ask for: any confident hazard escalates.
    unrequested = nouls.get("unrequested", 0.0) >= p["act_at"] and severity >= p["deny_severity"]

    for hazard, prob in nouls.items():
        if hazard == "unrequested" and severity < p["unrequested_min_severity"]:
            continue
        if prob >= p["act_at"]:
            wants_deny = HAZARD_ACTION.get(hazard, "ask") == "deny" or (unrequested and hazard != "unrequested")
            (denies if wants_deny and severity >= p["deny_severity"] else asks).append((hazard, prob))
        elif prob >= p["ask_at"]:
            asks.append((hazard, prob))

    if severity >= p["always_deny_severity"]:
        denies.append(("severity", severity))
    elif severity >= p["ask_severity"]:
        asks.append(("severity", severity))
    elif severity >= 1.0 and severity_confidence < p["uncertain_confidence"]:
        asks.append(("severity_uncertain", severity))

    # Hazards by probability, then severity (a 0-3 scale, so it can't share the sort).
    def order(kv):
        return (kv[0].startswith("severity"), -kv[1])

    if denies:
        return Verdict("deny", sorted(denies + asks, key=order))
    if asks:
        return Verdict("ask", sorted(asks, key=order))
    return Verdict("pass")


SEVERITY_WORDS = ["routine", "easily reversible", "hard to undo", "serious and irreversible"]


def describe_severity(severity: float) -> str:
    return SEVERITY_WORDS[min(3, max(0, round(severity)))]


def format_signals(fired: list[tuple[str, float]], severity: float) -> str:
    parts = [f"{name} {value:.2f}" for name, value in fired if not name.startswith("severity")]
    parts.append(f"severity {severity:.1f} ({describe_severity(severity)})")
    return " · ".join(parts)
