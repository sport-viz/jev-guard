"""Jev client wrapper. Phase 1 stub: the live call lands in phase 2."""

from dataclasses import dataclass, field


class JevUnavailable(Exception):
    """Any reason we couldn't get a usable assessment; the hook turns this into "ask"."""


@dataclass
class Assessment:
    nouls: dict[str, float]
    severity: float
    severity_confidence: float
    severity_probabilities: dict[str, float] = field(default_factory=dict)
    model: str = ""
    latency_ms: int = 0


def assess(state: dict, include_unrequested: bool) -> Assessment:
    raise JevUnavailable("Jev client not implemented yet")
