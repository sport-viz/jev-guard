"""Jev client wrapper: one request per screened tool call, every failure as JevUnavailable."""

import time
from dataclasses import dataclass, field

from jev_guard import config


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


def ask_jev(state: dict, questions: dict, model: str = config.MODEL):
    """Raw SDK call. Imported lazily so fast-path hook runs never pay the import cost."""
    from typesafe_sdk import RetryPolicy, TypeSafeClient

    retry = RetryPolicy(max_retries=config.JEV_MAX_RETRIES, backoff_initial=0.1,
                        backoff_max=config.JEV_BACKOFF_MAX_S,
                        timeout=config.JEV_TIMEOUT_S * (config.JEV_MAX_RETRIES + 1) + 1)
    with TypeSafeClient(timeout=config.JEV_TIMEOUT_S, retry=retry) as client:
        return client.system_one(state=state, questions=questions, model=model)


def parse(response, question_ids) -> Assessment:
    nouls = {qid: float(response.nouls[qid].noul) for qid in question_ids if qid != "severity"}
    sev = response.scores["severity"]
    if not all(0.0 <= p <= 1.0 for p in nouls.values()) or not 0.0 <= sev.score <= 3.0:
        raise ValueError(f"answer out of range: {nouls}, severity={sev.score}")
    return Assessment(nouls=nouls, severity=float(sev.score),
                      severity_confidence=float(sev.confidence),
                      severity_probabilities={k: float(v) for k, v in sev.probabilities.items()},
                      model=getattr(response, "model", "") or "")


def assess(state: dict, include_unrequested: bool, model: str = config.MODEL) -> Assessment:
    from jev_guard.questions import battery

    questions = battery(include_unrequested)
    started = time.monotonic()
    try:
        response = ask_jev(state, questions, model)
        assessment = parse(response, questions)
    except Exception as exc:  # SDK errors, timeouts, missing key, malformed answers
        raise JevUnavailable(f"{type(exc).__name__}: {exc}"[:300]) from exc
    assessment.latency_ms = int((time.monotonic() - started) * 1000)
    return assessment
