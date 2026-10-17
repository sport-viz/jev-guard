"""Review Jev Guard's audit log, replay it under the current policy, and harvest eval cases.

    python scripts/review_log.py                      # summary + every ask/deny
    python scripts/review_log.py --since 2026-10-16   # only entries from that date on
    python scripts/review_log.py --replay             # what the *current* policy would decide
    python scripts/review_log.py --export 12 --expected deny   # log line 12 → evals/cases.jsonl

Replay re-routes logged Jev answers through policy.route() without new API calls, so a
threshold change can be checked against real traffic before installing it. It keeps each
entry's logged rule outcome; changes to the code rules show up in tests and evals instead.
"""

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from jev_guard import config, policy  # noqa: E402

RANK = {"pass": 0, "ask": 1, "deny": 2}


def load(path: Path, since: str | None = None) -> list[tuple[int, dict]]:
    entries = []
    if not path.exists():
        return entries
    for number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if since is None or entry.get("ts", "") >= since:
            entries.append((number, entry))
    return entries


def replay(entry: dict) -> str:
    """The decision the current policy would make for a logged entry."""
    if entry.get("stage") in {"hard_rule", "jev_unavailable", "error"} or "nouls" not in entry:
        return entry["decision"]
    verdict = policy.route(entry["nouls"], entry["severity"], entry.get("severity_confidence", 1.0))
    return max(entry.get("rule_action", "pass"), verdict.action, key=RANK.__getitem__)


def percentile(values: list[float], pct: int) -> float:
    if len(values) < 2:
        return values[0] if values else 0.0
    return statistics.quantiles(values, n=100)[pct - 1]


def summarize(entries: list[tuple[int, dict]]) -> list[str]:
    rows = [e for _, e in entries]
    lines = [f"{len(rows)} screened calls (fast-path calls aren't logged)"]
    lines.append("decisions: " + ", ".join(f"{k} {v}" for k, v in Counter(e["decision"] for e in rows).most_common()))
    lines.append("stages:    " + ", ".join(f"{k} {v}" for k, v in Counter(e["stage"] for e in rows).most_common()))
    lines.append("tools:     " + ", ".join(f"{k} {v}" for k, v in Counter(e["tool"] for e in rows).most_common(8)))
    jev = [e["jev_latency_ms"] for e in rows if "jev_latency_ms" in e]
    total = [e["total_ms"] for e in rows if "total_ms" in e]
    if jev:
        lines.append(f"latency:   jev p50 {statistics.median(jev):.0f} ms / p95 {percentile(jev, 95):.0f} ms · "
                     f"hook p50 {statistics.median(total):.0f} ms / p95 {percentile(total, 95):.0f} ms")
    models = Counter(e["model"] for e in rows if e.get("model"))
    if models:
        lines.append("models:    " + ", ".join(f"{k} {v}" for k, v in models.items()))
    return lines


def target(entry: dict) -> str:
    tool_input = entry.get("input") or {}
    text = tool_input.get("command") or tool_input.get("file_path") or json.dumps(tool_input)
    return f"{entry['stage']:15} {entry['tool']:10} {' '.join(str(text).split())[:90]}"


def describe(number: int, entry: dict) -> str:
    return f"#{number:<5} {entry['decision']:4} {target(entry)}\n         {entry.get('reason', '')}"


def to_case(number: int, entry: dict, expected: str) -> dict:
    case = {"name": f"log_{entry.get('input_hash', number)}", "category": "from-log",
            "tool_name": entry["tool"], "tool_input": entry.get("input") or {}, "expected": expected}
    if entry.get("user_request"):
        case["user_request"] = entry["user_request"]
    return case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--log", type=Path, default=config.audit_log_path())
    parser.add_argument("--since", help="ISO date or timestamp prefix, e.g. 2026-10-16")
    parser.add_argument("--replay", action="store_true", help="show entries the current policy decides differently")
    parser.add_argument("--export", type=int, metavar="LINE", help="append this log line to evals/cases.jsonl")
    parser.add_argument("--expected", choices=["pass", "ask", "deny"], help="label for --export")
    args = parser.parse_args()

    entries = load(args.log, args.since)
    if args.export:
        if not args.expected:
            parser.error("--export needs --expected")
        match = [e for n, e in entries if n == args.export]
        if not match:
            parser.error(f"no log line {args.export}")
        case = to_case(args.export, match[0], args.expected)
        with open(REPO / "evals" / "cases.jsonl", "a") as f:
            f.write(json.dumps(case) + "\n")
        print(f"Added {case['name']} (expected {args.expected}) to evals/cases.jsonl")
        return 0

    print("\n".join(summarize(entries)))
    if args.replay:
        changed = [(n, e, replay(e)) for n, e in entries if replay(e) != e["decision"]]
        print(f"\ncurrent policy changes {len(changed)} decision(s):")
        for n, e, new in changed:
            print(f"  #{n:<5} {e['decision']:4} → {new:4} {target(e)}")
    else:
        flagged = [(n, e) for n, e in entries if e["decision"] != "pass"]
        print(f"\n{len(flagged)} ask/deny:")
        for n, e in flagged:
            print(describe(n, e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
