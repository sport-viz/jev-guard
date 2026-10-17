"""Append-only JSONL record of every screened call. Never raises: logging must not block."""

import hashlib
import json
import time

from jev_guard import config


def input_hash(tool_name: str, tool_input: dict) -> str:
    blob = json.dumps({"tool": tool_name, "input": tool_input}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def record(entry: dict) -> None:
    try:
        path = config.audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}, default=str)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
