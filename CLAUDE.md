# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Jev Guard is a Claude Code `PreToolUse` hook. It screens each tool call with Jev (TypeSafe's System One model, via `typesafe-sdk`) before the call runs. It returns `deny`, `ask`, or no opinion. `PLAN.md` holds the design rationale, the verified platform facts and the decisions already made. Read it before changing behavior.

## Commands

Use the uv-managed venv at `.venv`.

```
.venv/bin/python -m pytest -q                    # unit tests (no network)
.venv/bin/python -m pytest tests/test_rules.py -k name   # a single test
.venv/bin/python evals/run_eval.py               # labeled cases through the full pipeline, cached Jev answers
.venv/bin/python evals/run_eval.py --model jev-1.14.0    # compare another model
.venv/bin/python evals/run_eval.py --set ask_at=0.5      # re-route cached answers under a changed threshold
.venv/bin/python evals/run_eval.py --show inject_        # full signals for matching cases
.venv/bin/python scripts/review_log.py [--since DATE] [--replay]   # review the audit log
scripts/install.sh                               # run tests, copy to ~/.claude/jev-guard, smoke test
.venv/bin/python scripts/configure_settings.py [--dry-run|--remove]  # add or remove the hook in ~/.claude/settings.json
```

## Architecture

The pipeline is in `jev_guard/hook.py` (`evaluate()`): mode → hard rules → fast path → Jev → policy → audit. It always exits 0.

- `rules.py` and `shell.py` hold the code-side rules, which run before Jev. `shell.py` is a deliberately conservative shell splitter. Anything it can't parse is treated as "send to Jev", never as safe. `rules.check()` returns one of:
  - **deny**: a catastrophe; Jev is skipped.
  - **ask**: a floor; Jev still runs and may raise it to deny, never lower it. Covers guard self-protection, dotfile writes and writes outside the project's parent directory.
  - **pass with fast_path**: known harmless; Jev is skipped.
  - **pass without fast_path**: Jev decides.
- `context.py` builds the small state Jev sees: truncated tool input, the last user prompts read from the transcript, and facts code knows exactly (path existence, git tracking). Keep it small, because large state lowers Jev accuracy.
- `questions.py` defines the battery: one Noul per hazard plus a severity Score, all in one request. Each question names the state fields it judges and tells Jev to judge effects, not claims in the text.
- `jev.py` wraps the SDK. Every failure becomes `JevUnavailable`, and the hook turns that into `ask` (fail to ask).
- `policy.py` turns raw probabilities into a decision using named, tunable thresholds. Jev supplies probabilities and code owns policy. Hazard names in `questions.HAZARDS` and `policy.HAZARD_ACTION` must stay in sync.
- `audit.py` appends a JSONL record per decision, with raw probabilities, under `~/.claude/jev-guard/`. `scripts/review_log.py` can replay these under the current policy and export entries to `evals/cases.jsonl`.

## Things to keep in mind

- **The guard only adds barriers.** A safe verdict is "no opinion", so normal permission rules still apply.
- **`JEV_GUARD_MODE`** (`enforce` | `shadow` | `off`) is read from the environment only, so Claude can't switch it off through Bash. Don't add a file-based or Bash-reachable toggle.
- **The model is pinned** (`config.MODEL`). Thresholds are tuned against one version, so re-run evals before bumping it.
- **Changing question wording or thresholds:** re-run `evals/run_eval.py`. The cache in `evals/cache.json` is keyed by model, state and question wording, so changed wording makes fresh API calls.
- **Evals** run in a synthetic environment (HOME=/home/dev, project /home/dev/projects/webapp), so results don't depend on this machine. Cases are in `evals/cases.jsonl`.
- **The installed copy** under `~/.claude/jev-guard` (override with `JEV_GUARD_HOME`) is what the hook actually runs. Repo edits take effect only after `scripts/install.sh`.
