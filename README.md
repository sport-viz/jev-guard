# Jev Guard

A Claude Code `PreToolUse` hook that screens every tool call with
[Jev](https://typesafe.ai) (TypeSafe's System One model) before it runs. Dangerous calls are
denied, borderline ones force a permission prompt (even in auto mode), and everything else
passes through untouched.

The guard only adds barriers. A safe verdict is "no opinion", so your normal permission rules
and the auto-mode classifier still apply.

## How it works

```
tool call → mode → hard rules → fast path → Jev → policy → audit log
```

1. **Mode**: `JEV_GUARD_MODE` (`enforce` | `shadow` | `off`), read from the environment only.
2. **Hard rules** (code, no network):
   - *deny* for catastrophes (e.g. `rm -rf ~`), skipping Jev;
   - *ask* floors for guard self-protection, dotfile writes and writes outside the project's
     parent directory. Jev still runs and may raise these to deny, never lower them.
3. **Fast path**: known harmless calls skip Jev.
4. **Jev**: one request asks a battery of yes/no hazard questions (data loss, external effect,
   system change, secrets, security weakening, obfuscation, unrequested action) plus a severity
   score. The state is small: truncated tool input, the last user prompts, and facts that code
   knows exactly (path existence, git tracking).
5. **Policy**: named, tunable thresholds in `policy.py` turn probabilities into
   `deny`, `ask` or no opinion.
6. **Audit**: each decision is appended as JSONL, with raw probabilities, to
   `~/.claude/jev-guard/decisions.jsonl`.

If Jev is unreachable (error, timeout, rate limit, bad response) the guard fails to **ask**.
The hook always exits 0.

See [`PLAN.md`](PLAN.md) for the design rationale, verified platform facts and decisions.

## Requirements

- Python 3.10+ and [uv](https://docs.astral.sh/uv/)
- A TypeSafe API key in `TYPESAFE_API_KEY`
- Claude Code (2.1.295+ for `onFailure: "block"`)

Screening costs roughly $0.00003 per call at about 800 tokens.

## Install

```sh
uv sync                                   # create .venv
scripts/install.sh                        # run tests, copy to ~/.claude/jev-guard, smoke test
.venv/bin/python scripts/configure_settings.py --dry-run   # preview the settings change
.venv/bin/python scripts/configure_settings.py             # add the hook to ~/.claude/settings.json
```

The installed copy under `~/.claude/jev-guard` (override with `JEV_GUARD_HOME`) is what the
hook actually runs. Repo edits take effect only after re-running `scripts/install.sh`.

To remove the hook: `.venv/bin/python scripts/configure_settings.py --remove`.

## Configuration

| Setting | Where | Purpose |
| --- | --- | --- |
| `JEV_GUARD_MODE` | environment | `enforce` (default) applies decisions; `shadow` logs what it would do and returns no opinion; `off` exits immediately |
| `JEV_GUARD_HOME` | environment | install and log location (default `~/.claude/jev-guard`) |
| `TYPESAFE_API_KEY` | environment | credentials for the TypeSafe API |
| `MODEL`, timeouts | `jev_guard/config.py` | model is pinned (`jev-1.13.0`) because thresholds are tuned against one version |
| thresholds | `jev_guard/policy.py` | `ask_at`, `act_at`, severity cutoffs, etc. |

The mode is deliberately environment-only, so Claude cannot switch the guard off through Bash.
Starting with `shadow` is a good way to see how it behaves on your real traffic.

## Development

```sh
.venv/bin/python -m pytest -q                              # unit tests (no network)
.venv/bin/python evals/run_eval.py                         # labeled cases, cached Jev answers
.venv/bin/python evals/run_eval.py --model jev-1.14.0      # compare another model
.venv/bin/python evals/run_eval.py --set ask_at=0.5        # re-route cached answers under new thresholds
.venv/bin/python evals/run_eval.py --show inject_          # full signals for matching cases
.venv/bin/python scripts/review_log.py [--since DATE] [--replay]   # review the audit log
```

- Changing question wording or thresholds: re-run the evals. The cache in `evals/cache.json`
  is keyed by model, state and question wording, so new wording makes fresh API calls.
- Evals run in a synthetic environment (`HOME=/home/dev`, project `/home/dev/projects/webapp`),
  so results do not depend on your machine. Cases live in `evals/cases.jsonl`.
- Hazard names in `questions.HAZARDS` and `policy.HAZARD_ACTION` must stay in sync.
- `scripts/review_log.py` can replay logged decisions under the current policy and export
  entries to `evals/cases.jsonl`.

## Layout

```
jev_guard/
  hook.py       pipeline entry point (evaluate())
  rules.py      code-side deny / ask / fast-path rules
  shell.py      conservative shell splitter (unparseable → send to Jev)
  context.py    builds the small state Jev sees
  questions.py  hazard questions and severity score
  jev.py        SDK wrapper (every failure → JevUnavailable → ask)
  policy.py     thresholds and routing
  audit.py      JSONL decision log
  config.py     mode, model, budgets, paths
evals/          labeled cases and runner
scripts/        install.sh, configure_settings.py, review_log.py
tests/          unit tests
```
