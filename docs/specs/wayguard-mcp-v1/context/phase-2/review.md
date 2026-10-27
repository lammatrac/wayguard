STATUS: DONE

Verified (in worktree): `uv run pytest` 157 passed; `ruff check` clean; `ruff format` applied; `mypy --strict src/` clean; `scripts/check_static_safety.py src` exit 0.
Covered: AC-001 (every listed class + one fixture per denylist entry), AC-002 (0666, escaping symlink, missing; owner-UID path covered by phase 1 tests), AC-015 minus doctor (init layout/modes, init refuse, --force backup, exit codes distinct, no network in validate), AC-020 minus line-cap stub (121 / 262145 / 9 / action>defaults).
Browser verification (claude-in-chrome): skipped explicitly - Python library/CLI, no browser-observable surface.
TDD followed: tests written first, RED observed (import error / AttributeError), then implementation.
Gate: no risk dimension rose; chose hand-written validator over `jsonschema` to avoid a new dependency (noted in contracts).
Not done / deferred: `doctor` (phase 7), 2,000-line truncation (phase 4), README sync of full policy docs (phase 7). Owner-mismatch via CLI not re-tested (needs another UID).
Merge: skipped, phases 3-7 pending.
