STATUS: DONE

Verified (worktree): `uv run pytest` 245 passed (96 new across tests/test_validation.py, tests/test_command.py); `ruff check` and `ruff format --check` clean; `mypy --strict src/` clean; `scripts/check_static_safety.py src` exit 0.
Covered: AC-003 (all 11 listed request denials plus non-object/missing-id/policy-invalid, each with one `denied` audit record via in-memory FakeSink, no process spawned - none can be, module has no subprocess), AC-004 (golden serialized remote commands + `shlex.split` round-trip for shell metachars; `-rf`/`--help`/`../x`/`\n`/`\0` rejected; option injection tested separately incl. build-time recheck and unsafe ssh alias), AC-005 (exact 25-element golden argv; ConnectTimeout=min(10,timeout); discovery ignores PATH and env var even with a fake ssh first on PATH).
TDD: tests written first; RED observed (ImportError) for both modules, then GREEN.
Browser verification (claude-in-chrome): skipped explicitly - pure library, no browser-observable surface.
Gate: no dimension rose above manifest (Sec 2 as scored).
Not done / deferred: process spawning and real `AuditSink` (phases 4-5); wiring into MCP tool (6). Known limitation noted in contracts (negative integer minimum can make option-like arg; policy-controlled).
Merge: skipped, phases 4-7 pending.
