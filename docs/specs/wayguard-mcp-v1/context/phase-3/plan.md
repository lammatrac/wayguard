# Phase 3 plan

Gate re-score (after Locate): Rev 0 / Sec 2 / Con 0 / Blast 1 / Infra 0 / Amb 1 — no dimension above manifest. Proceed.

Files (all in worktree):
- `src/wayguard/validation.py` (new): denial reason codes, `RequestDenied`, `ValidatedRequest`, `validate_request`, `AuditSink` Protocol, `normalize_params`, `authorize_request` (validate + record denied).
- `src/wayguard/command.py` (new): `TRUSTED_SSH_PATHS`, `discover_ssh(_candidates)`, `child_env`, `build_remote_command`, `build_argv`, `build_command` -> `BuiltCommand`. No process spawning.
- `tests/test_validation.py`, `tests/test_command.py` (new), written first (TDD).
- `contracts.md`: append "### Phase 3", mark pending items RESOLVED.

Contracts produced: see contracts.md Phase 3.
