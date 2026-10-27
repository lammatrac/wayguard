# Phase 2 plan

Gate re-score (after Locate): Rev 0 / Sec 2 / Con 0 / Blast 2 / Infra 0 (hand-written structural validator, no new dependency; spec suggested `jsonschema` but custom code gives path-named errors and avoids a lock change) / Amb 1. No dimension rose; proceed.

Files (inside worktree):
- `src/wayguard/policy.py` (new): loader, validator, denylist, frozen model, `PolicyInvalidError`, `string_value_violation`, `policy_changed_since_load`.
- `src/wayguard/cli.py`: exit codes, `init`, `policy validate`, `actions list`; main returns int.
- `src/wayguard/__main__.py`: `sys.exit(main())`.
- `tests/test_policy.py`, `tests/test_cli.py`: TDD.
- `README.md`: exit code table.
Contracts: see contracts.md "Phase 2".
