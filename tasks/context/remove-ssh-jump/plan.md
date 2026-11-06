# Remove ssh_jump: plan

Evidence: `tasks/context/remove-ssh-jump/evidence.md`

1. Back up the live policy (mode 0600), then remove the 19 `"ssh_jump"` lines from
   `~/.config/wayguard/policy.json` textually (keeps formatting). Verify the parsed JSON
   equals the original minus `ssh_jump`, the mode is still 0600, and it validates under the
   current code.
2. `git revert --no-commit 8d96d03` (code, tests, README).
3. Gate: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src`.
4. Live check: `wayguard-mcp doctor`, a policy that still sets `ssh_jump` is rejected, and
   WayGuard `get_policy_status` reports the live policy as valid.
