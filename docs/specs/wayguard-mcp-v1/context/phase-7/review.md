STATUS: DONE

Verified (in worktree .worktrees/wayguard-mcp-v1): `uv run pytest` 364 passed (7 e2e deselected); `uv run pytest -m e2e` 7 passed against a real Docker sshd (ok with 5 lines, host_key_error, auth_error, unknown_alias, unreachable phrases, unknown action denied + proposable, policy bytes unchanged); ruff clean; `mypy --strict src/` clean; static safety check clean. Container and image confirmed removed after runs. Real ~/.ssh and ~/.config/wayguard never touched (temp -F config, temp known_hosts, throwaway keys, temp root, 127.0.0.1 binding, no StrictHostKeyChecking relaxation).
TDD: doctor tests written first (import error RED, then GREEN). E2E and README are verification/docs; e2e assertions passed on first run, and phrase assertion was tightened afterwards.
Browser check: skipped, no browser-observable surface (CLI + stdio MCP).
Not verified: macOS e2e; live Codex/Gemini/Cursor/Claude Code client configs; CI e2e job (cannot run GitHub Actions locally).
README synced (exit codes, CLI, deny-all, status fields, statuses, ceilings, minimum>=0, server description, Codex key, client-config caveat).
