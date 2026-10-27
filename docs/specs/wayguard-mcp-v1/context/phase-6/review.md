STATUS: DONE

Verified: pytest 356 passed (15 new), ruff clean, `mypy --strict src/` clean, static safety check clean.
- AC-012 tools/list = exactly 5 tools, additionalProperties false at every object level; no alias in list_servers/get_policy_status/list_actions.
- AC-013 real subprocess (initialize, tools/list, get_policy_status, EOF shutdown): stdout only JSON-RPC, startup line on stderr. Subprocess overrides `cli.default_root` in-process because the root ignores $HOME by design.
- AC-017 no hot reload; policy_changed_since_load true after edit.
- AC-018 deny-all (invalid and missing policy); nothing spawned; propose_action works.
- AC-019 second concurrent call returns busy immediately, denied audit with concurrency_limit.
- AC-011 remainders: policy bytes unchanged after propose_action; proposed server/action still denied by run_action; mcp_server never references set_status.
- Cancellation: cancelling the handler task kills the child (pid gone), gate released, `cancelled` audited. Tested at service level (task cancel), not via a client-sent notifications/cancelled message.
- Browser verification skipped: stdio MCP server, no browser-observable surface.
Notes: `run_action.parameters` schema is built from enabled actions' parameter-name sets (anyOf) so additionalProperties:false holds at that level; value checks stay in the validator. SDK input validation is off (validate_input=False) so malformed run_action calls become audited `denied` results.
