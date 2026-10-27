# Evidence: policy v2 (shared parameters, templates, hosts, projects)

## Trigger

2026-10-27 esim debugging: `docker_logs_since window=1h container=nginx-proxy` produced
408,512 bytes, returned 65,536 (`truncated: true`, audit `9a202265...`). A `--since/--until`
slice action was needed, and adding it showed the real pain: every server block repeats
~30 actions and every enum/limit inside them.

## Code facts (WayContext project `wayguard`, re-resolve before editing)

- `src/wayguard/policy.py` — `parse_policy(data, path) -> Policy` is the only parser.
  `SCHEMA_VERSION = 1`. Helpers to reuse: `_parse_parameter`, `_parse_action`,
  `_check_executable`, `_check_keys`, `string_value_violation`, `_Errors`, `_safe_key`,
  `PLACEHOLDER_RE`, `ID_RE`, `ALIAS_RE`. Model: `Policy{defaults, servers, sha256, path,
  loaded_at}`, `Server{id, enabled, ssh_alias, description, actions}`, `Action{...}`,
  `ParameterSpec{...}` (all frozen).
- Consumers of the model only (no raw JSON): `mcp_server.py` (`_list_servers`,
  `_list_actions`, `_run_action`, `_propose_action`, `_parameters_schema`),
  `validation.py`, `ssh_runner.py`, `command.py` (`build_command`), `cli.py`
  (`_cmd_validate`, `_cmd_actions_list`), `doctor.py` (resolvable check per server alias).
- `cli.py` `SAMPLE_POLICY` is a hard-coded v1 document written by `init`.
- Tests with v1 fixtures: `tests/test_policy.py` (`good()`, `mutations()`, includes a
  `version2` rejection case that must flip), `tests/test_e2e_docker.py:69`,
  `tests/test_validation.py` (`make_policy`), `tests/test_mcp_server.py`, `tests/test_cli*.py`.
- Docs: `README.md` §2.4 Policy format, §3.6 first action example, §1.5 change-control
  checklist; `examples/policy.starter.json` (v1, 33 actions, one server).
- Hard ceilings: `config.MAX_STREAM_BYTES = 256 KiB`, `MAX_STREAM_LINES = 2000`,
  `MAX_TIMEOUT_SECONDS = 120`, `MAX_CONCURRENCY = 8`.

## Fallbacks

- Used `grep`/`sed` on README.md, examples JSON and audit.jsonl: non-indexed file types.
