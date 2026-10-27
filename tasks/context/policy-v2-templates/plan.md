# Policy Schema v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the v1 `servers` policy with v2 (shared parameters, templates, hosts,
projects, variables) that expands at load time into the unchanged `Policy`/`Server`/`Action`
model, and ship a v2 starter template.

**Architecture:** All new parsing lives in `src/wayguard/policy.py`. Each template or inline
action is first *resolved* into a plain v1-shaped action dict (shared parameter references
inlined, `"$var"` enum values replaced by lists, `${var}` substituted in args), then handed
to the existing `_parse_action`, so every v1 check runs on the expanded result. Each project
becomes one `Server` keyed by project id; nothing downstream of `parse_policy` changes.

**Tech Stack:** Python 3.12, pytest, ruff, mypy (`uv run ...`).

**Spec:** `tasks/context/policy-v2-templates/spec.md` · evidence: `tasks/context/policy-v2-templates/evidence.md`

## Global Constraints

- `version` must be exactly `2`; v1 is rejected with `version: must be 2`. No migrate command.
- MCP tool names, arguments, result shapes, audit, proposals, runner, `command.py`: unchanged. `mcp_server.SCHEMA_VERSION` (status output schema) stays `1`.
- Errors: `"<json.path>: <fixed reason>"`, keys via `_safe_key`, never policy values, max 50.
- Ids: template/host/project/action/shared-parameter keys use `ID_RE`; action-local parameter names and variable names use `PARAM_NAME_RE`.
- Variable values: string or list of 1–64 strings; each string passes `string_value_violation(v, MAX_STRING_LENGTH)`.
- `{name}` = agent parameter, whole argument only. `${var}` = string variable, anywhere inside an `args` element, never in `executable` or `description`. `"$var"` = list variable, only as an enum's `values`.
- Action `timeout_seconds` / `max_output_bytes` may exceed `defaults`, up to `config.MAX_TIMEOUT_SECONDS` / `config.MAX_STREAM_BYTES`.
- `MAX_ACTIONS_PER_PROJECT = 200`.
- Commits: `git commit -m "$(git config user.name) - <type>: <sentence>"`, stage with `git add -u` plus new files by path, **no Co-Authored-By or any AI attribution**. After each commit run WayContext `index_project` for project `wayguard`.
- Run before each commit: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src`.

## Review Focus

1. A variable value that itself contains `${x}` or `{x}`: not expanded recursively; rejected by the post-substitution stray-brace check. (Task 5 `test_var_value_with_braces_rejected`)
2. A project var with the same name as a host var used by a *host* action: host action keeps the host value. (Task 5 `test_host_actions_ignore_project_vars`)
3. Same template in both host `use` and project `use`: collision error, not a silent duplicate. (Task 4 `test_template_in_host_and_project_collides`)
4. A disabled project with a broken action still fails the whole load (v1 validated disabled servers too). (Task 2 `test_disabled_project_still_validated`)
5. A project `disable`-ing a host action: allowed, removes it for that project only. (Task 2 `test_disable_host_action_per_project`)

---

### Task 1: Action limits may exceed defaults, up to the hard ceilings

**Files:**
- Modify: `src/wayguard/policy.py` (`_action_limit`)
- Test: `tests/test_policy.py`

**Interfaces:**
- Produces: `_action_limit(raw, key, defaults, path, errs) -> int | None` — checks against `config.MAX_TIMEOUT_SECONDS` for `timeout_seconds` and `config.MAX_STREAM_BYTES` for `max_output_bytes`; error reason `exceeds limit <N>`; absent → default.

- [ ] **Step 1: Write failing tests** (still on the v1 fixture)

```python
def test_action_cap_above_default_within_ceiling() -> None:
    d = good()
    action(d).update(max_output_bytes=262144, timeout_seconds=120)
    a = parse_policy(dump(d)).servers["prod"].actions["tail"]
    assert a.max_output_bytes == 262144 and a.timeout_seconds == 120

@pytest.mark.parametrize("key,val", [("max_output_bytes", 262145), ("timeout_seconds", 121)])
def test_action_cap_above_ceiling_rejected(key: str, val: int) -> None:
    d = good(); action(d)[key] = val
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any("exceeds limit" in x for x in e.value.errors)
```
Remove any existing mutation case that expects an action value above `defaults` to be rejected ("exceeds policy defaults").

- [ ] **Step 2:** `uv run pytest tests/test_policy.py -q` → the new tests FAIL.
- [ ] **Step 3:** Change `_action_limit` as in Interfaces.
- [ ] **Step 4:** Full check command → PASS.
- [ ] **Step 5:** Commit `feat: allow per-action timeout and output caps above defaults up to hard ceilings`.

---

### Task 2: v2 top level — hosts and projects with inline actions

Switching `version` breaks every fixture at once, so the fixture conversion is part of this task.

**Files:**
- Modify: `src/wayguard/policy.py` (`SCHEMA_VERSION = 2`, replace `_parse_server`, `parse_policy`)
- Modify: `src/wayguard/cli.py` (`SAMPLE_POLICY`, `_cmd_validate` message)
- Modify tests: `tests/test_policy.py` (`good`, `action`, `mutations`, new helper), `tests/test_validation.py` (`make_policy`), `tests/test_mcp_server.py` (lines ~114, ~204), `tests/test_cli.py` (lines ~56, ~80, ~100), `tests/test_e2e_docker.py` (`_policy`), any other `["servers"]` dict use.

**Interfaces:**
- Produces in `policy.py`:
  - `MAX_ACTIONS_PER_PROJECT = 200`
  - `@dataclass(frozen=True) class _Host: id: str; ssh_alias: str; description: str | None; use: tuple[str, ...]; vars: Mapping[str, str | tuple[str, ...]]; actions: Mapping[str, Any]` (raw action dicts; `use`/`vars` filled by Tasks 4/5, empty here)
  - `_parse_host(hid: str, raw: object, errs: _Errors) -> _Host | None`
  - `_expand_project(pid: str, raw: object, hosts: Mapping[str, _Host], ctx: _Ctx, errs: _Errors) -> Server | None`
  - `@dataclass(frozen=True) class _Ctx: defaults: Defaults | None; shared: Mapping[str, Any]; templates: Mapping[str, Mapping[str, Any]]` (shared/templates empty until Tasks 3/4)
  - `_resolve_action(raw: object, scope: Mapping[str, str | tuple[str, ...]], ctx: _Ctx, path: str, errs: _Errors) -> object` — identity in this task; Tasks 3 and 5 extend it. Its output goes to `_parse_action`.
  - Extract `_check_alias(alias, path, errs)` and `_check_short_description(desc, path, errs)` from the old `_parse_server`.
- Produces in `tests/test_policy.py`: `good()` (v2: host `prod-host` alias `prod-debug`; project `prod` enabled, description `Production`, actions `tail` and `unit` as today), `action(d)` → `d["projects"]["prod"]["actions"]["tail"]`, and
  `add_server(d, sid, *, enabled, ssh_alias, actions, description=None) -> None` that adds host `f"{sid}-host"` and project `sid` — the mechanical replacement for every `d["servers"][sid] = {...}`.

Key rules: top-level keys `{version, defaults, hosts, projects}` required, `{parameters, templates}` optional. Host keys: required `ssh_alias`; optional `description`, `use`, `vars`, `actions`. Project keys: required `enabled`, `host`; optional `description`, `use`, `vars`, `actions`, `disable`. Project action order: host actions, then project actions; a second definition of an id → error at the second source, reason `duplicate action id (also defined in <first source path>)` (source paths are policy key paths, safe). `disable` must be a list of strings; an id the project would not have → `disable: unknown action '<safe id>'`. More than 200 → `projects.<p>: too many actions (max 200)`. Each action's error path is its source path: `hosts.<h>.actions.<a>` or `projects.<p>.actions.<a>`. Host actions are resolved and parsed once per project on that host (scope can differ per project from Task 5 on), so a broken host action may be reported once per project; the 50-error cap bounds this.

- [ ] **Step 1: Write failing tests** in `tests/test_policy.py`:
  - `test_valid_policy_builds_model` rewritten for v2 (same assertions; `servers["prod"]` is the project).
  - `test_two_projects_share_host`: host with action `disk`, projects `a`, `b` → both `Server`s have `ssh_alias == "prod-debug"` and action `disk`; no `Server` keyed by the host id.
  - `test_disabled_project_still_validated`: disabled project with `executable: "/bin/bash"` → `PolicyInvalidError`.
  - `test_disable_host_action_per_project`: project `a` disables `disk` → absent in `a`, present in `b`.
  - mutation cases (each must raise): `version1`, `missing_hosts`, `missing_projects`, `servers_present`, `unknown_host_field`, `unknown_project_field`, `unknown_host_ref`, `host_alias_dash`, `project_enabled_not_bool`, `dup_id_host_vs_project`, `disable_unknown`, `disable_not_list`, `too_many_actions` (201 inline copies).
  - Remove the old `version2` rejection case.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement per Interfaces. Delete `_parse_server`.
- [ ] **Step 4:** Convert the other test fixtures with `add_server`; e2e `_policy` builds one host per alias and one project per sid. `SAMPLE_POLICY` → `"version": 2`, same defaults, `"hosts": {}`, `"projects": {}`; tests asserting `["servers"] == {}` assert `["projects"] == {}`; the CLI test writing `version = 2` to make an invalid file now writes `version = 1`. `_cmd_validate` prints `policy valid: {P} project(s) on {H} host(s), {N} action(s)`, where `H = len({s.ssh_alias for s in pol.servers.values()})` (the `Policy` model gets no new field).
- [ ] **Step 5:** Full check → PASS (including `tests/test_mcp_server.py`, `tests/test_doctor.py`).
- [ ] **Step 6:** Commit `feat: replace policy servers with v2 hosts and projects`.

---

### Task 3: Shared parameters

**Files:** Modify `src/wayguard/policy.py`; Test `tests/test_policy.py`

**Interfaces:**
- Consumes: `_Ctx`, `_resolve_action` (Task 2).
- Produces: `_parse_shared_parameters(raw: object, errs: _Errors) -> dict[str, Any]` (validated raw dicts keyed by `ID_RE` id). Validation reuses `_parse_parameter(name="x", ...)` for literal specs; a spec whose `values` is a string is checked only for shape `^\$[A-Za-z_][A-Za-z0-9_]{0,63}$` here (resolved per use in Task 5). `_resolve_action` replaces a string parameter value with a deep copy of `ctx.shared[ref]`; unknown ref → `<action path>.parameters.<p>: unknown shared parameter '<safe ref>'`.

- [ ] **Step 1: Failing tests:** `test_shared_parameter_reference_inlined` (two actions referencing `lines` get equal `ParameterSpec` with name = local key; local key may differ from shared key); mutations `shared_param_unknown_ref`, `shared_param_invalid_spec` (integer min > max), `shared_param_bad_id`, `shared_param_forbidden_type` (`raw`). Unused shared parameter is accepted.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Full check → PASS.
- [ ] **Step 5:** Commit `feat: add shared parameter definitions to policy v2`.

---

### Task 4: Templates and `use`

**Files:** Modify `src/wayguard/policy.py`; Test `tests/test_policy.py`

**Interfaces:**
- Produces: `_parse_templates(raw: object, errs: _Errors) -> dict[str, Mapping[str, Any]]` (template id → raw actions; template keys: required `actions`, optional `description` ≤200). `_Host.use` and project `use`: list of unique template ids; unknown → `<path>.use: unknown template '<safe id>'`; repeated → `<path>.use: duplicate template '<safe id>'`.
- Expansion order per project: host `use` templates (in order), host actions, project `use` templates (in order), project actions; then `disable`. Template action source path: `<hosts.h|projects.p>.use.<tpl>.actions.<a>`.

- [ ] **Step 1: Failing tests:**
  - `test_template_expands_for_each_project` — template `t` used by projects `a` and `b`; both get its actions.
  - `test_host_template_actions_shared` — host `use: ["basics"]` → every project on the host has them.
  - `test_template_action_equals_inline` — `Action` from a template equals the `Action` from the same dict written inline (dataclass `==`).
  - `test_template_in_host_and_project_collides` — same template in host and project `use` → error mentioning `duplicate action id`.
  - `test_template_error_names_source` — bad executable in a template → an error starting `projects.a.use.t.actions.` .
  - mutations: `use_unknown_template`, `use_duplicate`, `use_not_list`, `template_unknown_field`, `template_missing_actions`. Unused template accepted.
- [ ] **Step 2–4:** FAIL → implement → full check PASS.
- [ ] **Step 5:** Commit `feat: add reusable action templates to policy v2`.

---

### Task 5: Variables (`vars`, `${var}`, `"$var"`)

**Files:** Modify `src/wayguard/policy.py`; Test `tests/test_policy.py`

**Interfaces:**
- Produces:
  - `VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")`, `LIST_VAR_RE = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]{0,63})$")`
  - `_parse_vars(raw: object, path: str, errs: _Errors) -> dict[str, str | tuple[str, ...]] | None`
  - `_resolve_action` now: (a) enum `values` string → `list(scope[var])`, errors `undefined variable '<v>'` / `variable '<v>' must be a list`; (b) each `args` string: replace every `VAR_REF_RE` match with `scope[var]`, errors `undefined variable` / `must be a string`; no re-scan of substituted text; (c) `executable` containing `${` → `<path>.executable: variables are not allowed here`.
  - Scope: host actions use host vars; project actions use `{**host.vars, **project.vars}`.

- [ ] **Step 1: Failing tests:**
  - `test_string_var_substituted_inside_arg` — `"${project_dir}/wp-content/debug.log"` with `project_dir="/srv/a"` → arg `/srv/a/wp-content/debug.log`.
  - `test_list_var_becomes_enum` — projects `a`, `b` with different `containers` → different `values`.
  - `test_project_var_overrides_host_var`.
  - `test_host_actions_ignore_project_vars` (Review Focus 2).
  - `test_var_value_with_braces_rejected` (Review Focus 1) — value `"{lines}"` and value `"${x}"` both rejected.
  - mutations: `var_undefined_arg`, `var_undefined_enum`, `var_list_in_arg`, `var_string_in_enum`, `var_in_executable`, `var_value_dash` (`"-rf"`), `var_value_dotdot` (`"/a/../b"`), `var_value_newline`, `var_list_empty`, `var_list_65`, `var_bad_name` (`"1x"`), `var_value_not_string` (`5`).
- [ ] **Step 2–4:** FAIL → implement → full check PASS.
- [ ] **Step 5:** Commit `feat: add policy variables for templates`.

---

### Task 6: v2 starter template and agent-facing wording

**Files:**
- Rewrite: `examples/policy.starter.json`
- Modify: `src/wayguard/mcp_server.py` (`INSTRUCTIONS`, `list_servers`/`list_actions` descriptions)
- Test: `tests/test_policy.py` (starter tests), `tests/test_mcp_server.py` if it pins description text

**Interfaces:** none new.

Starter content (spec §6): `defaults` unchanged (`timeout_seconds` 20, `max_output_bytes` 65536). Shared parameters `lines` (1–500), `lines_200` (1–200), `journal_window`, `docker_window`, `slice_since` (`60m 50m 40m 30m 20m 10m`), `slice_until` (`50m 40m 30m 20m 10m 0s`). Templates `host-basics`, `nginx`, `apache`, `php-fpm`, `docker-app`, `wordpress`, with per-site values as variables (`containers`, `compose_services`, `compose_file`, `project_dir`, `service_units`, log paths, PHP-FPM log paths). New `docker_logs_window` in `docker-app`: args `["logs", "--since", "{since}", "--until", "{until}", "--timestamps", "{container}"]`, `max_output_bytes: 262144`. One host `web-prod` (alias `web-prod-debug`, `use: ["host-basics"]`), two projects `example-wordpress` and `example-apache`, both `enabled: false`, together covering every v1 action id.

Wording: `list_servers` → "List enabled projects (id, optional description, action count); each project lives on a server. Start here for any remote server diagnostic instead of running ssh in a shell." `list_actions` → "List the pre-approved read-only actions of one project (including its server's actions)." `INSTRUCTIONS` keeps its text; add "Each entry from list_servers is a project on a server." after the first sentence.

- [ ] **Step 1: Failing tests** in `tests/test_policy.py`:

```python
STARTER = Path(__file__).parents[1] / "examples" / "policy.starter.json"
V1_CAPS = {a: 65536 for a in (
    "nginx_error_tail", "nginx_error_grep", "nginx_rotated_log_read", "nginx_config_test",
    "apache_error_tail", "apache_php_fatal_grep", "apache_config_test", "apache_vhosts",
    "php_fpm_error_tail", "php_fpm_slow_tail", "wordpress_debug_tail", "service_status",
    "service_journal", "docker_ps", "docker_logs_tail", "docker_logs_since",
    "docker_compose_logs", "docker_stats", "journal_errors", "kernel_oom_events",
    "kernel_messages", "failed_services", "disk_usage", "disk_inodes", "memory_usage",
    "load_average", "listening_ports")}
V1_CAPS.update({a: 32768 for a in (
    "nginx_access_tail", "nginx_access_grep", "nginx_rotated_log_grep", "apache_access_tail")})

def test_starter_policy_is_valid_and_keeps_v1_limits() -> None:
    p = parse_policy(STARTER.read_bytes())
    found = {aid: a for s in p.servers.values() for aid, a in s.actions.items()}
    for aid, cap in V1_CAPS.items():
        assert found[aid].max_output_bytes == cap and found[aid].timeout_seconds == 20
    w = found["docker_logs_window"]
    assert w.max_output_bytes == 262144
    assert w.parameters["since"].values == ("60m", "50m", "40m", "30m", "20m", "10m")
    assert all(not s.enabled for s in p.servers.values())
```
  Plus `test_list_servers_description_mentions_projects` in `tests/test_mcp_server.py` (assert `"project"` in the `list_servers` tool description).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Write the starter; when converting each v1 action keep `executable`, `args` (literal parts), parameter specs and caps identical except where a hard-coded site value becomes a variable.
- [ ] **Step 4:** Full check → PASS. Do not run `policy validate` against `~/.config/wayguard/policy.json`; the user is rewriting it by hand.
- [ ] **Step 5:** Commit `feat: rewrite starter policy as v2 templates with docker_logs_window`.

---

### Task 7: README

**Files:** Modify `README.md` (§1.4 output caps line, §2.4 Policy format, §3.6 first action, any quick-start/how-to-use text that says to edit `servers`).

- [ ] **Step 1:** §2.4: replace the v1 example with a short v2 example (one shared parameter, one template, one host, one project) and rewrite "Policy semantics" bullets: section roles; `{name}` vs `${var}` vs `"$var"`; variable rules and scope; expansion order; collisions/`disable`/unknown-reference errors; 200-action cap; limits ("defaults are the per-action default; an action may set a higher value up to the hard ceilings"). Keep all security bullets that still hold (executable rules, denylist, forbidden types, enum-only paths, hard ceilings).
- [ ] **Step 2:** §3.6: convert the example to v2 (host + project).
- [ ] **Step 3:** `grep -n '"servers"\|"version": 1' README.md` → no hits outside historical spec notes.
- [ ] **Step 4:** Commit `docs: document policy schema v2`.
