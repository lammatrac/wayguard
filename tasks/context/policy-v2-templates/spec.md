# Policy schema v2: shared parameters, templates, hosts and projects

Status: draft for review · 2026-10-28 · evidence: `tasks/context/policy-v2-templates/evidence.md`

## 1. Intent

Today every server block in `policy.json` repeats the full action list (about 30 actions),
and every action repeats its enum lists, time windows and line limits. Adding a server
means copying the whole block and hand-editing container names, service names, log paths
and the project directory scattered through it. One fix then has to be made in many places,
and copies drift.

Several projects also live on the same server. When debugging, the user thinks "look at
the esim project" and expects to see only that project's actions, plus the machine-level
ones (disk, memory, OOM, ...).

v2 lets the author write each thing once and reference it:

- **shared parameters**: `lines`, `window`, ... defined once, referenced by name;
- **templates**: named action sets written once with variables;
- **hosts**: one entry per machine (SSH alias + machine-level templates);
- **projects**: one entry per project on a host, filling in the variables.

## 2. Goals, non-goals, anti-goals

Goals
- Adding a project to an existing host is about 10 lines: id, host, description, templates,
  variables.
- Adding a host is one small entry plus its projects.
- The agent targets a project and sees only that project's actions plus its host's actions.
- The starter template (`examples/policy.starter.json`) shows the intended layout.

Non-goals
- No migration command and no v1 support. The user rewrites `policy.json` by hand from
  the new starter.
- No change to MCP tool names, argument names, result shapes, audit format, proposals,
  SSH runner or command construction.
- No template inheritance (templates using templates), no conditionals, no expressions.

Anti-goals (a failure even if it works)
- Any path by which agent input reaches executable, alias, a fixed argument or a variable.
- Any check that is weaker for a templated action than for the same action written inline.
- Silent overrides: two definitions of one action id in a project, a misspelled `disable`
  entry or variable that quietly does nothing.

## 3. Schema

```jsonc
{
  "version": 2,
  "defaults": { "decision": "deny", "timeout_seconds": 20,
                "max_output_bytes": 65536, "max_concurrent_actions": 2 },   // unchanged

  "parameters": {                                     // optional
    "lines":  { "type": "integer", "minimum": 1, "maximum": 500 },
    "window": { "type": "enum", "values": ["15m", "30m", "1h", "6h"] }
  },

  "templates": {                                      // optional
    "docker-app": {
      "description": "Container logs for one Compose project",        // optional, <=200
      "actions": {
        "docker_logs_since": {
          "description": "Log lines of one container within a time window",
          "risk": "read-only",
          "executable": "/usr/bin/docker",
          "args": ["logs", "--since", "{window}", "--timestamps", "{container}"],
          "parameters": {
            "window": "window",                                        // shared reference
            "container": { "type": "enum", "values": "$containers" }   // list variable
          }
        },
        "wordpress_debug_tail": {
          "description": "Last N lines of the WordPress debug log",
          "risk": "read-only",
          "executable": "/usr/bin/tail",
          "args": ["-n", "{lines}", "--", "${project_dir}/wp-content/debug.log"],
          "parameters": { "lines": "lines" }
        }
      }
    }
  },

  "hosts": {                                          // required (may be {})
    "esim-prod": {
      "ssh_alias": "esim-prod-debug",
      "description": "Hetzner box running the esim and games stacks",  // optional, <=200
      "use": ["host-basics"],                                          // optional
      "vars": { },                                                     // optional
      "actions": { }                                                   // optional
    }
  },

  "projects": {                                       // required (may be {})
    "www.bild-esim.com": {
      "enabled": true,
      "host": "esim-prod",
      "description": "bild eSIM WordPress",                            // optional, <=200
      "use": ["docker-app", "nginx-host-logs"],                        // optional
      "vars": {
        "containers": ["www.bild-esim.com_wp", "www.bild-esim.com_db", "nginx-proxy"],
        "project_dir": "/srv/www.bild-esim.com"
      },
      "actions": { },                                                  // optional extras
      "disable": ["apache_config_test"]                                // optional
    }
  }
}
```

Top level: `version`, `defaults`, `hosts`, `projects` are required; `parameters` and
`templates` are optional. `servers` is gone. Unknown fields are rejected at every level, as
today.

### 3.1 Identifiers

- Keys of `parameters`, `templates`, `hosts`, `projects` and action ids use `ID_RE`
  (`[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}`).
- An action's local parameter names keep `PARAM_NAME_RE` (the `{name}` placeholder
  grammar), whether the definition is inline or a shared reference.
- Variable names use `PARAM_NAME_RE`.

### 3.2 Action definitions

An action is written exactly as in v1 (`description`, `risk`, `executable`, `args`,
`parameters`, optional `timeout_seconds`, `max_output_bytes`), with three additions:

1. **Shared parameter reference.** In `parameters`, a value that is a string is the key
   of an entry in top-level `parameters`. The action-local name (the key) is what `{name}`
   in `args` refers to, so `"container": "containers_param"` is legal. Unknown key → error.
2. **List variable as enum values.** An `enum` parameter's `values` may be a string
   `"$var"` naming a list variable instead of a literal list. Allowed both inline and in
   top-level `parameters`. The variable must resolve to a list (see 3.4). The resulting
   enum is checked exactly like a literal enum (1–64 values, `string_value_violation`).
3. **String variables in arguments.** Inside an `args` element, `${var}` is replaced at
   load time with a string variable. It may appear anywhere in the element, any number of
   times (`"${project_dir}/wp-content/debug.log"`). This is a load-time constant written
   by the policy author; agent input never reaches it.

**Changed limit rule (user decision).** `defaults.max_output_bytes` is only the value an
action gets when it sets none. An action's own `max_output_bytes` may now be higher than
the default, up to the hard ceiling `config.MAX_STREAM_BYTES` (256 KiB). The same applies
to `timeout_seconds`, up to `config.MAX_TIMEOUT_SECONDS`. In `policy.py`, `_action_limit`
checks against the config ceiling instead of the default. Above the ceiling → error
`exceeds limit <N>`.

Unchanged rules: `{name}` is an agent-supplied parameter and must still be the whole
argument; `executable` must be a literal (no `${var}`), absolute, normalized, not on the
denylist; `description` is literal; every declared parameter must be used and every
`{name}` must be declared.

### 3.3 Order of checks for one expanded action

1. Parse the action as written (structure, unknown fields, types).
2. Resolve shared parameter references and `"$var"` enum values.
3. Substitute `${var}` in each `args` element.
4. Run every existing v1 check on the **result**: placeholder/whole-arg rule, no stray
   `{`/`}` left after substitution, no NUL/CR/LF, enum value rules, executable rules,
   limit rules against `defaults`.

So a substituted value containing `{lines}`, a newline, or a brace is rejected, and the
expanded action is held to exactly the v1 bar.

### 3.4 Variables

- A variable value is either a string or a list of 1–64 strings.
- Every string (scalar or list element) must pass `string_value_violation` with
  `MAX_STRING_LENGTH`: no control characters, does not start with `-`, no `..` path
  segment, at most 256 characters.
- `${var}` requires a string; `"$var"` requires a list. Wrong kind → error.
- Scope: host actions (from host `use` and host `actions`) see **host vars** only.
  Project actions (from project `use` and project `actions`) see **host vars overlaid by
  project vars** (project wins).
- Undefined variable → error. Unused variables are allowed (a host var may only be used
  by some projects).

### 3.5 Expansion into the existing model

Each project becomes one `policy.Server` in `Policy.servers`, keyed by project id:

- `id` = project id; `enabled` = project `enabled`; `description` = project description;
  `ssh_alias` = its host's `ssh_alias`.
- `actions` = host template actions + host inline actions + project template actions +
  project inline actions, minus `disable`.
- Two sources defining the same action id in one project → error naming both sources.
  To replace a template action, `disable` it and define a new id.
- `disable` naming an action id that the project would not otherwise have → error.
- `host` naming an unknown host, or `use` naming an unknown template → error.
- A template listed twice in one `use` → error.
- Hosts with no projects are allowed and produce nothing. Unused templates and unused
  shared parameters are allowed (the starter ships a library).
- Cap: at most 200 actions per expanded project (new constant `MAX_ACTIONS_PER_PROJECT`).

The `Policy`, `Server`, `Action` and `ParameterSpec` dataclasses keep their fields, so
`mcp_server`, `validation`, `ssh_runner`, `command`, audit, proposals and `doctor`
need no code change.

### 3.6 Errors

Same style as today (`<json.path>: <fixed reason>`, sanitized keys, no values, max 50).
For an action that came from a template, the path names where it is written and which
project expanded it, e.g.
`projects.www.bild-esim.com.use.docker-app.actions.wordpress_debug_tail.args[3]: undefined variable 'project_dir'`.
A template with a structural mistake reports it once per expanding project; the 50-error
cap bounds this.

`version` other than 2 → `version: must be 2`.

## 4. Agent-facing behaviour

- Tool names, arguments and results are unchanged. `server_id` now carries a project id.
- `list_servers` lists enabled projects with their description and action count. Its tool
  description and the server instructions text say "projects (each on a host)" so the
  agent knows what an entry is. Host ids and aliases are never exposed.
- `list_actions` returns the expanded actions, exactly as if written inline.

## 5. CLI and other touch points

- `init` writes a v2 `SAMPLE_POLICY` (`version: 2`, defaults, `hosts: {}`, `projects: {}`).
- `policy validate` prints `policy valid: N project(s) on M host(s), K action(s)`.
- `actions list [--server ID]` prints the expanded actions (unchanged code path).
- `doctor` keeps checking alias resolvability per server; projects sharing a host repeat
  the line. Acceptable.

## 6. Starter template (`examples/policy.starter.json`)

Rewritten as v2. Keeps every v1 starter action (same ids, executables, args, limits) but
organises them as:

- shared `parameters`: `lines` (1–500), `lines_200` (1–200), `journal_window`
  (`15 min ago` … `today`), `docker_window` (`15m` … `6h`), plus slice enums for the new
  window action;
- templates: `host-basics` (disk, inodes, memory, load, failed services, OOM, kernel,
  listening ports, journal errors, `docker_ps`, `docker_stats`), `nginx`, `apache`,
  `php-fpm`, `docker-app` (container logs tail/since/window, compose logs),
  `wordpress` (debug log);
- variables replace the hard-coded per-site values: `containers`, `compose_services`,
  `compose_file`, `project_dir`, `nginx_units`/`service_units`, log paths, PHP version
  paths;
- new action `docker_logs_window` in `docker-app`:
  `docker logs --since {since} --until {until} --timestamps {container}`, `since` enum
  `60m 50m 40m 30m 20m 10m`, `until` enum `50m 40m 30m 20m 10m 0s`,
  `max_output_bytes` 262144. `defaults.max_output_bytes` stays 65536, so every other
  action keeps exactly its v1 starter cap (allowed by the changed limit rule in 3.2);
- one example host with two disabled example projects, to show that host actions are
  shared and project values differ.

## 7. Docs

- README §2.4 rewritten for v2 (schema, the `{name}` vs `${var}` vs `"$var"` rules,
  scoping, expansion, collision rules). §3.6 example converted to v2. Quick-start text that
  mentions servers in the policy is updated to hosts/projects.
- README §1.5 change-control answers recorded in this spec (section 9).

## 8. Tests (acceptance)

Policy (`tests/test_policy.py`, fixtures rewritten for v2):
- Valid v2 with shared params, a template, a host, two projects on that host builds the
  model: two `Server`s, same alias, host actions present in both, per-project enum values.
- The expanded `Action` equals the one built from the same action written inline
  (field-by-field).
- Rejected, each with its own path-addressed error: version 1; missing `hosts`/`projects`;
  unknown field at each new level; unknown host; unknown template; duplicate template in
  `use`; unknown shared parameter; undefined variable (both `${}` and `"$"` forms);
  `${list}` and `"$string"` kind mismatch; variable value starting with `-`, containing
  `..`, a newline or a control character; substituted arg containing `{`, `}` or `{x}`;
  `${var}` in `executable`; action id collision (template vs template, template vs
  inline, host vs project); `disable` of a non-existent action; more than 200 actions;
  list variable with 0 or 65 entries.
- `examples/policy.starter.json` loads with `parse_policy` (guards the starter), and
  every action id from the v1 starter is present in an example project with the same
  effective `timeout_seconds` and `max_output_bytes` as in v1.
- Limits: an action cap above `defaults` but within the hard ceiling is accepted and
  effective; above the hard ceiling is rejected (bytes and timeout); an action without a
  cap gets the default. The existing v1 test expecting "exceeds policy defaults" is
  replaced by these.

Others: update fixtures in `test_validation.py`, `test_mcp_server.py`, `test_cli*.py`,
`test_e2e_docker.py` to v2; `init` test asserts the sample is v2 and valid; `list_servers`
returns project ids and never a host id or alias.

## 9. Change-control answers (README §1.5)

- Adds no executable, target type, SSH capability or mutation. Adds a load-time text
  substitution written only by the policy author.
- Agent-controlled values: unchanged. Agents still choose only `{name}` parameters
  within their specs; `${var}` and `"$var"` are resolved before any request exists.
- Self-granting: no. Policy file ownership/mode checks unchanged.
- Secrets: variables are not returned by any tool except as enum values the author
  chose, which are already visible in v1. Errors never echo values.
- Malformed input: fail closed, same as v1.
- Injection tests: section 8 (braces, newlines, `-`, `..` in variables; executable
  substitution forbidden; post-expansion v1 checks).
- Limits: a single action may now be given a cap above `defaults`, up to the unchanged
  hard ceilings in code. Policy still cannot exceed the ceilings or disable a cap; the
  default output per call stays 64 KiB in the starter. README §1.4/§2.4 wording
  ("within globally defined maximums") is updated to say the maximum is the hard ceiling.
- Enforcement remains client-side only, as in v1.

## 10. Calls made by the builder/designer (review these)

- Project ids are exposed through the existing `server_id`; tool names unchanged.
- `${var}` may be embedded anywhere in an argument; `{name}` stays whole-argument.
- Project vars override host vars; host actions see host vars only.
- No `enabled` on hosts; disable the projects instead.
- v1 is rejected outright (no compatibility path), as the user will rewrite the policy.
- Collisions are errors; override = `disable` + new id.
- Unused templates, shared parameters and variables are allowed.
- 200-action cap per project.
- `max_concurrent_actions` stays global, not per host or project.
- Projects on one host share its alias; no alias-uniqueness rule is added.
- No escape syntax for a literal `${` (braces are already illegal in arguments).
- A shared parameter's `"$var"` is resolved in the scope of the action that uses it.

- The same "may exceed default, up to the hard ceiling" rule is applied to
  `timeout_seconds` for consistency.

User decision: action output caps may exceed `defaults` up to the hard ceiling (3.2).
