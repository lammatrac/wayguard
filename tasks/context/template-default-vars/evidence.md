# Evidence

All symbols are in `src/wayguard/policy.py` unless noted. Located with `sed`/`grep` on a
single known file, since the code is already open in the session (no `search_code` needed).

- `_parse_templates(raw, errs)`: today accepts only `description` and `actions` and returns
  `dict[str, Mapping]` of raw action dicts. This is where `vars` gets parsed.
- `_Ctx.templates`: read in `_expand_project` (host `use`, project `use`, unused-project-var
  refs) and passed to `_parse_host` / `_parse_use` for id lookup.
- `_parse_vars(raw, path, errs)`: shared vars validation, reused as is.
- `_expand_project`: builds `sources` as `(path, actions, scope)`. Host templates get
  `host.vars`, project templates get `project_scope = {**host.vars, **proj_vars}`. Template
  defaults are layered under these per template.
- `_var_refs(actions, shared)`: collects referenced names, including through shared
  parameters. Reused for the unused-template-var check, which must run after
  `_parse_shared_parameters` (parsed after templates in `parse_policy`).
- `tests/test_policy.py::test_template_vars_per_project_and_raw_not_mutated` spies on
  `_parse_templates` and indexes its result as actions, so it changes with the return type.
- `tests/test_policy.py::test_resolve_action_does_not_mutate_input` builds `_Ctx(...,
  templates={})`, which stays valid.
- `examples/policy.starter.json` + `test_starter_expands_to_v1_commands`: pins the starter's
  expanded commands to v1.
