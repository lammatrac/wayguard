# Template default vars: plan

Spec: `tasks/context/template-default-vars/spec.md` · evidence: `evidence.md`

1. Tests first (`tests/test_policy.py`), one per acceptance criterion 1-6. Confirm they fail.
2. `policy.py`:
   - Add a frozen `_Template(actions, vars)`. `_parse_templates` accepts optional `vars` (via
     `_parse_vars`) and returns `dict[str, _Template]`.
   - `_expand_project`: scope for a host template is `{**t.vars, **host.vars}`, and for a
     project template `{**t.vars, **project_scope}`. Use `.actions` where the raw actions
     were used before.
   - `parse_policy`: after shared parameters are parsed, report template vars that
     `_var_refs(t.actions, shared)` does not reference.
   - Update the `_parse_templates` spy test for the new return type.
3. Starter: move the Nginx/Apache/PHP-FPM log path defaults from `hosts.web-prod.vars` into
   the `nginx`, `apache` and `php-fpm` templates' `vars`. Starter tests must still pass.
4. README: the `templates` key list and the Scope bullet, plus setup step 3.
5. Gate: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src`.
