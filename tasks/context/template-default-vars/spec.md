# Template default vars

## Goal

Let a template carry default values for the variables its actions reference, so values that
are the same on every host (Debian log paths, for example) are written once instead of being
repeated in every host's or project's `vars`.

## Behavior

- `templates.<id>` accepts an optional `vars` object, parsed and validated exactly like host
  and project `vars` (string or list of 1-64 strings, same value checks).
- A template's `vars` are visible only to that template's own actions. Inline host/project
  actions and other templates never see them.
- Precedence when expanding a template action, lowest first:
  - template used by a host: template `vars` < host `vars`
  - template used by a project: template `vars` < host `vars` < project `vars`
- A template variable that none of the template's actions references (as `${var}` in `args`
  or `"$var"` as enum `values`, including through a shared parameter) is an error:
  `templates.<id>.vars.<name>: unused variable`.
- Existing rules are unchanged: host vars may be unused; an unused project var is an error;
  host-scope actions never see project vars.
- Backward compatible: a policy without template `vars` parses to the same result.

## Acceptance criteria

1. A project using a template with `vars: {"dir": "/t"}` and no `dir` of its own gets `/t`.
2. A host `dir` overrides the template default; a project `dir` overrides both.
3. A list default resolves an `"$var"` enum.
4. An inline project action referencing a var defined only in a template's `vars` fails with
   `undefined variable`.
5. An unreferenced template var fails with `templates.<id>.vars.<name>: unused variable`.
6. An invalid template var value fails with an error under `templates.<id>.vars.<name>`.
7. The starter policy uses template defaults for shared log paths and still expands to the
   v1 commands (`test_starter_expands_to_v1_commands`).
8. README documents the new key and the precedence.
