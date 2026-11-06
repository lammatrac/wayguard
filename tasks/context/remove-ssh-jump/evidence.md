# Evidence

Context: hosts are now reached by direct SSH over a VPN tunnel, so the `ssh -J` jump
support added in 8d96d03 is no longer needed. Decision (user): remove the feature.

Located with WayContext `search_code` ("ssh jump host alias passed as -J option") and
`get_symbol` (`build_argv`, `run_doctor`). Docs, config and the live policy were checked
with `grep` because they are not indexed code.

- `src/wayguard/policy.py`: `Server.ssh_jump`, `_Host.ssh_jump`, the `ssh_jump` optional
  key and `_check_alias` call in `_parse_host`, and `ssh_jump=host.ssh_jump` in
  `_expand_project`. All added by 8d96d03, nothing else reads them.
- `src/wayguard/command.py::build_argv`: jump alias validation and `-J <jump>` before `--`.
  Added by 8d96d03.
- Tests added by 8d96d03: `test_jump_host_adds_dash_j_before_double_dash`,
  `test_build_rejects_unsafe_jump` (tests/test_command.py),
  `test_host_ssh_jump_reaches_every_project_on_the_host`, the `ssh_jump is None` assert and
  the five `jump_*` mutations (tests/test_policy.py).
- README: the `hosts` key list and the `ssh_alias`/`ssh_jump` semantics bullet were changed
  by 8d96d03. The older generic `ProxyJump` notes (lines ~217, ~608, ~875) describe the
  user's own `~/.ssh/config` and predate 8d96d03; they stay.
- 8d96d03 is HEAD, so `git revert --no-commit 8d96d03` applies cleanly.
- Live policy `~/.config/wayguard/policy.json` (not in the repo): 19 of 21 hosts set
  `"ssh_jump": "wlxssh"`. After the code removal, `_check_keys` rejects `ssh_jump` as an
  unknown key, so the live policy must be updated first.
- Could not check `~/.ssh/config` for a `ProxyJump` on the target aliases: the WayGuard
  Claude guard hook blocks running `ssh -G` from the shell. The user checks this.
