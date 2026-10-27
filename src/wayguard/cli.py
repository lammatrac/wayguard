"""Command-line entry point."""

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime

from wayguard import __version__, audit, claude_guard, config, doctor, proposals
from wayguard import policy as policy_mod
from wayguard.config import default_root

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_INVALID_POLICY = 2  # argparse usage errors also exit 2 (spec-mandated)
EXIT_DENIED = 3
EXIT_OPERATIONAL = 4

SAMPLE_POLICY = b"""{
  "version": 2,
  "defaults": {
    "decision": "deny",
    "timeout_seconds": 15,
    "max_output_bytes": 32768,
    "max_concurrent_actions": 2
  },
  "hosts": {},
  "projects": {}
}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wayguard-mcp",
        description="Read-only, policy-gated SSH diagnostics exposed over MCP (stdio).",
    )
    parser.add_argument("--version", action="version", version=f"wayguard-mcp {__version__}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="create the config layout and a sample policy")
    init.add_argument("--force", action="store_true", help="overwrite policy (keeps a backup)")
    init.add_argument("--no-claude-guard", action="store_true",
                      help="do not block direct ssh in Claude Code settings")  # fmt: skip

    guard = sub.add_parser("claude-guard", help="block direct ssh in Claude Code (settings.json)")
    guard_sub = guard.add_subparsers(dest="guard_command", required=True)
    guard_sub.add_parser("install", help="add the PreToolUse hook and deny rules (idempotent)")
    guard_sub.add_parser("uninstall", help="remove what install added")
    guard_sub.add_parser("status", help="report whether the guard is installed")

    hk = sub.add_parser("hook", help="agent hook entry points (called by the agent, not you)")
    hk.add_argument("hook_name", choices=[claude_guard.HOOK_SUBCOMMAND])

    pol = sub.add_parser("policy", help="policy tools")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    pol_sub.add_parser("validate", help="validate the policy offline")

    act = sub.add_parser("actions", help="action tools")
    act_sub = act.add_subparsers(dest="actions_command", required=True)
    lst = act_sub.add_parser("list", help="list configured actions (no ssh aliases shown)")
    lst.add_argument("--server", metavar="ID", default=None)

    sub.add_parser("doctor", help="check python, ssh, paths, modes, policy (offline)")
    sub.add_parser("serve", help="run the MCP server on stdio")

    aud = sub.add_parser("audit", help="audit log tools")
    aud_sub = aud.add_subparsers(dest="audit_command", required=True)
    tl = aud_sub.add_parser("tail", help="print the last audit lines")
    tl.add_argument("--limit", type=_positive_int, default=20, metavar="N")
    pr = aud_sub.add_parser("prune", help="delete audit lines older than DAYS")
    pr.add_argument("--older-than", type=_positive_int, required=True, metavar="DAYS")

    prop = sub.add_parser("proposals", help="review action proposals (human only)")
    prop_sub = prop.add_subparsers(dest="proposals_command", required=True)
    pl = prop_sub.add_parser("list", help="list pending proposals")
    pl.add_argument("--all", action="store_true", help="include dismissed and done")
    for name, helptext in (
        ("show", "show one proposal"),
        ("dismiss", "mark a pending proposal dismissed (terminal)"),
        ("mark-done", "mark a pending proposal done (terminal)"),
    ):
        pp = prop_sub.add_parser(name, help=helptext)
        pp.add_argument("id", metavar="ID")
    return parser


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer >= 1") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be an integer >= 1")
    return n


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _install_claude_guard() -> int:
    if not claude_guard.claude_dir().is_dir():
        print("Claude Code not detected; skipped the direct-ssh guard "
              "(run `wayguard-mcp claude-guard install` after installing it)")  # fmt: skip
        return EXIT_OK
    return _cmd_claude_guard("install")


def _cmd_claude_guard(cmd: str) -> int:
    path = claude_guard.settings_path()
    try:
        if cmd == "status":
            st = claude_guard.status(path)
            if st.ok:
                print(f"claude guard: installed in {path}")
                return EXIT_OK
            if not st.hook:
                print("claude guard: hook missing")
            elif not st.current_path:
                print("claude guard: hook points at another wayguard install")
            for rule in st.missing_rules:
                print(f"claude guard: deny rule missing: {rule}")
            print("run `wayguard-mcp claude-guard install`")
            return EXIT_DENIED
        change = (claude_guard.install if cmd == "install" else claude_guard.uninstall)(path)
    except claude_guard.GuardConfigError as e:
        _err(f"claude guard: {e}")
        return EXIT_OPERATIONAL
    verb = "installed in" if cmd == "install" else "removed from"
    print(f"claude guard: {verb} {path}" if change.changed
          else f"claude guard: {path} already up to date")  # fmt: skip
    if change.backup is not None:
        print(f"claude guard: previous settings saved to {change.backup}")
    if change.changed:
        print("claude guard: restart Claude Code sessions to apply")
    return EXIT_OK


def _cmd_init(force: bool, guard: bool) -> int:
    root = default_root()
    config.ensure_layout(root)
    guard_code = _install_claude_guard() if guard else EXIT_OK
    path = config.policy_path(root)
    if path.exists() or path.is_symlink():
        if not force:
            _err("policy already exists; use --force to overwrite (a backup is kept)")
            return EXIT_OPERATIONAL
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        config.atomic_write(path.with_name(f"policy.json.bak-{stamp}"), path.read_bytes())
    config.atomic_write(path, SAMPLE_POLICY)
    print(f"initialized {root}")
    return guard_code


def _load() -> tuple[policy_mod.Policy | None, int]:
    try:
        return policy_mod.load_policy(default_root()), EXIT_OK
    except config.PolicyPermissionError as e:
        _err(f"policy refused: {e}")
        return None, EXIT_DENIED
    except policy_mod.PolicyInvalidError as e:
        _err("policy invalid:")
        for line in e.errors:
            _err(f"  {line}")
        return None, EXIT_INVALID_POLICY


def _cmd_validate() -> int:
    pol, code = _load()
    if pol is None:
        return code
    n = sum(len(s.actions) for s in pol.servers.values())
    hosts = len({s.ssh_alias for s in pol.servers.values()})
    print(f"policy valid: {len(pol.servers)} project(s) on {hosts} host(s), {n} action(s)")
    return EXIT_OK


def _cmd_actions_list(server: str | None) -> int:
    pol, code = _load()
    if pol is None:
        return code
    if server is not None and server not in pol.servers:
        _err("unknown server")
        return EXIT_DENIED
    for sid, s in pol.servers.items():
        if server is not None and sid != server:
            continue
        for aid, a in s.actions.items():
            flag = "" if s.enabled else " [disabled]"
            print(f"{sid}/{aid}{flag}: {a.description}")
            print(f"  timeout={a.timeout_seconds}s max_output={a.max_output_bytes}B")
            for p in a.parameters.values():
                print(f"  param {p.name}: {p.type}")
    return EXIT_OK


def _cmd_audit(args: argparse.Namespace) -> int:
    root = default_root()
    if args.audit_command == "tail":
        for line in audit.tail(root, args.limit):
            print(line)
        return EXIT_OK
    print(audit.prune(root, older_than_days=args.older_than))
    return EXIT_OK


def _cmd_proposals(args: argparse.Namespace) -> int:
    root = default_root()
    cmd = args.proposals_command
    try:
        if cmd == "list":
            for d in proposals.list_proposals(root, include_all=args.all):
                print(f"{d['id']}  {d.get('status')}  {d.get('created_at')}  "
                      f"{d.get('server_id')}  {str(d.get('goal'))[:60]!r}")  # fmt: skip
            return EXIT_OK
        if cmd == "show":
            d = proposals.get_proposal(root, args.id)
            for key, val in d.items():
                print(f"{key}: {val}")
            return EXIT_OK
        new = "dismissed" if cmd == "dismiss" else "done"
        d = proposals.set_status(root, args.id, new)
        print(f"{d['id']}: {d['status']}")
        return EXIT_OK
    except proposals.InvalidProposalIdError:
        _err("invalid proposal id")
        return EXIT_DENIED
    except proposals.ProposalNotFoundError:
        _err("proposal not found")
        return EXIT_DENIED
    except proposals.ProposalStateError:
        _err("proposal is already in a terminal state; status cannot change")
        return EXIT_OPERATIONAL


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            from wayguard import mcp_server  # lazy: keep other commands import-light

            return mcp_server.serve(default_root())
        if args.command == "doctor":
            return doctor.run_doctor(default_root())
        if args.command == "hook":
            return claude_guard.run_hook(sys.stdin, sys.stdout, sys.stderr)
        if args.command == "init":
            return _cmd_init(args.force, not args.no_claude_guard)
        if args.command == "claude-guard":
            return _cmd_claude_guard(args.guard_command)
        if args.command == "policy":
            return _cmd_validate()
        if args.command == "actions":
            return _cmd_actions_list(args.server)
        if args.command == "audit":
            return _cmd_audit(args)
        if args.command == "proposals":
            return _cmd_proposals(args)
        parser.print_help()
        return EXIT_OK
    except OSError:
        _err("operational error")
        return EXIT_OPERATIONAL
    except Exception:  # noqa: BLE001 - fail closed, never leak details (CON-006)
        _err("internal error")
        return EXIT_INTERNAL
