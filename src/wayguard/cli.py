"""Command-line entry point. Later phases add serve, doctor, audit, proposals."""

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime

from wayguard import __version__, config
from wayguard import policy as policy_mod
from wayguard.config import default_root

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_INVALID_POLICY = 2  # argparse usage errors also exit 2 (spec-mandated)
EXIT_DENIED = 3
EXIT_OPERATIONAL = 4

SAMPLE_POLICY = b"""{
  "version": 1,
  "defaults": {
    "decision": "deny",
    "timeout_seconds": 15,
    "max_output_bytes": 32768,
    "max_concurrent_actions": 2
  },
  "servers": {}
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

    pol = sub.add_parser("policy", help="policy tools")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    pol_sub.add_parser("validate", help="validate the policy offline")

    act = sub.add_parser("actions", help="action tools")
    act_sub = act.add_subparsers(dest="actions_command", required=True)
    lst = act_sub.add_parser("list", help="list configured actions (no ssh aliases shown)")
    lst.add_argument("--server", metavar="ID", default=None)
    return parser


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _cmd_init(force: bool) -> int:
    root = default_root()
    config.ensure_layout(root)
    path = config.policy_path(root)
    if path.exists() or path.is_symlink():
        if not force:
            _err("policy already exists; use --force to overwrite (a backup is kept)")
            return EXIT_OPERATIONAL
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        config.atomic_write(path.with_name(f"policy.json.bak-{stamp}"), path.read_bytes())
    config.atomic_write(path, SAMPLE_POLICY)
    print(f"initialized {root}")
    return EXIT_OK


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
    print(f"policy valid: {len(pol.servers)} server(s), {n} action(s)")
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            return _cmd_init(args.force)
        if args.command == "policy":
            return _cmd_validate()
        if args.command == "actions":
            return _cmd_actions_list(args.server)
        parser.print_help()
        return EXIT_OK
    except OSError:
        _err("operational error")
        return EXIT_OPERATIONAL
    except Exception:  # noqa: BLE001 - fail closed, never leak details (CON-006)
        _err("internal error")
        return EXIT_INTERNAL
