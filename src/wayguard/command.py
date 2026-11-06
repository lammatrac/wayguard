"""Command construction (REQ-006) and trusted SSH discovery (REQ-007).

Builds the exact local argv and serialized remote command from a
``ValidatedRequest``. It never spawns a process (the runner does, phase 4).
Every check here is defense in depth on top of policy load and request
validation; any failure raises ``CommandBuildError`` (fail closed, CON-005).
"""

from __future__ import annotations

import os
import pwd
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from wayguard.policy import ALIAS_RE, PLACEHOLDER_RE, Action, Server, string_value_violation
from wayguard.validation import ValidatedRequest

# Hard-coded. Not configurable via env, policy or MCP input.
TRUSTED_SSH_PATHS: tuple[str, ...] = (
    "/usr/bin/ssh",
    "/usr/local/bin/ssh",
    "/opt/homebrew/bin/ssh",
)

MAX_CONNECT_TIMEOUT = 10
MAX_ALIAS_LENGTH = 255


class CommandBuildError(Exception):
    """Could not build a safe command. Message is fixed text, never a raw value."""


class SshNotFoundError(Exception):
    """No trusted ssh client found."""


@dataclass(frozen=True)
class BuiltCommand:
    argv: list[str]  # exact local argv, run with shell=False
    remote_command: str  # serialized remote command (also argv[-1]); never audit/log it


def discover_ssh(*, _candidates: Sequence[str] = TRUSTED_SSH_PATHS) -> str:
    """First existing, executable regular file from the fixed list. ``PATH`` is never used.

    ``_candidates`` is the TEST-ONLY seam: tests pass a tmp fake ssh. Production
    code must call ``discover_ssh()`` with no arguments; nothing reads it from
    env vars, policy or MCP input.
    """
    for path in _candidates:
        if os.path.isabs(path) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise SshNotFoundError("no trusted ssh client found")


def child_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Minimal child environment. Nothing else is inherited.

    HOME/USER/LOGNAME come from the passwd entry of the current UID (not env).
    ``SSH_AUTH_SOCK`` is passed through from ``environ`` (default ``os.environ``).
    """
    src = os.environ if environ is None else environ
    pw = pwd.getpwuid(os.getuid())
    env = {
        "HOME": pw.pw_dir,
        "USER": pw.pw_name,
        "LOGNAME": pw.pw_name,
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    sock = src.get("SSH_AUTH_SOCK")
    if sock:
        env["SSH_AUTH_SOCK"] = sock
    return env


def _arg_value(action: Action, name: str, params: Mapping[str, str | int]) -> str:
    spec = action.parameters.get(name)
    if spec is None or name not in params:
        raise CommandBuildError("placeholder has no validated value")
    value = params[name]
    if spec.type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise CommandBuildError("integer placeholder is not an integer")
        return str(value)
    if not isinstance(value, str):
        raise CommandBuildError("string placeholder is not a string")
    limit = spec.max_length if spec.max_length is not None else 256
    if string_value_violation(value, limit) is not None:
        raise CommandBuildError("placeholder value violates string rules")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CommandBuildError("placeholder value is not valid UTF-8") from exc
    return value


def build_remote_command(action: Action, params: Mapping[str, str | int]) -> str:
    """``shlex.quote(executable)`` + ``shlex.quote(arg)`` per argument, single-space joined.

    A placeholder is an arg that is exactly ``{name}`` and yields exactly one argument.
    """
    parts = [shlex.quote(action.executable)]
    for arg in action.args:
        m = PLACEHOLDER_RE.fullmatch(arg)
        parts.append(shlex.quote(_arg_value(action, m.group(1), params) if m else arg))
    return " ".join(parts)


def build_argv(ssh_path: str, server: Server, action: Action, remote_command: str) -> list[str]:
    if not os.path.isabs(ssh_path):
        raise CommandBuildError("ssh path must be absolute")
    alias = server.ssh_alias
    if len(alias) > MAX_ALIAS_LENGTH or ALIAS_RE.fullmatch(alias) is None:
        raise CommandBuildError("ssh alias is not allowed")
    connect_timeout = min(MAX_CONNECT_TIMEOUT, action.timeout_seconds)
    if connect_timeout < 1:
        raise CommandBuildError("timeout must be positive")
    return [
        ssh_path,
        "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "RequestTTY=no",
        "-o", f"ConnectTimeout={connect_timeout}",
        "--", alias, remote_command,
    ]  # fmt: skip


def build_command(request: ValidatedRequest, ssh_path: str) -> BuiltCommand:
    remote = build_remote_command(request.action, request.params)
    return BuiltCommand(
        argv=build_argv(ssh_path, request.server, request.action, remote), remote_command=remote
    )
