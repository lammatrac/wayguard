import dataclasses
import os
import pwd
import shlex
from pathlib import Path
from typing import Any

import pytest

from tests.test_validation import make_policy, req
from wayguard import command
from wayguard.command import (
    CommandBuildError,
    SshNotFoundError,
    build_argv,
    build_command,
    build_remote_command,
    child_env,
    discover_ssh,
)
from wayguard.validation import ValidatedRequest, validate_request

SSH = "/usr/bin/ssh"


def vr(action_id: str, **params: Any) -> ValidatedRequest:
    return validate_request(make_policy(), req(action_id=action_id, parameters=params))


# ---- AC-005 golden argv
def test_golden_argv() -> None:
    v = vr("tail", lines=50)
    built = build_command(v, SSH)
    assert built.remote_command == "/usr/bin/tail -n 50 -- /var/log/x.log"
    assert built.argv == [
        "/usr/bin/ssh", "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "RequestTTY=no",
        "-o", "ConnectTimeout=10",
        "--", "prod-debug", "/usr/bin/tail -n 50 -- /var/log/x.log",
    ]  # fmt: skip


def test_connect_timeout_is_min_of_10_and_timeout() -> None:
    v = vr("tail", lines=1)
    short = dataclasses.replace(v, action=dataclasses.replace(v.action, timeout_seconds=3))
    assert "ConnectTimeout=3" in build_command(short, SSH).argv
    long_ = dataclasses.replace(v, action=dataclasses.replace(v.action, timeout_seconds=100))
    assert "ConnectTimeout=10" in build_command(long_, SSH).argv


def test_alias_is_after_double_dash_and_second_last() -> None:
    argv = build_command(vr("tail", lines=1), SSH).argv
    assert argv[-3] == "--" and argv[-2] == "prod-debug" and len(argv) == 25


# ---- AC-004: shell injection matrix (values that pass validation)
SHELL_VALUES = [
    "a b",
    "'",
    '"',
    ";",
    "|",
    "$()",
    "`",
    "$(id)",
    "a&&b",
    "a;b|c",
    "x y'z\"w",
    "é",
    "\\",
]


@pytest.mark.parametrize("val", SHELL_VALUES)
def test_value_is_exactly_one_remote_argument(val: str) -> None:
    built = build_command(vr("grep", pat=val), SSH)
    assert shlex.split(built.remote_command) == ["/usr/bin/grep", "-e", val, "--", "/var/log/x.log"]


def test_golden_serialized_remote_commands() -> None:
    golden = {
        "a b": "/usr/bin/grep -e 'a b' -- /var/log/x.log",
        "'": "/usr/bin/grep -e ''\"'\"'' -- /var/log/x.log",
        ";": "/usr/bin/grep -e ';' -- /var/log/x.log",
        "$()": "/usr/bin/grep -e '$()' -- /var/log/x.log",
        "`": "/usr/bin/grep -e '`' -- /var/log/x.log",
        "plain": "/usr/bin/grep -e plain -- /var/log/x.log",
    }
    for val, expected in golden.items():
        assert build_command(vr("grep", pat=val), SSH).remote_command == expected


def test_enum_and_string_placeholders() -> None:
    built = build_command(vr("unit", unit="php", name="abc"), SSH)
    assert built.remote_command == "/usr/bin/systemctl status php abc"


# ---- option injection tested separately from shell injection
@pytest.mark.parametrize("val", ["-rf", "--help", "-e", "-"])
def test_option_injection_rejected_before_build(val: str) -> None:
    from wayguard.validation import RequestDenied

    with pytest.raises(RequestDenied):
        vr("grep", pat=val)


def test_build_rechecks_string_values() -> None:
    v = vr("grep", pat="ok")
    evil = dataclasses.replace(v, params={"pat": "-rf"})
    with pytest.raises(CommandBuildError):
        build_command(evil, SSH)
    evil2 = dataclasses.replace(v, params={"pat": "a\nb"})
    with pytest.raises(CommandBuildError):
        build_command(evil2, SSH)


@pytest.mark.parametrize("alias", ["-oProxyCommand=x", "-F/tmp/x", "a b", "a;b", "", "a\nb"])
def test_build_rejects_unsafe_alias(alias: str) -> None:
    v = vr("tail", lines=1)
    bad = dataclasses.replace(v, server=dataclasses.replace(v.server, ssh_alias=alias))
    with pytest.raises(CommandBuildError):
        build_command(bad, SSH)


def test_jump_host_adds_dash_j_before_double_dash() -> None:
    v = vr("tail", lines=1)
    jumped = dataclasses.replace(v, server=dataclasses.replace(v.server, ssh_jump="bastion"))
    argv = build_command(jumped, SSH).argv
    assert argv[-5:-2] == ["-J", "bastion", "--"] and argv[-2] == "prod-debug"
    assert "-J" not in build_command(v, SSH).argv


@pytest.mark.parametrize("jump", ["-oProxyCommand=x", "a b", "a;b", "a,b", "", "a\nb"])
def test_build_rejects_unsafe_jump(jump: str) -> None:
    v = vr("tail", lines=1)
    bad = dataclasses.replace(v, server=dataclasses.replace(v.server, ssh_jump=jump))
    with pytest.raises(CommandBuildError):
        build_command(bad, SSH)


def test_build_rejects_bool_and_missing_param() -> None:
    v = vr("tail", lines=1)
    with pytest.raises(CommandBuildError):
        build_command(dataclasses.replace(v, params={"lines": True}), SSH)
    with pytest.raises(CommandBuildError):
        build_command(dataclasses.replace(v, params={}), SSH)


def test_build_rejects_relative_ssh_path() -> None:
    with pytest.raises(CommandBuildError):
        build_command(vr("tail", lines=1), "ssh")


def test_remote_command_helper() -> None:
    v = vr("tail", lines=7)
    assert build_remote_command(v.action, v.params) == "/usr/bin/tail -n 7 -- /var/log/x.log"
    assert build_argv(SSH, v.server, v.action, "X")[-1] == "X"


# ---- trusted ssh discovery (REQ-007)
def test_trusted_paths_constant() -> None:
    assert command.TRUSTED_SSH_PATHS == (
        "/usr/bin/ssh",
        "/usr/local/bin/ssh",
        "/opt/homebrew/bin/ssh",
    )


def _exe(p: Path) -> str:
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    return str(p)


def test_discover_first_existing_regular_executable(tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    second = _exe(tmp_path / "second")
    assert (
        discover_ssh(_candidates=(str(tmp_path / "missing"), str(tmp_path / "d"), second)) == second
    )


def test_discover_skips_non_executable(tmp_path: Path) -> None:
    f = tmp_path / "noexec"
    f.write_text("x")
    f.chmod(0o644)
    with pytest.raises(SshNotFoundError):
        discover_ssh(_candidates=(str(f),))


def test_discover_ignores_path_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _exe(tmp_path / "ssh")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin")
    monkeypatch.setenv("WAYGUARD_SSH", fake)
    chosen = discover_ssh()
    assert chosen in command.TRUSTED_SSH_PATHS and chosen != fake


def test_discover_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(SshNotFoundError):
        discover_ssh(_candidates=(str(tmp_path / "nope"),))


# ---- child env
def test_child_env_minimal(monkeypatch: pytest.MonkeyPatch) -> None:
    pw = pwd.getpwuid(os.getuid())
    env = child_env({"SECRET": "x", "HOME": "/evil", "SSH_AUTH_SOCK": "/tmp/agent", "AWS_KEY": "y"})
    assert env == {
        "HOME": pw.pw_dir,
        "USER": pw.pw_name,
        "LOGNAME": pw.pw_name,
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "SSH_AUTH_SOCK": "/tmp/agent",
    }


def test_child_env_without_agent_sock() -> None:
    assert "SSH_AUTH_SOCK" not in child_env({})
    assert "SSH_AUTH_SOCK" not in child_env({"SSH_AUTH_SOCK": ""})


def test_child_env_defaults_to_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/a")
    monkeypatch.setenv("LD_PRELOAD", "/evil.so")
    env = child_env()
    assert env["SSH_AUTH_SOCK"] == "/run/a" and "LD_PRELOAD" not in env
