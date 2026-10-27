"""AC-016 end-to-end test against a disposable Docker sshd (run with ``pytest -m e2e``).

Safety: the real ~/.ssh and ~/.config/wayguard are never touched. ssh is run through a wrapper
that passes ``-F <temp config>`` (OpenSSH locates ~/.ssh via passwd, not $HOME), with a temp
known_hosts and a throwaway key. The container port is bound to 127.0.0.1 only and the
container and image are removed afterwards. StrictHostKeyChecking is never relaxed.
"""

import asyncio
import json
import shutil
import stat
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from wayguard import config, mcp_server
from wayguard.command import discover_ssh

pytestmark = pytest.mark.e2e

HERE = Path(__file__).parent / "e2e"
IMAGE = "wayguard-e2e-sshd:test"
REAL_SSH = "/usr/bin/ssh"


def _docker_ok() -> bool:
    if not (shutil.which("docker") and shutil.which("ssh-keygen") and shutil.which("ssh-keyscan")):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass
class Env:
    root: Path
    ssh: str
    policy_bytes: bytes


def _keygen(path: Path) -> str:
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "wg-e2e", "-f", str(path)],
        check=True,
    )
    return path.with_name(path.name + ".pub").read_text()


def _policy(extra_servers: dict[str, Any]) -> dict[str, Any]:
    tail = {
        "description": "Tail nginx error log",
        "risk": "read-only",
        "executable": "/usr/bin/tail",
        "args": ["-n", "{lines}", "--", "/var/log/nginx/error.log"],
        "parameters": {"lines": {"type": "integer", "minimum": 1, "maximum": 50}},
    }
    hosts = {f"{alias}-host": {"ssh_alias": alias} for alias in set(extra_servers.values())}
    projects = {
        sid: {
            "enabled": True,
            "host": f"{alias}-host",
            "actions": {"nginx_error_tail": tail},
        }
        for sid, alias in extra_servers.items()
    }
    return {
        "version": 2,
        "defaults": {
            "decision": "deny",
            "timeout_seconds": 20,
            "max_output_bytes": 32768,
            "max_concurrent_actions": 2,
        },
        "hosts": hosts,
        "projects": projects,
    }


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Env]:
    if not _docker_ok():
        pytest.skip("docker, ssh-keygen or ssh-keyscan unavailable")
    tmp = tmp_path_factory.mktemp("wg-e2e")
    cid = ""
    try:
        subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(HERE)], check=True,
                       capture_output=True)  # fmt: skip
        pub = _keygen(tmp / "id_good")
        _keygen(tmp / "id_other")
        (tmp / "authorized_keys").write_text(pub)
        cid = subprocess.run(
            ["docker", "create", "-p", "127.0.0.1::22", IMAGE],
            check=True, capture_output=True, text=True,
        ).stdout.strip()  # fmt: skip
        subprocess.run(["docker", "cp", str(tmp / "authorized_keys"), f"{cid}:/authorized_keys"],
                       check=True, capture_output=True)  # fmt: skip
        subprocess.run(["docker", "start", cid], check=True, capture_output=True)
        out = subprocess.run(["docker", "port", cid, "22/tcp"], check=True,
                             capture_output=True, text=True).stdout.splitlines()[0]  # fmt: skip
        host, _, port = out.rpartition(":")
        assert host == "127.0.0.1"

        hostkey = ""
        for _ in range(40):
            r = subprocess.run(["ssh-keyscan", "-T", "2", "-t", "ed25519", "-p", port, host],
                               capture_output=True, text=True)  # fmt: skip
            hostkey = "".join(x for x in r.stdout.splitlines(keepends=True) if x.startswith("["))
            if hostkey:
                break
            time.sleep(0.5)
        assert hostkey, "sshd did not come up"
        known = tmp / "known_hosts"
        known.write_text(hostkey)
        bad_known = tmp / "known_hosts_changed"
        other_pub = (tmp / "id_other.pub").read_text().split()
        bad_known.write_text(f"[{host}]:{port} {other_pub[0]} {other_pub[1]}\n")

        def block(alias: str, hostname: str, prt: str, key: str, kh: Path) -> str:
            return (
                f"Host {alias}\n  HostName {hostname}\n  Port {prt}\n  User wguser\n"
                f"  IdentityFile {tmp / key}\n  IdentitiesOnly yes\n  IdentityAgent none\n"
                f"  UserKnownHostsFile {kh}\n  GlobalKnownHostsFile /dev/null\n"
            )

        cfg = tmp / "ssh_config"
        cfg.write_text(
            block("e2e-ok", host, port, "id_good", known)
            + block("e2e-changed", host, port, "id_good", bad_known)
            + block("e2e-auth", host, port, "id_other", known)
            + block("e2e-ghost", "nonexistent.invalid", port, "id_good", known)
            + block("e2e-closed", host, "1", "id_good", known)
        )
        wrapper = tmp / "ssh-wrapper"
        wrapper.write_text(f'#!/bin/sh\nexec {REAL_SSH} -F {cfg} "$@"\n')
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        ssh = discover_ssh(_candidates=[str(wrapper)])

        root = tmp / "wgroot"
        config.ensure_layout(root)
        data = json.dumps(_policy({
            "ok": "e2e-ok", "changed": "e2e-changed", "auth": "e2e-auth",
            "ghost": "e2e-ghost", "closed": "e2e-closed",
        })).encode()  # fmt: skip
        config.atomic_write(config.policy_path(root), data)
        yield Env(root, ssh, data)
    finally:
        if cid:
            subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
        subprocess.run(["docker", "rmi", "-f", IMAGE], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


def call(env: Env, name: str, args: dict[str, Any]) -> dict[str, Any]:
    async def go() -> dict[str, Any]:
        svc = mcp_server.WayguardService(env.root, ssh_path=env.ssh)
        r = await svc.call_tool(name, args)
        assert r.structuredContent is not None
        return r.structuredContent

    return asyncio.run(go())


def run(env: Env, server: str, lines: int = 5) -> dict[str, Any]:
    return call(env, "run_action", {"server_id": server, "action_id": "nginx_error_tail",
                                    "parameters": {"lines": lines}})  # fmt: skip


def test_nginx_error_tail_ok_with_five_lines(env: Env) -> None:
    r = run(env, "ok", 5)
    assert r["status"] == "ok", r
    assert r["exit_code"] == 0
    lines = [x for x in r["stdout"].splitlines() if x]
    assert len(lines) == 5
    assert "fake nginx error line 20" in lines[-1]


def test_changed_host_key_is_host_key_error(env: Env) -> None:
    r = run(env, "changed")
    assert r["status"] == "host_key_error", r
    assert r["exit_code"] == 255


@pytest.mark.parametrize(
    ("server", "status", "phrase"),
    [
        ("changed", "host_key_error", "REMOTE HOST IDENTIFICATION HAS CHANGED"),
        ("auth", "auth_error", "Permission denied ("),
        ("ghost", "unknown_alias", "Could not resolve hostname"),
        ("closed", "unreachable", "Connection refused"),
    ],
)
def test_real_openssh_stderr_phrases(env: Env, server: str, status: str, phrase: str) -> None:
    r = run(env, server)
    assert r["status"] == status, r
    assert r["exit_code"] == 255
    # also confirm the phrase really is what OpenSSH printed (stderr passes redaction untouched)
    assert phrase in r["stderr"]


def test_unknown_action_denied_and_only_proposable(env: Env) -> None:
    denied = call(env, "run_action", {"server_id": "ok", "action_id": "nginx_restart",
                                      "parameters": {}})  # fmt: skip
    assert denied["status"] == "denied" and denied["reason_code"] == "unknown_action"
    prop = call(env, "propose_action", {"server_id": "ok", "goal": "restart nginx",
                                        "reason": "needs restart"})  # fmt: skip
    assert prop["status"] == "recorded"
    assert config.policy_path(env.root).read_bytes() == env.policy_bytes
    again = call(env, "run_action", {"server_id": "ok", "action_id": "nginx_restart",
                                     "parameters": {}})  # fmt: skip
    assert again["status"] == "denied"
