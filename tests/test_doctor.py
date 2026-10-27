import stat
from pathlib import Path

import pytest

from tests.test_policy import dump, good
from wayguard import cli, config, doctor


def fake_ssh(tmp_path: Path, body: str = "exit 0") -> str:
    p = tmp_path / "bin" / "ssh"
    p.parent.mkdir(exist_ok=True)
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


def make_root(tmp_path: Path, data: bytes | None = None) -> Path:
    root = tmp_path / "cfg"
    config.ensure_layout(root)
    config.atomic_write(config.policy_path(root), data if data is not None else dump(good()))
    return root


def run(root: Path, ssh: str | None, lines: list[str]) -> int:
    return doctor.run_doctor(root, ssh_candidates=[ssh] if ssh else [], out=lines.append)


def test_all_ok(tmp_path: Path) -> None:
    lines: list[str] = []
    assert run(make_root(tmp_path), fake_ssh(tmp_path), lines) == 0
    text = "\n".join(lines)
    assert "python" in text and "policy: valid" in text
    assert "prod-debug" not in text  # aliases are never printed
    assert "resolvable: yes" in text


def test_ssh_g_output_never_printed(tmp_path: Path) -> None:
    ssh = fake_ssh(tmp_path, 'echo "identityfile /SECRET/KEY hostname 10.9.8.7"; '
                   'echo "SECRETERR" >&2; exit 0')  # fmt: skip
    lines: list[str] = []
    run(make_root(tmp_path), ssh, lines)
    text = "\n".join(lines)
    assert "SECRET" not in text and "10.9.8.7" not in text


def test_ssh_g_argv_is_minimal_and_failure_reported(tmp_path: Path) -> None:
    log = tmp_path / "argv.log"
    ssh = fake_ssh(tmp_path, f'echo "$@" > {log}; env > {log}.env; exit 255')
    lines: list[str] = []
    run(make_root(tmp_path), ssh, lines)
    assert log.read_text().split() == ["-G", "--", "prod-debug"]
    assert "resolvable: no" in "\n".join(lines)
    env = (tmp_path / "argv.log.env").read_text()
    assert "PATH=/usr/bin:/bin" in env and "LANG=C.UTF-8" in env


def test_no_trusted_ssh_fails(tmp_path: Path) -> None:
    lines: list[str] = []
    assert run(make_root(tmp_path), None, lines) == 4
    assert any("ssh" in line and "FAIL" in line for line in lines)


def test_invalid_policy_exit_2(tmp_path: Path) -> None:
    lines: list[str] = []
    assert run(make_root(tmp_path, b"{}"), fake_ssh(tmp_path), lines) == 2


def test_unsafe_policy_mode_exit_3(tmp_path: Path) -> None:
    root = make_root(tmp_path)
    config.policy_path(root).chmod(0o666)
    lines: list[str] = []
    assert run(root, fake_ssh(tmp_path), lines) == 3
    assert any("mode" in line and "FAIL" in line for line in lines)


def test_missing_root_reports_and_fails(tmp_path: Path) -> None:
    lines: list[str] = []
    assert run(tmp_path / "nope", fake_ssh(tmp_path), lines) != 0


def test_cli_doctor_wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make_root(tmp_path)
    monkeypatch.setattr(cli, "default_root", lambda: root)
    monkeypatch.setattr(doctor, "TRUSTED_SSH_PATHS", (fake_ssh(tmp_path),))
    assert cli.main(["doctor"]) == 0
