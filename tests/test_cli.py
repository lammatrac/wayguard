import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_policy import good
from wayguard import cli, config
from wayguard import policy as policy_mod


def test_main_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert "wayguard-mcp" in capsys.readouterr().out


def test_module_entry_runs() -> None:
    r = subprocess.run(
        [sys.executable, "-m", "wayguard", "--version"], capture_output=True, text=True
    )
    assert r.returncode == 0
    assert "wayguard-mcp" in r.stdout


# ---- phase 2: init / policy validate / actions list ----


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    r = tmp_path / "home" / ".config" / "wayguard"
    monkeypatch.setattr(cli, "default_root", lambda: r)
    return r


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_exit_code_constants_distinct() -> None:
    codes = [cli.EXIT_OK, cli.EXIT_INTERNAL, cli.EXIT_INVALID_POLICY, cli.EXIT_DENIED,
             cli.EXIT_OPERATIONAL]  # fmt: skip
    assert codes == [0, 1, 2, 3, 4]


def test_init_creates_layout_and_empty_policy(root: Path) -> None:
    assert cli.main(["init"]) == 0
    assert mode(root) == 0o700
    assert mode(root / "proposals") == 0o700
    assert mode(root / "state") == 0o700
    p = root / "policy.json"
    assert mode(p) == 0o600
    assert json.loads(p.read_text())["servers"] == {}
    assert policy_mod.load_policy(root).servers == {}


def test_init_twice_refuses_and_leaves_file(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["init"])
    p = root / "policy.json"
    p.write_text(p.read_text() + "\n")
    before = p.read_bytes()
    assert cli.main(["init"]) == cli.EXIT_OPERATIONAL
    assert p.read_bytes() == before
    assert "--force" in capsys.readouterr().err


def test_init_force_keeps_backup(root: Path) -> None:
    cli.main(["init"])
    p = root / "policy.json"
    p.write_bytes(b'{"custom": true}')
    p.chmod(0o600)
    assert cli.main(["init", "--force"]) == 0
    backups = list(root.glob("policy.json.bak-*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == b'{"custom": true}'
    assert mode(backups[0]) == 0o600
    assert json.loads(p.read_text())["servers"] == {}


def write(root: Path, d: object, m: int = 0o600) -> None:
    config.ensure_layout(root)
    p = root / "policy.json"
    p.write_text(json.dumps(d))
    p.chmod(m)


def test_validate_ok(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(root, good())
    assert cli.main(["policy", "validate"]) == 0
    assert "valid" in capsys.readouterr().out


def test_validate_invalid_exit_code_and_message(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d = good()
    d["version"] = 2
    write(root, d)
    assert cli.main(["policy", "validate"]) == cli.EXIT_INVALID_POLICY
    assert "version" in capsys.readouterr().err


def test_validate_permission_error_exit_code(root: Path) -> None:
    write(root, good(), 0o644)
    (root / "policy.json").chmod(0o666)
    assert cli.main(["policy", "validate"]) == cli.EXIT_DENIED


def test_validate_missing_policy(root: Path) -> None:
    config.ensure_layout(root)
    assert cli.main(["policy", "validate"]) == cli.EXIT_DENIED


def test_actions_list_hides_alias(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(root, good())
    assert cli.main(["actions", "list"]) == 0
    out = capsys.readouterr().out
    assert "prod/tail" in out and "prod/unit" in out
    assert "prod-debug" not in out


def test_actions_list_server_filter_and_unknown(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(root, good())
    assert cli.main(["actions", "list", "--server", "prod"]) == 0
    capsys.readouterr()
    assert cli.main(["actions", "list", "--server", "nope"]) == cli.EXIT_DENIED


def test_unexpected_exception_is_internal_error(
    root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_r: Path) -> None:
        raise RuntimeError("SECRET")

    monkeypatch.setattr(policy_mod, "load_policy", boom)
    assert cli.main(["policy", "validate"]) == cli.EXIT_INTERNAL
    assert "SECRET" not in capsys.readouterr().err


def test_policy_path_not_overridable_by_env(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(root, good())
    monkeypatch.setenv("WAYGUARD_POLICY", "/nonexistent")
    assert cli.main(["policy", "validate"]) == 0
