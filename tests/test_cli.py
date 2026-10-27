import subprocess
import sys

import pytest

from wayguard import cli


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
