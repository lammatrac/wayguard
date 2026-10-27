import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_static_safety.py"


def run(*dirs: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, dirs)], capture_output=True, text=True
    )


def test_real_src_is_clean() -> None:
    assert run(ROOT / "src").returncode == 0


def test_flags_each_forbidden_construct(tmp_path: Path) -> None:
    for i, bad in enumerate(
        [
            "subprocess.run(x, shell=True)",
            "os.system('ls')",
            "os.popen('ls')",
            "eval('1')",
            "exec('1')",
        ]
    ):
        d = tmp_path / str(i)
        d.mkdir()
        (d / "m.py").write_text(f"import os, subprocess\n{bad}\n")
        r = run(d)
        assert r.returncode == 1, bad
        assert "m.py:2" in r.stdout


def test_ignores_lookalikes(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("def evaluate(): ...\nx = 'shell=True'\nmodel.exec_()\n")
    assert run(tmp_path).returncode == 0
