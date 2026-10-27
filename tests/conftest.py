from pathlib import Path

import pytest

from wayguard import claude_guard


@pytest.fixture(autouse=True)
def isolated_claude_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never let a test read or edit the real ~/.claude/settings.json."""
    d = tmp_path / "claude-home" / ".claude"
    monkeypatch.setattr(claude_guard, "claude_dir", lambda: d)
    return d
