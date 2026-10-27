import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from wayguard import audit, cli, config, proposals


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    r = tmp_path / "w"
    monkeypatch.setattr(cli, "default_root", lambda: r)
    return r


def seed_audit(root: Path, n: int) -> None:
    sink = audit.FileAuditSink(root)
    for i in range(n):
        sink.record_start(correlation_id=f"c{i}", server_id="s", action_id="a", params_summary={})


def test_audit_tail_default_and_limit(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seed_audit(root, 30)
    assert cli.main(["audit", "tail"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 20
    assert cli.main(["audit", "tail", "--limit", "3"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert [json.loads(x)["correlation_id"] for x in out] == ["c27", "c28", "c29"]


def test_audit_tail_without_file_is_empty_ok(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["audit", "tail"]) == 0
    assert capsys.readouterr().out == ""


def test_audit_tail_bad_limit_is_usage_error(root: Path) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", "tail", "--limit", "0"])
    assert e.value.code == 2


def test_audit_prune_prints_count_and_keeps_mode(
    root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    seed_audit(root, 1)
    p = config.audit_path(root)
    old = (datetime.now(UTC) - timedelta(days=45)).isoformat()
    with p.open("a") as f:
        f.write(json.dumps({"ts": old, "event": "start"}) + "\n")
    assert cli.main(["audit", "prune", "--older-than", "30"]) == 0
    assert capsys.readouterr().out.strip() == "1"
    assert len(p.read_text().splitlines()) == 1
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


@pytest.mark.parametrize("val", ["0", "-3", "abc"])
def test_audit_prune_rejects_bad_days(root: Path, val: str) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", "prune", "--older-than", val])
    assert e.value.code == 2


def test_audit_prune_requires_flag(root: Path) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(["audit", "prune"])
    assert e.value.code == 2


def mk(root: Path, goal: str = "find disk usage") -> str:
    return proposals.create_proposal(
        root, server_id="web1", goal=goal, reason="why", server_known=False
    )


def test_proposals_list_and_all(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, b = mk(root), mk(root)
    assert cli.main(["proposals", "dismiss", a]) == 0
    capsys.readouterr()
    assert cli.main(["proposals", "list"]) == 0
    out = capsys.readouterr().out
    assert b in out and a not in out
    assert cli.main(["proposals", "list", "--all"]) == 0
    out = capsys.readouterr().out
    assert a in out and b in out and "dismissed" in out


def test_proposals_show(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = mk(root, "line1\nline2")
    assert cli.main(["proposals", "show", a]) == 0
    out = capsys.readouterr().out
    assert a in out and "line1" in out and "pending" in out


def test_show_rejects_traversal_and_bad_ids(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config.ensure_layout(root)
    (root / "policy.json").write_text("{}")
    for bad in ["../policy", "../../etc/passwd", "x", ""]:
        assert cli.main(["proposals", "show", bad]) == cli.EXIT_DENIED
        assert "invalid proposal id" in capsys.readouterr().err


def test_show_unknown_id(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config.ensure_layout(root)
    rc = cli.main(["proposals", "show", "11111111-1111-4111-8111-111111111111"])
    assert rc == cli.EXIT_DENIED
    assert "not found" in capsys.readouterr().err


def test_dismiss_and_mark_done_terminal(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, b = mk(root), mk(root)
    assert cli.main(["proposals", "dismiss", a]) == 0
    assert cli.main(["proposals", "mark-done", b]) == 0
    assert proposals.get_proposal(root, a)["status"] == "dismissed"
    d = proposals.get_proposal(root, b)
    assert d["status"] == "done" and "status_changed_at" in d
    capsys.readouterr()
    for pid in (a, b):
        for cmd in ("dismiss", "mark-done"):
            assert cli.main(["proposals", cmd, pid]) == cli.EXIT_OPERATIONAL
            assert "terminal" in capsys.readouterr().err
