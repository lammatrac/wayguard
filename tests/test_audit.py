import json
import multiprocessing
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from wayguard import audit, config
from wayguard.validation import normalize_params

REQUIRED = {
    "ts", "event", "correlation_id", "server_id", "action_id", "params", "status",
    "exit_code", "duration_ms", "stdout_bytes", "stderr_bytes", "truncated", "timed_out",
    "reason_code",
}  # fmt: skip


def lines(root: Path) -> list[dict[str, object]]:
    return [json.loads(x) for x in config.audit_path(root).read_text().splitlines()]


def end_kwargs(cid: str = "c1") -> dict[str, object]:
    return dict(
        correlation_id=cid, server_id="s", action_id="a", params_summary={"n": 1},
        status="ok", exit_code=0, duration_ms=5, stdout_bytes=3, stderr_bytes=0,
        truncated=False, timed_out=False,
    )  # fmt: skip


def test_events_have_required_fields_and_mode(tmp_path: Path) -> None:
    root = tmp_path / "w"
    sink = audit.FileAuditSink(root)
    sink.record_start(correlation_id="c1", server_id="s", action_id="a", params_summary={"n": 1})
    sink.record_end(**end_kwargs())  # type: ignore[arg-type]
    sink.record_denied(
        correlation_id="c2", server_id=None, action_id=None, params_summary={},
        reason_code="unknown_server",
    )  # fmt: skip
    ev = lines(root)
    assert [e["event"] for e in ev] == ["start", "end", "denied"]
    for e in ev:
        assert set(e) == REQUIRED
        datetime.fromisoformat(str(e["ts"]))
    assert ev[2]["reason_code"] == "unknown_server"
    assert ev[2]["status"] == "denied"
    assert ev[1]["status"] == "ok"
    assert stat.S_IMODE(config.audit_path(root).stat().st_mode) == 0o600


def test_params_are_normalized_only(tmp_path: Path) -> None:
    root = tmp_path / "w"
    sink = audit.FileAuditSink(root)
    from wayguard.policy import ParameterSpec  # noqa: F401

    summary = normalize_params({"path": "/etc/secret-host"})
    sink.record_start(correlation_id="c", server_id="s", action_id="a", params_summary=summary)
    text = config.audit_path(root).read_text()
    assert "secret-host" not in text
    assert "sha256_8" in text


def test_sink_never_raises(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    sink = audit.FileAuditSink(f / "sub")  # parent is a file -> OSError internally
    sink.record_start(correlation_id="c", server_id="s", action_id="a", params_summary={})


def _worker(args: tuple[str, int]) -> None:
    root, n = args
    sink = audit.FileAuditSink(Path(root))
    for i in range(50):
        sink.record_start(
            correlation_id=f"{n}-{i}", server_id="s", action_id="a",
            params_summary={"pad": "x" * 3000},
        )  # fmt: skip


def test_concurrent_appends_keep_lines_intact(tmp_path: Path) -> None:
    root = tmp_path / "w"
    audit.FileAuditSink(root)  # create layout
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(6) as pool:
        pool.map(_worker, [(str(root), n) for n in range(6)])
    ev = lines(root)  # every line must parse
    assert len(ev) == 300
    assert len({e["correlation_id"] for e in ev}) == 300


def write_ev(root: Path, ts: datetime | str, cid: str) -> None:
    p = config.audit_path(root)
    t = ts if isinstance(ts, str) else ts.isoformat()
    with p.open("a") as f:
        f.write(json.dumps({"ts": t, "event": "start", "correlation_id": cid}) + "\n")


def test_prune_removes_only_old_and_keeps_mode(tmp_path: Path) -> None:
    root = tmp_path / "w"
    audit.FileAuditSink(root)
    now = datetime.now(UTC)
    write_ev(root, now - timedelta(days=40), "old")
    write_ev(root, now - timedelta(days=29), "new")
    write_ev(root, "garbage", "undatable")
    config.audit_path(root).chmod(0o600)
    assert audit.prune(root, older_than_days=30, now=now) == 1
    assert [e["correlation_id"] for e in lines(root)] == ["new", "undatable"]
    assert stat.S_IMODE(config.audit_path(root).stat().st_mode) == 0o600


def test_prune_missing_file_is_zero(tmp_path: Path) -> None:
    assert audit.prune(tmp_path / "w", older_than_days=1) == 0


def test_prune_rejects_days_below_one(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        audit.prune(tmp_path / "w", older_than_days=0)


def test_append_after_prune_lands_in_new_file(tmp_path: Path) -> None:
    root = tmp_path / "w"
    sink = audit.FileAuditSink(root)
    write_ev(root, datetime.now(UTC) - timedelta(days=90), "old")
    audit.prune(root, older_than_days=1)
    sink.record_start(correlation_id="after", server_id="s", action_id="a", params_summary={})
    assert [e["correlation_id"] for e in lines(root)] == ["after"]


def test_tail_returns_last_n(tmp_path: Path) -> None:
    root = tmp_path / "w"
    sink = audit.FileAuditSink(root)
    for i in range(5):
        sink.record_start(correlation_id=f"c{i}", server_id="s", action_id="a", params_summary={})
    t = audit.tail(root, 2)
    assert [json.loads(x)["correlation_id"] for x in t] == ["c3", "c4"]
    assert audit.tail(tmp_path / "none", 3) == []
