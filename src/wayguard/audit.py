"""Append-only JSONL audit log (REQ-011).

Metadata only: callers pass ``normalize_params`` output, never raw values, output
text, the remote command, host/user or environment (CON-006).

Locking: all readers/writers take ``flock`` on a *separate* lock file
(``state/audit.lock``), then open ``audit.jsonl`` by path. Locking the log itself
would be unsafe because ``prune`` replaces it (``os.replace``) and a waiting
appender would write into the orphaned inode.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from wayguard import config


def _lock_path(root: Path) -> Path:
    return config.state_dir(root) / "audit.lock"


@contextmanager
def _locked(root: Path, *, exclusive: bool) -> Iterator[None]:
    config.ensure_layout(root)
    fd = os.open(_lock_path(root), os.O_RDWR | os.O_CREAT, config.FILE_MODE)
    try:
        os.fchmod(fd, config.FILE_MODE)
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        os.close(fd)  # closing releases the flock


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


class FileAuditSink:
    """Implements ``validation.AuditSink`` against ``<root>/audit.jsonl``.

    Methods never raise (an audit failure must not turn a denial into an
    execution, nor crash the server); ``append`` is the raising primitive.
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        try:
            config.ensure_layout(root)
        except OSError:
            pass

    def append(self, event: Mapping[str, Any]) -> None:
        line = (json.dumps(event, separators=(",", ":"), sort_keys=False) + "\n").encode("ascii")
        with _locked(self._root, exclusive=True):
            fd = os.open(
                config.audit_path(self._root),
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                config.FILE_MODE,
            )
            try:
                os.fchmod(fd, config.FILE_MODE)
                view = memoryview(line)
                while view:
                    view = view[os.write(fd, view) :]
            finally:
                os.close(fd)

    def _emit(self, **fields: Any) -> None:
        base: dict[str, Any] = {
            "ts": _now_iso(),
            "event": None,
            "correlation_id": None,
            "server_id": None,
            "action_id": None,
            "params": {},
            "status": None,
            "exit_code": None,
            "duration_ms": None,
            "stdout_bytes": None,
            "stderr_bytes": None,
            "truncated": None,
            "timed_out": None,
            "reason_code": None,
        }
        base.update(fields)
        try:
            self.append(base)
        except Exception:  # noqa: BLE001 - never raise into caller
            pass

    def record_denied(
        self,
        *,
        correlation_id: str,
        server_id: str | None,
        action_id: str | None,
        params_summary: Mapping[str, Any],
        reason_code: str,
    ) -> None:
        self._emit(
            event="denied", correlation_id=correlation_id, server_id=server_id,
            action_id=action_id, params=dict(params_summary), status="denied",
            reason_code=reason_code,
        )  # fmt: skip

    def record_start(
        self,
        *,
        correlation_id: str,
        server_id: str,
        action_id: str,
        params_summary: Mapping[str, Any],
    ) -> None:
        self._emit(
            event="start", correlation_id=correlation_id, server_id=server_id,
            action_id=action_id, params=dict(params_summary),
        )  # fmt: skip

    def record_end(
        self,
        *,
        correlation_id: str,
        server_id: str,
        action_id: str,
        params_summary: Mapping[str, Any],
        status: str,
        exit_code: int | None,
        duration_ms: int,
        stdout_bytes: int,
        stderr_bytes: int,
        truncated: bool,
        timed_out: bool,
    ) -> None:
        self._emit(
            event="end", correlation_id=correlation_id, server_id=server_id,
            action_id=action_id, params=dict(params_summary), status=status,
            exit_code=exit_code, duration_ms=duration_ms, stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes, truncated=truncated, timed_out=timed_out,
        )  # fmt: skip


def _read_lines(root: Path) -> list[str]:
    try:
        fd = os.open(config.audit_path(root), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return []
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
        return [ln for ln in f.read().split("\n") if ln]


def tail(root: Path, limit: int = 20) -> list[str]:
    """Last ``limit`` raw JSON lines (shared lock; consistent with appends)."""
    if limit < 1:
        raise ValueError("limit must be >= 1")
    if not config.audit_path(root).exists():
        return []
    with _locked(root, exclusive=False):
        return _read_lines(root)[-limit:]


def _line_ts(line: str) -> datetime | None:
    try:
        ts = json.loads(line)["ts"]
        dt = datetime.fromisoformat(ts)
    except (ValueError, KeyError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def prune(root: Path, *, older_than_days: int, now: datetime | None = None) -> int:
    """Remove lines older than the cutoff; atomic rewrite under the exclusive lock.

    Lines whose timestamp cannot be parsed are kept (never delete what cannot be
    dated). Returns the number of lines removed.
    """
    if older_than_days < 1:
        raise ValueError("older_than_days must be >= 1")
    if not config.audit_path(root).exists():
        return 0
    cutoff = (now or datetime.now(UTC)) - timedelta(days=older_than_days)
    with _locked(root, exclusive=True):
        lines = _read_lines(root)
        kept = [ln for ln in lines if (t := _line_ts(ln)) is None or t >= cutoff]
        removed = len(lines) - len(kept)
        if removed:
            data = ("\n".join(kept) + "\n").encode("utf-8") if kept else b""
            config.atomic_write(config.audit_path(root), data, config.FILE_MODE)
        return removed
