"""Inert action proposals (REQ-012).

A proposal is data for a human to read. Nothing here reads a proposal as policy
or passes its content to a process. Status changes happen only through the CLI
(``set_status``); no MCP tool is wired to it.

Concurrency guarantee (what is and is not provided): the pending-count check and
the ``O_EXCL`` create run inside one exclusive ``flock`` on ``state/proposals.lock``,
as does every status change, so the 200 cap is exact among processes that use
this module on a local filesystem with working ``flock``. It is NOT enforced
against writers that bypass this module, nor on filesystems without flock
semantics (e.g. some NFS setups); there the worst case is a small overshoot.
Unparseable proposal files count as pending (conservative).
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import unicodedata
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wayguard import config

MAX_PENDING = 200
MAX_GOAL = 500
MAX_REASON = 1000
MAX_SUMMARY = 1000
MAX_SERVER_ID = 256
PROPOSAL_LIMIT = "proposal_limit"
ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TERMINAL = ("dismissed", "done")


class ProposalInputError(ValueError):
    """Invalid proposal field; ``reason`` is fixed text (never echoes the value)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ProposalLimitError(Exception):
    code = PROPOSAL_LIMIT


class InvalidProposalIdError(ValueError):
    pass


class ProposalNotFoundError(LookupError):
    pass


class ProposalStateError(Exception):
    """Proposal is already in a terminal state."""


def _check_text(name: str, value: object, max_len: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ProposalInputError(f"{name}: must be a string")
    if not value and not allow_empty:
        raise ProposalInputError(f"{name}: must not be empty")
    if len(value) > max_len:
        raise ProposalInputError(f"{name}: exceeds {max_len} characters")
    for ch in value:
        if ch != "\n" and unicodedata.category(ch) == "Cc":
            raise ProposalInputError(f"{name}: contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ProposalInputError(f"{name}: not valid UTF-8 text") from None
    return value


def _check_id(proposal_id: str) -> str:
    if not isinstance(proposal_id, str) or not ID_RE.fullmatch(proposal_id):
        raise InvalidProposalIdError("invalid proposal id")
    return proposal_id


def _path(root: Path, proposal_id: str) -> Path:
    return config.proposals_dir(root) / f"{_check_id(proposal_id)}.json"


@contextmanager
def _locked(root: Path) -> Iterator[None]:
    config.ensure_layout(root)
    fd = os.open(
        config.state_dir(root) / "proposals.lock", os.O_RDWR | os.O_CREAT, config.FILE_MODE
    )
    try:
        os.fchmod(fd, config.FILE_MODE)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _read(path: Path) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("not an object")
    return data


def _files(root: Path) -> list[Path]:
    d = config.proposals_dir(root)
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.suffix == ".json" and ID_RE.fullmatch(p.stem))


def _count_pending(root: Path) -> int:
    n = 0
    for p in _files(root):
        try:
            status = _read(p).get("status")
        except (OSError, ValueError):
            status = "pending"  # unreadable: count conservatively
        if status not in TERMINAL:
            n += 1
    return n


def create_proposal(
    root: Path,
    *,
    server_id: str,
    goal: str,
    reason: str,
    suggested_action_summary: str | None = None,
    server_known: bool,
) -> str:
    """Validate, enforce the cap, create ``proposals/<uuid4>.json`` (0600); return the id.

    Raises ``ProposalInputError`` or ``ProposalLimitError`` (code ``proposal_limit``).
    Spawns no process and touches no policy.
    """
    record: dict[str, Any] = {
        "server_id": _check_text("server_id", server_id, MAX_SERVER_ID),
        "server_known": bool(server_known),
        "goal": _check_text("goal", goal, MAX_GOAL),
        "reason": _check_text("reason", reason, MAX_REASON),
        "suggested_action_summary": (
            None
            if suggested_action_summary is None
            else _check_text("suggested_action_summary", suggested_action_summary, MAX_SUMMARY)
        ),
    }
    with _locked(root):
        if _count_pending(root) >= MAX_PENDING:
            raise ProposalLimitError(PROPOSAL_LIMIT)
        pid = str(uuid.uuid4())
        full = {
            "id": pid,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            **record,
            "status": "pending",
        }
        fd = os.open(
            _path(root, pid),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            config.FILE_MODE,
        )
        try:
            os.fchmod(fd, config.FILE_MODE)
            data = json.dumps(full, indent=2).encode("utf-8")
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
    return pid


def get_proposal(root: Path, proposal_id: str) -> dict[str, Any]:
    path = _path(root, proposal_id)
    try:
        return _read(path)
    except (OSError, ValueError):
        raise ProposalNotFoundError("proposal not found") from None


def list_proposals(root: Path, *, include_all: bool = False) -> list[dict[str, Any]]:
    """Readable proposals sorted by ``created_at``; pending only unless ``include_all``."""
    out: list[dict[str, Any]] = []
    for p in _files(root):
        try:
            d = _read(p)
        except (OSError, ValueError):
            continue
        if include_all or d.get("status") == "pending":
            out.append(d)
    out.sort(key=lambda d: str(d.get("created_at", "")))
    return out


def set_status(root: Path, proposal_id: str, new_status: str) -> dict[str, Any]:
    """pending -> dismissed|done, atomically, adding ``status_changed_at``.

    CLI-only by design. Raises ``ProposalStateError`` if already terminal.
    """
    if new_status not in TERMINAL:
        raise ValueError("new_status must be 'dismissed' or 'done'")
    path = _path(root, proposal_id)
    with _locked(root):
        try:
            d = _read(path)
        except (OSError, ValueError):
            raise ProposalNotFoundError("proposal not found") from None
        if d.get("status") != "pending":
            raise ProposalStateError("proposal is already in a terminal state")
        d["status"] = new_status
        d["status_changed_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        config.atomic_write(path, json.dumps(d, indent=2).encode("utf-8"), config.FILE_MODE)
    return d
