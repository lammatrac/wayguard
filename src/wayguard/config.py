"""Filesystem layout, permission checks and atomic writes (REQ-001).

The configuration root is derived from the account's home directory only; it is
never taken from the CWD, an environment variable or MCP input.
"""

import os
import pwd
import stat
import tempfile
from pathlib import Path

# CON-009: hard ceilings. Nothing may raise these.
MAX_TIMEOUT_SECONDS = 120
MAX_STREAM_BYTES = 256 * 1024
MAX_STREAM_LINES = 2000
MAX_CONCURRENCY = 8

DIR_MODE = 0o700
FILE_MODE = 0o600


class PolicyPermissionError(Exception):
    """The policy file fails a REQ-001 permission/ownership check (fail closed)."""


def default_root() -> Path:
    """``~/.config/wayguard`` of the current UID (passwd entry, not $HOME)."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".config" / "wayguard"


def policy_path(root: Path) -> Path:
    return root / "policy.json"


def audit_path(root: Path) -> Path:
    return root / "audit.jsonl"


def proposals_dir(root: Path) -> Path:
    return root / "proposals"


def state_dir(root: Path) -> Path:
    return root / "state"


def ensure_layout(root: Path) -> None:
    """Create the root, ``proposals/`` and ``state/`` with mode 0700 (tightening if present)."""
    for d in (root, proposals_dir(root), state_dir(root)):
        d.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
        d.chmod(DIR_MODE)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = FILE_MODE) -> None:
    """Write ``data`` via a temp file in the same directory, fsync, then ``os.replace``."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as f:
                fd = -1
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        finally:
            if fd != -1:
                os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(path.parent)


def check_policy_file(path: Path, root: Path) -> Path:
    """Validate the policy file's location and permissions; return its resolved path.

    Raises PolicyPermissionError if it is missing, not a regular file, a symlink
    resolving outside ``root``, not owned by the current UID, or writable by
    group or other.
    """
    if not path.is_symlink() and not path.exists():
        raise PolicyPermissionError("policy file is missing")
    resolved = path.resolve()
    if path.is_symlink():
        root_resolved = root.resolve()
        if root_resolved != resolved and root_resolved not in resolved.parents:
            raise PolicyPermissionError("policy is a symlink resolving outside the config root")
    try:
        st = resolved.stat()
    except OSError:
        raise PolicyPermissionError("policy file is missing or unreadable") from None
    if not stat.S_ISREG(st.st_mode):
        raise PolicyPermissionError("policy is not a regular file")
    if st.st_uid != os.getuid():
        raise PolicyPermissionError("policy is not owned by the current user (owner mismatch)")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PolicyPermissionError("policy is writable by group or other")
    return resolved
