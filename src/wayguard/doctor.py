"""``wayguard-mcp doctor``: offline environment checks (REQ-014).

Never prints ``ssh -G`` output (CON-006): its stdout/stderr go to DEVNULL and only the
exit status is turned into "resolvable: yes/no". No alias, path of a key or host is shown.
"""

import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from wayguard import command, config
from wayguard import policy as policy_mod
from wayguard.command import TRUSTED_SSH_PATHS

EXIT_OK = 0
EXIT_INVALID_POLICY = 2
EXIT_DENIED = 3
EXIT_OPERATIONAL = 4
SSH_G_TIMEOUT_SECONDS = 10
MIN_PYTHON = (3, 11)


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.lstat().st_mode)


def _check_modes(root: Path, out: Callable[[str], None]) -> bool:
    ok = True
    targets = [(root, config.DIR_MODE), (config.proposals_dir(root), config.DIR_MODE),
               (config.state_dir(root), config.DIR_MODE),
               (config.policy_path(root), config.FILE_MODE)]  # fmt: skip
    for path, want in targets:
        label = path.name if path != root else "config root"
        try:
            got = _mode(path)
        except OSError:
            out(f"FAIL path {label}: missing (run `wayguard-mcp init`)")
            ok = False
            continue
        if got & 0o077:
            out(f"FAIL mode {label}: {got:04o} is group/other accessible (expected {want:04o})")
            ok = False
        else:
            out(f"ok   mode {label}: {got:04o}")
    return ok


def _resolvable(ssh: str, alias: str) -> bool:
    try:
        r = subprocess.run(
            [ssh, "-G", "--", alias],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=command.child_env(),
            timeout=SSH_G_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def run_doctor(
    root: Path,
    *,
    ssh_candidates: Sequence[str] | None = None,
    out: Callable[[str], None] = print,
) -> int:
    """Run all checks, print a report, return a CLI exit code."""
    code = EXIT_OK
    if sys.version_info >= MIN_PYTHON:
        out(f"ok   python {sys.version_info.major}.{sys.version_info.minor}")
    else:
        out("FAIL python: 3.11 or newer is required")
        code = EXIT_OPERATIONAL

    ssh: str | None
    try:
        cands = TRUSTED_SSH_PATHS if ssh_candidates is None else ssh_candidates
        ssh = command.discover_ssh(_candidates=cands)
        out(f"ok   ssh: trusted binary found at {ssh}")
    except command.SshNotFoundError:
        ssh = None
        out("FAIL ssh: no trusted ssh binary found")
        code = EXIT_OPERATIONAL

    if not _check_modes(root, out):
        code = code or EXIT_OPERATIONAL

    pol: policy_mod.Policy | None = None
    try:
        pol = policy_mod.load_policy(root)
        out(f"ok   policy: valid ({len(pol.servers)} server(s))")
    except config.PolicyPermissionError:
        out("FAIL policy: file is missing, unreadable or has unsafe permissions/mode")
        code = EXIT_DENIED
    except policy_mod.PolicyInvalidError as e:
        out("FAIL policy: invalid")
        for line in e.errors:
            out(f"       {line}")
        code = EXIT_INVALID_POLICY

    if pol is not None and ssh is not None:
        for sid, server in pol.servers.items():
            ok = _resolvable(ssh, server.ssh_alias)
            out(f"ok   server {sid}: resolvable: yes" if ok
                else f"WARN server {sid}: resolvable: no")  # fmt: skip
    out("doctor: all checks passed" if code == EXIT_OK else "doctor: problems found")
    return code


