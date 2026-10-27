import os
import stat
from pathlib import Path

import pytest

from wayguard import config


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_paths_derive_from_root(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    assert config.policy_path(root) == root / "policy.json"
    assert config.audit_path(root) == root / "audit.jsonl"
    assert config.proposals_dir(root) == root / "proposals"
    assert config.state_dir(root) == root / "state"


def test_default_root_ignores_env_and_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAYGUARD_POLICY", str(tmp_path / "evil.json"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)
    root = config.default_root()
    assert root.parts[-2:] == (".config", "wayguard")
    assert tmp_path not in root.parents


def test_ensure_layout_creates_0700_dirs(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    old = os.umask(0o000)
    try:
        config.ensure_layout(root)
    finally:
        os.umask(old)
    for d in (root, config.proposals_dir(root), config.state_dir(root)):
        assert d.is_dir()
        assert mode(d) == 0o700


def test_ensure_layout_tightens_existing_dir(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    config.ensure_layout(root)
    assert mode(root) == 0o700


def test_atomic_write_creates_0600_file(tmp_path: Path) -> None:
    target = tmp_path / "f.json"
    old = os.umask(0o000)
    try:
        config.atomic_write(target, b"hello")
    finally:
        os.umask(old)
    assert target.read_bytes() == b"hello"
    assert mode(target) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["f.json"]


def test_atomic_write_replaces_and_leaves_old_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "f.json"
    config.atomic_write(target, b"old")

    def boom(*a: object, **k: object) -> None:
        raise OSError("fsync failed")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        config.atomic_write(target, b"new")
    monkeypatch.undo()
    assert target.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["f.json"]


def test_atomic_write_fsyncs_and_replaces_in_same_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy(src: str | Path, dst: str | Path) -> None:
        calls.append((str(Path(src).parent), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    target = tmp_path / "f.json"
    config.atomic_write(target, b"x")
    assert calls == [(str(tmp_path), str(target))]


def _policy(root: Path, content: bytes = b"{}") -> Path:
    config.ensure_layout(root)
    p = config.policy_path(root)
    config.atomic_write(p, content)
    return p


def test_policy_check_accepts_0600_owned_file(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    p = _policy(root)
    assert config.check_policy_file(p, root) == p


@pytest.mark.parametrize("bad", [0o620, 0o602, 0o660, 0o666, 0o664])
def test_policy_check_refuses_group_or_other_writable(tmp_path: Path, bad: int) -> None:
    root = tmp_path / "wg"
    p = _policy(root)
    p.chmod(bad)
    with pytest.raises(config.PolicyPermissionError, match="writable"):
        config.check_policy_file(p, root)


def test_policy_check_refuses_wrong_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "wg"
    p = _policy(root)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(p).st_uid + 1)
    with pytest.raises(config.PolicyPermissionError, match="owner"):
        config.check_policy_file(p, root)


def test_policy_check_refuses_symlink_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    config.ensure_layout(root)
    outside = tmp_path / "other.json"
    outside.write_bytes(b"{}")
    outside.chmod(0o600)
    config.policy_path(root).symlink_to(outside)
    with pytest.raises(config.PolicyPermissionError, match="symlink"):
        config.check_policy_file(config.policy_path(root), root)


def test_policy_check_allows_symlink_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    config.ensure_layout(root)
    real = root / "state" / "real.json"
    config.atomic_write(real, b"{}")
    config.policy_path(root).symlink_to(real)
    assert config.check_policy_file(config.policy_path(root), root) == real.resolve()


def test_policy_check_refuses_missing_and_non_regular(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    config.ensure_layout(root)
    with pytest.raises(config.PolicyPermissionError, match="missing"):
        config.check_policy_file(config.policy_path(root), root)
    config.policy_path(root).mkdir()
    with pytest.raises(config.PolicyPermissionError, match="regular"):
        config.check_policy_file(config.policy_path(root), root)


def test_hard_ceilings() -> None:
    assert config.MAX_TIMEOUT_SECONDS == 120
    assert config.MAX_STREAM_BYTES == 256 * 1024
    assert config.MAX_STREAM_LINES == 2000
    assert config.MAX_CONCURRENCY == 8
