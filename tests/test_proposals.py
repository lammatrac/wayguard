import json
import multiprocessing
import stat
from pathlib import Path

import pytest

from wayguard import config, proposals


def mk(root: Path, **kw: object) -> str:
    args: dict[str, object] = dict(server_id="web1", goal="g", reason="r", server_known=True)
    args.update(kw)
    return proposals.create_proposal(root, **args)  # type: ignore[arg-type]


def test_create_writes_0600_uuid4_file(tmp_path: Path) -> None:
    pid = mk(tmp_path, suggested_action_summary="s")
    assert proposals.ID_RE.fullmatch(pid)
    p = config.proposals_dir(tmp_path) / f"{pid}.json"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    d = json.loads(p.read_text())
    assert d["status"] == "pending" and d["id"] == pid and d["server_known"] is True
    assert set(d) == {"id", "created_at", "server_id", "server_known", "goal", "reason",
                      "suggested_action_summary", "status"}  # fmt: skip
    assert len(list(config.proposals_dir(tmp_path).glob("*.json"))) == 1


@pytest.mark.parametrize(
    "kw",
    [
        {"goal": "x" * 501},
        {"reason": "x" * 1001},
        {"suggested_action_summary": "x" * 1001},
        {"goal": "a\x00b"},
        {"reason": "tab\there"},
        {"goal": "esc\x1b[31m"},
        {"server_id": ""},
        {"server_id": "x" * 257},
        {"goal": 5},
    ],
)
def test_create_rejects_bad_input(tmp_path: Path, kw: dict[str, object]) -> None:
    with pytest.raises(proposals.ProposalInputError):
        mk(tmp_path, **kw)
    assert not list(config.proposals_dir(tmp_path).glob("*.json"))


def test_newline_allowed_and_unknown_server_ok(tmp_path: Path) -> None:
    pid = mk(tmp_path, goal="a\nb", server_id="nonexistent", server_known=False)
    assert proposals.get_proposal(tmp_path, pid)["server_known"] is False


def test_cap_200_pending_then_proposal_limit(tmp_path: Path) -> None:
    for _ in range(200):
        mk(tmp_path)
    with pytest.raises(proposals.ProposalLimitError) as e:
        mk(tmp_path)
    assert e.value.code == "proposal_limit"
    assert len(list(config.proposals_dir(tmp_path).glob("*.json"))) == 200


def test_terminal_proposals_do_not_count_toward_cap(tmp_path: Path) -> None:
    ids = [mk(tmp_path) for _ in range(200)]
    proposals.set_status(tmp_path, ids[0], "dismissed")
    mk(tmp_path)  # frees one slot
    with pytest.raises(proposals.ProposalLimitError):
        mk(tmp_path)


def _w(args: tuple[str, int]) -> str:
    root, _ = args
    try:
        mk(Path(root))
        return "ok"
    except proposals.ProposalLimitError:
        return "limit"


def test_cap_holds_under_concurrent_processes(tmp_path: Path) -> None:
    config.ensure_layout(tmp_path)
    for _ in range(190):
        mk(tmp_path)
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(8) as pool:
        res = pool.map(_w, [(str(tmp_path), i) for i in range(40)])
    assert res.count("ok") == 10
    assert len(list(config.proposals_dir(tmp_path).glob("*.json"))) == 200


def test_set_status_lifecycle(tmp_path: Path) -> None:
    a, b = mk(tmp_path), mk(tmp_path)
    d = proposals.set_status(tmp_path, a, "dismissed")
    assert d["status"] == "dismissed" and "status_changed_at" in d
    d = proposals.set_status(tmp_path, b, "done")
    assert d["status"] == "done" and "status_changed_at" in d
    p = config.proposals_dir(tmp_path) / f"{a}.json"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    for pid in (a, b):
        for new in ("dismissed", "done"):
            with pytest.raises(proposals.ProposalStateError):
                proposals.set_status(tmp_path, pid, new)


def test_set_status_rejects_pending_target(tmp_path: Path) -> None:
    pid = mk(tmp_path)
    with pytest.raises(ValueError):
        proposals.set_status(tmp_path, pid, "pending")


def test_unknown_and_malformed_ids(tmp_path: Path) -> None:
    config.ensure_layout(tmp_path)
    with pytest.raises(proposals.ProposalNotFoundError):
        proposals.get_proposal(tmp_path, "11111111-1111-4111-8111-111111111111")
    for bad in ["../../policy", "../x", "", "A" * 36, "11111111-1111-1111-8111-111111111111",
                "11111111-1111-4111-8111-11111111111G", "11111111-1111-4111-8111-111111111111\n"]:  # fmt: skip
        with pytest.raises(proposals.InvalidProposalIdError):
            proposals.get_proposal(tmp_path, bad)
        with pytest.raises(proposals.InvalidProposalIdError):
            proposals.set_status(tmp_path, bad, "done")


def test_list_pending_default_and_all(tmp_path: Path) -> None:
    a, b = mk(tmp_path), mk(tmp_path)
    proposals.set_status(tmp_path, a, "done")
    assert [d["id"] for d in proposals.list_proposals(tmp_path)] == [b]
    assert {d["id"] for d in proposals.list_proposals(tmp_path, include_all=True)} == {a, b}


def test_list_ignores_stray_files(tmp_path: Path) -> None:
    mk(tmp_path)
    (config.proposals_dir(tmp_path) / "notes.txt").write_text("x")
    (config.proposals_dir(tmp_path) / "bad.json").write_text("x")
    assert len(proposals.list_proposals(tmp_path, include_all=True)) == 1


def test_symlinked_proposal_not_followed(tmp_path: Path) -> None:
    config.ensure_layout(tmp_path)
    secret = tmp_path / "secret.json"
    secret.write_text('{"status":"pending"}')
    pid = "11111111-1111-4111-8111-111111111111"
    (config.proposals_dir(tmp_path) / f"{pid}.json").symlink_to(secret)
    with pytest.raises(proposals.ProposalNotFoundError):
        proposals.get_proposal(tmp_path, pid)
