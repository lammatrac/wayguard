import asyncio
import json
import os
import stat
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import CallToolResult

from tests.test_policy import add_server, dump, good
from wayguard import config, mcp_server
from wayguard.command import discover_ssh

TOOLS = {"list_servers", "list_actions", "run_action", "propose_action", "get_policy_status"}


def setup_root(tmp_path: Path, data: bytes | None = None, concurrency: int = 2) -> Path:
    root = tmp_path / "cfg"
    config.ensure_layout(root)
    if data is None:
        d = good()
        d["defaults"]["max_concurrent_actions"] = concurrency
        data = dump(d)
    config.atomic_write(config.policy_path(root), data)
    return root


def stub(tmp_path: Path, body: str) -> str:
    p = tmp_path / "ssh"
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return discover_ssh(_candidates=[str(p)])


def drive(root: Path, fn: Callable[[Any], Awaitable[Any]], ssh: str | None = None) -> Any:
    async def go() -> Any:
        server = mcp_server.create_server(root, ssh_path=ssh)
        async with create_connected_server_and_client_session(server) as s:
            return await fn(s)

    return asyncio.run(go())


def sc(r: CallToolResult) -> dict[str, Any]:
    assert r.structuredContent is not None
    return r.structuredContent


def audit_events(root: Path) -> list[dict[str, Any]]:
    p = config.audit_path(root)
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


RUN = {"server_id": "prod", "action_id": "tail", "parameters": {"lines": 3}}


def test_tools_list_exactly_five_with_strict_schemas(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    tools = drive(root, lambda s: s.list_tools()).tools
    assert {t.name for t in tools} == TOOLS

    def strict(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            for v in node.values():
                strict(v)

    for t in tools:
        strict(t.inputSchema)
    run = next(t for t in tools if t.name == "run_action")
    assert set(run.inputSchema["required"]) == {"server_id", "action_id", "parameters"}


def test_listing_never_leaks_alias(tmp_path: Path) -> None:
    root = setup_root(tmp_path)

    async def fn(s: Any) -> list[str]:
        out = [
            json.dumps(sc(await s.call_tool("list_servers", {}))),
            json.dumps(sc(await s.call_tool("get_policy_status", {}))),
            json.dumps(sc(await s.call_tool("list_actions", {"server_id": "prod"}))),
        ]
        return out

    outs = drive(root, fn)
    for o in outs:
        assert "prod-debug" not in o
    ls = json.loads(outs[0])
    assert ls["servers"] == [{"server_id": "prod", "description": "Production", "action_count": 2}]
    acts = json.loads(outs[2])["actions"]
    tail = next(a for a in acts if a["action_id"] == "tail")
    assert tail["timeout_seconds"] == 10 and tail["max_output_bytes"] == 1000
    assert tail["parameters"]["lines"]["maximum"] == 200


def test_status_valid_and_enforcement(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    st = sc(drive(root, lambda s: s.call_tool("get_policy_status", {})))
    assert st["validation"] == "valid" and st["errors"] == []
    assert st["enforcement"] == "local-policy-only"
    assert st["policy_changed_since_load"] is False
    assert st["schema_version"] == 1 and st["loaded_at"]


def test_list_actions_denies_unknown_and_disabled(tmp_path: Path) -> None:
    d = good()
    add_server(d, "off", enabled=False, ssh_alias="x", actions={})
    root = setup_root(tmp_path, dump(d))

    async def fn(s: Any) -> list[dict[str, Any]]:
        return [
            sc(await s.call_tool("list_actions", {"server_id": "nope"})),
            sc(await s.call_tool("list_actions", {"server_id": "off"})),
            sc(await s.call_tool("list_actions", {"server_id": "prod", "x": 1})),
        ]

    for r in drive(root, fn):
        assert r["status"] == "denied"


def test_run_action_ok_untrusted_framing_and_audit(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    ssh = stub(tmp_path, "echo hello")
    r = drive(root, lambda s: s.call_tool("run_action", RUN), ssh)
    d = sc(r)
    assert d["status"] == "ok" and d["stdout"].strip() == "hello"
    assert d["enforcement"] == "local-policy-only"
    assert d["untrusted_output_notice"]
    text = r.content[0].text  # type: ignore[union-attr]
    assert "BEGIN UNTRUSTED REMOTE OUTPUT" in text and "hello" in text
    ev = [e["event"] for e in audit_events(root)]
    assert ev == ["start", "end"]
    assert "prod-debug" not in json.dumps(d)


def test_run_action_denials_audited_and_nothing_spawned(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    marker = tmp_path / "ran"
    ssh = stub(tmp_path, f"touch {marker}")

    async def fn(s: Any) -> list[dict[str, Any]]:
        return [
            sc(await s.call_tool("run_action", {**RUN, "server_id": "zzz"})),
            sc(await s.call_tool("run_action", {**RUN, "extra": 1})),
            sc(await s.call_tool("run_action", {**RUN, "parameters": {"lines": 3, "q": 1}})),
            sc(await s.call_tool("run_action", {"server_id": "prod"})),
        ]

    res = drive(root, fn, ssh)
    assert [r["status"] for r in res] == ["denied"] * 4
    assert res[0]["reason_code"] == "unknown_server"
    assert res[1]["reason_code"] == "extra_field"
    assert not marker.exists()
    assert all(e["event"] == "denied" for e in audit_events(root))
    assert len(audit_events(root)) == 4


def test_deny_all_mode(tmp_path: Path) -> None:
    root = setup_root(tmp_path, b"{not json")
    marker = tmp_path / "ran"
    ssh = stub(tmp_path, f"touch {marker}")

    async def fn(s: Any) -> dict[str, Any]:
        tools = {t.name for t in (await s.list_tools()).tools}
        return {
            "tools": tools,
            "status": sc(await s.call_tool("get_policy_status", {})),
            "servers": sc(await s.call_tool("list_servers", {})),
            "actions": sc(await s.call_tool("list_actions", {"server_id": "prod"})),
            "run": sc(await s.call_tool("run_action", RUN)),
            "prop": sc(
                await s.call_tool("propose_action", {"server_id": "a", "goal": "g", "reason": "r"})
            ),
        }

    o = drive(root, fn, ssh)
    assert o["tools"] == TOOLS
    assert o["status"]["validation"] == "invalid" and o["status"]["errors"]
    assert o["servers"]["servers"] == []
    assert o["actions"]["status"] == "denied" and o["actions"]["reason_code"] == "policy_invalid"
    assert o["run"]["status"] == "denied" and o["run"]["reason_code"] == "policy_invalid"
    assert o["prop"]["status"] == "recorded"
    assert not marker.exists()


def test_missing_policy_is_deny_all(tmp_path: Path) -> None:
    root = tmp_path / "cfg"
    config.ensure_layout(root)
    st = sc(drive(root, lambda s: s.call_tool("get_policy_status", {})))
    assert st["validation"] == "invalid" and st["errors"]


def test_policy_lifecycle_no_hot_reload(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    ssh = stub(tmp_path, "echo hi")

    async def fn(s: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        d = good()
        d["projects"] = {}
        config.atomic_write(config.policy_path(root), dump(d))
        run = sc(await s.call_tool("run_action", RUN))
        st = sc(await s.call_tool("get_policy_status", {}))
        return run, st

    run, st = drive(root, fn, ssh)
    assert run["status"] == "ok"
    assert st["policy_changed_since_load"] is True


def test_busy_immediate_and_audited(tmp_path: Path) -> None:
    root = setup_root(tmp_path, concurrency=1)
    ssh = stub(tmp_path, "sleep 2; echo done")

    async def fn(s: Any) -> tuple[dict[str, Any], float, dict[str, Any]]:
        first = asyncio.create_task(s.call_tool("run_action", RUN))
        await asyncio.sleep(0.5)
        t = time.monotonic()
        second = sc(await s.call_tool("run_action", RUN))
        dt = time.monotonic() - t
        return second, dt, sc(await first)

    second, dt, first = drive(root, fn, ssh)
    assert second["status"] == "busy" and dt < 1.0
    assert first["status"] == "ok"
    denied = [e for e in audit_events(root) if e["event"] == "denied"]
    assert len(denied) == 1 and denied[0]["reason_code"] == "concurrency_limit"
    assert denied[0]["status"] == "denied"


def test_cancellation_kills_child_and_releases_gate(tmp_path: Path) -> None:
    root = setup_root(tmp_path, concurrency=1)
    pidf = tmp_path / "pid"
    ssh = stub(tmp_path, f"echo $$ > {pidf}; exec sleep 30")

    async def go() -> None:
        svc = mcp_server.WayguardService(root, ssh_path=ssh)
        task = asyncio.create_task(svc.call_tool("run_action", RUN))
        for _ in range(50):
            if pidf.exists() and pidf.read_text().strip():
                break
            await asyncio.sleep(0.1)
        pid = int(pidf.read_text())
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        assert svc.gate.try_acquire()  # released

    asyncio.run(go())
    assert any(e.get("status") == "cancelled" for e in audit_events(root))


def test_propose_action_writes_proposal_policy_untouched(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    before = config.policy_path(root).read_bytes()
    ssh = stub(tmp_path, "echo hi")
    args = {"server_id": "newhost", "goal": "see disk usage", "reason": "need df"}

    async def fn(s: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        p = sc(await s.call_tool("propose_action", args))
        bad = sc(await s.call_tool("propose_action", {**args, "extra": 1}))
        run = sc(
            await s.call_tool(
                "run_action", {"server_id": "newhost", "action_id": "df", "parameters": {}}
            )
        )
        tools = await s.list_tools()
        assert {t.name for t in tools.tools} == TOOLS
        return p, bad, run, {}

    p, bad, run, _ = drive(root, fn, ssh)
    assert p["status"] == "recorded"
    assert f"wayguard-mcp proposals show {p['proposal_id']}" in p["review"]
    assert bad["status"] == "denied"
    assert run["status"] == "denied"
    assert config.policy_path(root).read_bytes() == before
    f = config.proposals_dir(root) / f"{p['proposal_id']}.json"
    data = json.loads(f.read_text())
    assert data["server_known"] is False and data["status"] == "pending"


def test_propose_action_limit_denied_and_audited(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    from wayguard import proposals

    for _ in range(proposals.MAX_PENDING if hasattr(proposals, "MAX_PENDING") else 200):
        proposals.create_proposal(root, server_id="a", goal="g", reason="r", server_known=False)
    r = sc(
        drive(
            root,
            lambda s: s.call_tool("propose_action", {"server_id": "a", "goal": "g", "reason": "r"}),
        )
    )
    assert r["status"] == "denied" and r["reason_code"] == "proposal_limit"
    assert audit_events(root)[-1]["reason_code"] == "proposal_limit"


def test_no_tool_changes_proposal_status(tmp_path: Path) -> None:
    src = Path(mcp_server.__file__).read_text()
    assert "set_status" not in src


def test_serve_subprocess_stdout_hygiene(tmp_path: Path) -> None:
    root = setup_root(tmp_path)
    env = {"PATH": os.environ.get("PATH", ""), "WAYGUARD_TEST_ROOT": str(root)}
    code = (
        "import sys; from wayguard import cli, config; from pathlib import Path;"
        f"cli.default_root = lambda: Path({str(root)!r});"
        "sys.exit(cli.main(['serve']))"
    )
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "get_policy_status", "arguments": {}},
        },
    ]
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )
    assert proc.stdin is not None and proc.stdout is not None
    lines: list[str] = []
    for m in msgs:
        proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        if "id" in m:
            lines.append(proc.stdout.readline())
    proc.stdin.close()  # shutdown
    rest = proc.stdout.read()
    err = proc.stderr.read() if proc.stderr else ""
    rc = proc.wait(timeout=30)
    assert rest.strip() == ""
    parsed = [json.loads(x) for x in lines]
    assert all(m["jsonrpc"] == "2.0" for m in parsed)
    assert {t["name"] for t in parsed[1]["result"]["tools"]} == TOOLS
    status = parsed[2]["result"]["structuredContent"]
    assert status["validation"] == "valid"
    assert "wayguard-mcp serve" in err
    assert rc == 0


def test_list_servers_description_mentions_projects() -> None:
    tool = next(t for t in mcp_server.tool_definitions() if t.name == "list_servers")
    assert "project" in (tool.description or "")
