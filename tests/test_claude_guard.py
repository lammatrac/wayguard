import io
import json
import stat
from pathlib import Path

import pytest

from wayguard import claude_guard as g

# The command a Claude Code session actually used to bypass WayGuard.
OBSERVED_BYPASS = (
    "cd /tmp/scratchpad && for c in www.bild-esim.com_wp www.bild-esim.com_db; do "
    'ssh -o BatchMode=yes wlxuser@142.93.109.102 "docker logs --since 60m --timestamps $c 2>&1" '
    '> $c.log; echo "$c: $(wc -l < $c.log) lines"; done; '
    "ssh -o BatchMode=yes wlxuser@142.93.109.102 'docker logs --since 60m nginx-proxy 2>&1 | grep -c bild-esim'"
)

BLOCKED = [
    OBSERVED_BYPASS,
    "ssh host uptime",
    "ssh",
    "/usr/bin/ssh host",
    "\\ssh host",
    "'ssh' host",
    "s''sh host",
    "ssh.exe host",
    "C:/Windows/System32/OpenSSH/ssh.exe host",
    "cd /x && ssh host",
    "true || ssh host",
    "ls | ssh host cat",
    "echo $(ssh host uptime)",
    'echo "$(ssh host uptime)"',
    "echo `ssh host uptime`",
    "diff <(ssh host cat /etc/hosts) /etc/hosts",
    "bash -c 'ssh host uptime'",
    'sh -lc "cd /; ssh host"',
    "eval 'ssh host'",
    "sudo -u bob ssh host",
    "env FOO=1 ssh host",
    "FOO=1 ssh host",
    "timeout 10 ssh host",
    "nohup ssh host &",
    "xargs -I{} ssh {} uptime < hosts",
    "watch 'ssh host uptime'",
    "find . -name x -exec ssh host \\;",
    "if true; then ssh host; fi",
    "(ssh host)",
    "{ ssh host; }",
    "ls\nssh host",
    "a#b; ssh host",
    "S=ssh; $S host",
    "alias x='ssh host'",
    "scp file host:/tmp",
    "sftp host",
    "sshpass -p x ssh host",
    "autossh -M 0 host",
    "mosh host",
    "pssh -h hosts uptime",
    "ansible all -a uptime",
    "rsync -av ./x host:/tmp/x",
    "rsync -av -e ssh ./x /y",
    "rsync -av --rsh=ssh ./x /y",
    "rsync rsync://host/mod ./x",
    "docker -H ssh://user@host ps",
    "docker --host=ssh://user@host ps",
    "docker context use prod",
    "docker -c prod ps",
    "DOCKER_HOST=ssh://user@host docker ps",
    "export DOCKER_HOST=ssh://user@host",
    "podman --remote ps",
    "GIT_SSH_COMMAND='ssh -i k' git pull",
    "git -c core.sshCommand='ssh host x #' fetch",
    "gcloud compute ssh vm",
    "doctl compute ssh droplet",
    "aws ssm start-session --target i-1",
    "python3 -c 'import paramiko'",
    "unterminated 'quote ; ssh host",
]

ALLOWED = [
    "ls -la",
    "ls ~/.ssh",
    "cat /etc/ssh/sshd_config",
    "ssh-keygen -lf key.pub",
    "ssh-add -l",
    "which ssh",
    "command -v ssh",
    "grep -rn ssh src/",
    "git push origin main",
    "git clone git@github.com:o/r.git",
    'git commit -m "Trac Lam - feat: block direct ssh"',
    'git commit -m "feat(ssh): guard"',
    "docker ps --format '{{.Names}}'",
    "docker logs --since 60m web",
    "docker run -c 512 img",
    "rsync -av ./a/ ./b/",
    "echo 'a # b'",
    "uv run pytest -q",
    "wayguard-mcp doctor",
    "gcloud compute instances list",
]


@pytest.mark.parametrize("cmd", BLOCKED)
def test_blocked(cmd: str) -> None:
    assert g.check_command(cmd) is not None, cmd


@pytest.mark.parametrize("cmd", ALLOWED)
def test_allowed(cmd: str) -> None:
    assert g.check_command(cmd) is None, cmd


def hook(event: object) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    raw = event if isinstance(event, str) else json.dumps(event)
    code = g.run_hook(io.StringIO(raw), out, err)
    return code, out.getvalue(), err.getvalue()


def test_hook_denies_with_guidance() -> None:
    code, out, _ = hook({"tool_name": "Bash", "tool_input": {"command": OBSERVED_BYPASS}})
    assert code == 0
    spec = json.loads(out)["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "deny"
    assert "run_action" in spec["permissionDecisionReason"]
    assert "142.93.109.102" not in spec["permissionDecisionReason"]


def test_hook_allows_silently() -> None:
    assert hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}) == (0, "", "")


def test_hook_ignores_other_tools() -> None:
    assert hook({"tool_name": "Read", "tool_input": {"file_path": "/x"}}) == (0, "", "")


@pytest.mark.parametrize(
    "raw", ["not json", "[]", json.dumps({"tool_name": "Bash", "tool_input": {}})]
)
def test_hook_fails_closed(raw: str) -> None:
    code, out, err = hook(raw)
    assert code == 2 and out == "" and "refused" in err


def test_hook_analysis_error_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: str) -> None:
        raise RuntimeError

    monkeypatch.setattr(g, "check_command", boom)
    code, out, _ = hook({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert code == 0 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


# ---- settings.json install / uninstall / status ----


def settings(isolated_claude_dir: Path) -> Path:
    return isolated_claude_dir / "settings.json"


def test_install_creates_settings(isolated_claude_dir: Path) -> None:
    p = settings(isolated_claude_dir)
    res = g.install(p)
    assert res.changed and res.backup is None
    data = json.loads(p.read_text())
    assert set(g.DENY_RULES) <= set(data["permissions"]["deny"])
    [entry] = data["hooks"]["PreToolUse"]
    assert entry["matcher"] == "Bash"
    assert entry["hooks"][0]["command"] == g.hook_command()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert g.status(p).ok


def test_install_preserves_existing_settings_and_is_idempotent(isolated_claude_dir: Path) -> None:
    p = settings(isolated_claude_dir)
    p.parent.mkdir(parents=True)
    original = {
        "model": "opus",
        "permissions": {"allow": ["Bash(git add *)"], "deny": ["Bash(rm -rf *)"]},
        "hooks": {
            "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "other"}]}]
        },
    }
    p.write_text(json.dumps(original))
    p.chmod(0o644)
    res = g.install(p)
    assert res.changed and res.backup is not None
    assert json.loads(res.backup.read_text()) == original
    data = json.loads(p.read_text())
    assert data["model"] == "opus"
    assert data["permissions"]["allow"] == ["Bash(git add *)"]
    assert data["permissions"]["deny"][0] == "Bash(rm -rf *)"
    assert data["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]
    assert stat.S_IMODE(p.stat().st_mode) == 0o644
    snapshot = p.read_text()
    again = g.install(p)
    assert not again.changed and again.backup is None
    assert p.read_text() == snapshot


def test_install_refreshes_stale_hook_path(isolated_claude_dir: Path) -> None:
    p = settings(isolated_claude_dir)
    p.parent.mkdir(parents=True)
    stale = {"type": "command", "command": f"/old/python -m {g.HOOK_MARKER}"}
    p.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [stale]}]}}))
    assert g.status(p).hook and not g.status(p).current_path
    g.install(p)
    [entry] = json.loads(p.read_text())["hooks"]["PreToolUse"]
    assert entry["hooks"][0]["command"] == g.hook_command()


def test_install_refuses_invalid_json(isolated_claude_dir: Path) -> None:
    p = settings(isolated_claude_dir)
    p.parent.mkdir(parents=True)
    p.write_text("{ not json")
    with pytest.raises(g.GuardConfigError):
        g.install(p)
    assert p.read_text() == "{ not json"


def test_install_follows_symlink(isolated_claude_dir: Path, tmp_path: Path) -> None:
    target = tmp_path / "dotfiles" / "settings.json"
    target.parent.mkdir()
    target.write_text("{}")
    p = settings(isolated_claude_dir)
    p.parent.mkdir(parents=True)
    p.symlink_to(target)
    g.install(p)
    assert p.is_symlink()
    assert g.status(target).ok


def test_uninstall_restores_shape(isolated_claude_dir: Path) -> None:
    p = settings(isolated_claude_dir)
    p.parent.mkdir(parents=True)
    original = {"model": "opus", "permissions": {"allow": ["x"]}}
    p.write_text(json.dumps(original))
    g.install(p)
    assert g.uninstall(p).changed
    assert json.loads(p.read_text()) == original
    assert not g.uninstall(p).changed


def test_uninstall_missing_file_is_noop(isolated_claude_dir: Path) -> None:
    assert g.uninstall(settings(isolated_claude_dir)) == g.Change(False, None)


# ---- CLI / doctor wiring ----


@pytest.fixture
def wg_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from wayguard import cli

    r = tmp_path / "home" / ".config" / "wayguard"
    monkeypatch.setattr(cli, "default_root", lambda: r)
    return r


def test_init_installs_guard_when_claude_present(wg_root: Path, isolated_claude_dir: Path) -> None:
    from wayguard import cli

    isolated_claude_dir.mkdir(parents=True)
    assert cli.main(["init"]) == 0
    assert g.status(settings(isolated_claude_dir)).ok


def test_init_skips_guard_without_claude(wg_root: Path, isolated_claude_dir: Path,
                                         capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    from wayguard import cli

    assert cli.main(["init"]) == 0
    assert not isolated_claude_dir.exists()
    assert "Claude Code not detected" in capsys.readouterr().out


def test_init_no_claude_guard_flag(wg_root: Path, isolated_claude_dir: Path) -> None:
    from wayguard import cli

    isolated_claude_dir.mkdir(parents=True)
    assert cli.main(["init", "--no-claude-guard"]) == 0
    assert not settings(isolated_claude_dir).exists()


def test_rerun_init_still_installs_guard(wg_root: Path, isolated_claude_dir: Path) -> None:
    from wayguard import cli

    assert cli.main(["init"]) == 0  # policy created, Claude Code not yet installed
    isolated_claude_dir.mkdir(parents=True)
    assert cli.main(["init"]) == cli.EXIT_OPERATIONAL  # policy exists: refused as before
    assert g.status(settings(isolated_claude_dir)).ok  # but the guard is added


def test_cli_guard_commands(isolated_claude_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from wayguard import cli

    assert cli.main(["claude-guard", "status"]) == cli.EXIT_DENIED
    assert cli.main(["claude-guard", "install"]) == 0
    assert cli.main(["claude-guard", "status"]) == 0
    assert cli.main(["claude-guard", "uninstall"]) == 0
    assert cli.main(["claude-guard", "status"]) == cli.EXIT_DENIED
    assert "hook missing" in capsys.readouterr().out


def test_cli_guard_invalid_settings(isolated_claude_dir: Path) -> None:
    from wayguard import cli

    isolated_claude_dir.mkdir(parents=True)
    settings(isolated_claude_dir).write_text("[")
    assert cli.main(["claude-guard", "install"]) == cli.EXIT_OPERATIONAL


def test_cli_hook_entry(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from wayguard import cli

    event = {"tool_name": "Bash", "tool_input": {"command": "ssh host"}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    assert cli.main(["hook", g.HOOK_SUBCOMMAND]) == 0
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_command_runs_as_subprocess() -> None:
    import shlex
    import subprocess

    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "scp a host:b"}})
    r = subprocess.run(shlex.split(g.hook_command()), input=event, capture_output=True,
                       text=True, check=False)  # fmt: skip
    assert r.returncode == 0
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_doctor_reports_guard(isolated_claude_dir: Path, tmp_path: Path) -> None:
    from wayguard import doctor

    lines: list[str] = []
    doctor.run_doctor(tmp_path / "none", ssh_candidates=[], out=lines.append)
    assert any(line.startswith("skip claude guard") for line in lines)
    isolated_claude_dir.mkdir(parents=True)
    lines.clear()
    doctor.run_doctor(tmp_path / "none", ssh_candidates=[], out=lines.append)
    assert any(line.startswith("WARN claude guard") for line in lines)
    g.install(settings(isolated_claude_dir))
    lines.clear()
    doctor.run_doctor(tmp_path / "none", ssh_candidates=[], out=lines.append)
    assert any(line.startswith("ok   claude guard") for line in lines)
