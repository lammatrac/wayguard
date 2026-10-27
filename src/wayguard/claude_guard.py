"""Claude Code guard against the direct-SSH bypass (README §1.2, §3.10).

Two halves:

* ``check_command`` / ``run_hook``: a ``PreToolUse`` hook that denies Bash commands
  which open a remote shell (ssh, scp, sftp, rsync to a host, docker over ssh, ...)
  and points the agent at the WayGuard MCP tools instead.
* ``install`` / ``uninstall`` / ``status``: idempotent edits of Claude Code's
  user ``settings.json`` that register the hook and matching ``permissions.deny``
  rules, so ``wayguard-mcp init`` sets this up without manual editing.

This is defense in depth, not a shell parser: a determined same-user process can
still reach a host (a script file, an unknown wrapper). Server-side restriction of
the SSH identity remains the real boundary.
"""

import json
import os
import pwd
import re
import shlex
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from wayguard import config

HOOK_SUBCOMMAND = "claude-pretooluse"
HOOK_MARKER = f"wayguard hook {HOOK_SUBCOMMAND}"
HOOK_TIMEOUT_SECONDS = 10
DENY_RULES = (
    "Bash(ssh *)",
    "Bash(scp *)",
    "Bash(sftp *)",
    "Bash(sshpass *)",
    "Bash(ssh.exe *)",
    "Bash(scp.exe *)",
)
GUIDANCE = (
    "Use the WayGuard MCP tools instead: list_servers, list_actions, then run_action. "
    "If no action fits, call propose_action. If the user really needs this command, "
    "ask them to run it themselves."
)

# Programs whose only job is reaching a remote host.
REMOTE_PROGRAMS = frozenset({
    "ssh", "scp", "sftp", "slogin", "sshpass", "autossh", "mosh", "mosh-client",
    "pssh", "parallel-ssh", "pscp", "pdsh", "clush", "dbclient", "plink", "sshfs",
    "ansible", "ansible-playbook", "ansible-console", "fab", "tsh",
})  # fmt: skip
# Programs that run another command given as a later argument.
WRAPPERS = frozenset({
    "sudo", "doas", "su", "runuser", "env", "command", "exec", "builtin", "nohup",
    "time", "timeout", "nice", "ionice", "stdbuf", "setsid", "xargs", "parallel",
    "watch", "flock", "chronic", "unbuffer", "script", "strace", "ltrace", "torsocks",
    "proxychains", "proxychains4", "expect", "tmux", "screen", "busybox", "eval",
    "bash", "sh", "zsh", "dash", "ksh", "fish",
})  # fmt: skip
# Cloud CLIs whose listed subcommands open a remote shell.
CLOUD_SSH = {
    "gcloud": {"ssh", "scp"},
    "doctl": {"ssh"},
    "az": {"ssh"},
    "aws": {"start-session", "send-command"},
}
CONTAINER_CLIS = frozenset({"docker", "docker-compose", "podman"})
CONTAINER_REMOTE_FLAGS = ("-H", "--host", "--context", "--remote", "--url", "--connection")
SEPARATORS = frozenset({
    ";", ";;", "&", "&&", "|", "||", "|&", "(", ")", "{", "}", "!",
    "do", "then", "else", "elif", "-exec", "-execdir", "-ok", "-okdir",
})  # fmt: skip
REDIRECTS = frozenset({">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|", "<>"})
BLOCKED_VARS = frozenset({"DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST", "GIT_SSH",
                          "GIT_SSH_COMMAND"})  # fmt: skip
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
SSH_LIBRARIES = re.compile(r"\b(paramiko|asyncssh|pxssh|Net::SSH|ssh2)\b")
RSYNC_REMOTE = re.compile(r"^(rsync://|[^/\s=]+:)")
MAX_DEPTH = 8


class GuardConfigError(Exception):
    """Claude Code settings cannot be read or have an unexpected shape."""


# ---------------------------------------------------------------- command analysis


def _program(token: str) -> str:
    name = token.lstrip("\\").rsplit("/", 1)[-1]
    return name[:-4] if name.endswith(".exe") else name


def _tokens(text: str) -> list[str]:
    lex = shlex.shlex(text, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""  # bash keeps `#` literal mid-word; never hide the rest of a line
    return list(lex)


def _fallback(text: str) -> str | None:
    names = "|".join(re.escape(n) for n in sorted(REMOTE_PROGRAMS))
    if re.search(rf"(^|[^\w.-])({names})(\.exe)?($|[^\w.-])", text):
        return "possible remote shell command (unparseable command line)"
    return None


def _check_simple(words: list[str]) -> str | None:
    """Inspect one simple command (no separators). ``words[0]`` is at command position."""
    i = 0
    while i < len(words):
        m = ASSIGNMENT.match(words[i])
        if not m:
            break
        if m.group(1) in BLOCKED_VARS:
            return f"setting {m.group(1)} redirects tools to a remote host"
        i += 1
    if i == len(words):
        return None
    prog, args = _program(words[i]), words[i + 1 :]
    if prog in REMOTE_PROGRAMS:
        return f"direct `{prog}` is blocked"
    if prog in {"export", "declare", "typeset", "local", "readonly", "alias"}:
        return _check_simple(args)
    if prog == "command" and args[:1] in (["-v"], ["-V"]):
        return None  # lookup only, runs nothing
    if prog in WRAPPERS:
        for a in args:
            if _program(a) in REMOTE_PROGRAMS:
                return f"`{_program(a)}` via `{prog}` is blocked"
    if prog in CLOUD_SSH and CLOUD_SSH[prog] & set(args):
        return f"`{prog}` remote shell is blocked"
    if prog == "rsync":
        if any(a in ("-e", "--rsh") or a.startswith("--rsh=") or a.startswith("-e")
               or (not a.startswith("-") and RSYNC_REMOTE.match(a)) for a in args):  # fmt: skip
            return "`rsync` to a remote host is blocked"
    if prog in CONTAINER_CLIS:
        first = next((a for a in args if not a.startswith("-")), None)
        if (
            first in ("context", "connection")
            or any(a == f or a.startswith(f + "=") for a in args for f in CONTAINER_REMOTE_FLAGS)
            or any(a in ("-c", "-r") for a in args[: args.index(first) if first else None])
        ):
            return f"`{prog}` against a remote engine is blocked"
    if prog == "git" and any(a.lower().startswith("core.sshcommand=") for a in args):
        return "overriding git's ssh command is blocked"
    return None


def _scan(text: str, depth: int) -> str | None:
    if depth > MAX_DEPTH:
        return "command nesting is too deep to analyse"
    if m := SSH_LIBRARIES.search(text):
        return f"SSH library `{m.group(1)}` is blocked"
    text = re.sub(r"[$<>]\(", " ( ", text).replace("`", " ; ").replace("\n", " ; ")
    text = re.sub(r"(?<=[\w-])\(", "_", text)  # `word(` is no subshell: feat(ssh): msg
    try:
        tokens = _tokens(text)
    except ValueError:
        return _fallback(text)
    words: list[str] = []
    skip_next = False
    for tok in [*tokens, ";"]:
        if skip_next:
            skip_next = False
            if tok not in SEPARATORS:
                continue
        if tok in REDIRECTS:
            skip_next = True
            continue
        if tok in SEPARATORS:
            if words and (reason := _check_simple(words)):
                return reason
            words = []
            continue
        words.append(tok)
        # Quoted strings and assignment values may hold a whole command
        # (bash -c '...', watch "...", x='ssh host'): analyse them as one.
        m = ASSIGNMENT.match(tok)
        inner = m.group(2) if m else tok
        if (m or any(c.isspace() for c in tok)) and inner != text:
            if reason := _scan(inner, depth + 1):
                return reason
    return None


def check_command(command: str) -> str | None:
    """Return why ``command`` is denied, or ``None`` when it may run."""
    return _scan(command, 0)


def run_hook(stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    """Claude Code ``PreToolUse`` entry point. Fails closed on malformed input."""
    try:
        event = json.load(stdin)
        if not isinstance(event, dict):
            raise ValueError
    except ValueError:
        print("wayguard: unreadable hook input; command refused", file=stderr)
        return 2
    if event.get("tool_name") != "Bash":
        return 0
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        print("wayguard: Bash call without a command string; refused", file=stderr)
        return 2
    try:
        reason = check_command(command)
    except Exception:  # noqa: BLE001 - fail closed
        reason = "the WayGuard guard could not analyse this command"
    if reason is None:
        return 0
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"WayGuard: {reason}. {GUIDANCE}",
        }
    }, stdout)  # fmt: skip
    return 0


# ---------------------------------------------------------------- settings.json


def claude_dir() -> Path:
    """Claude Code's config directory (``$CLAUDE_CONFIG_DIR`` or ``~/.claude``)."""
    override = os.environ.get("CLAUDE_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".claude"


def settings_path() -> Path:
    return claude_dir() / "settings.json"


def hook_command() -> str:
    return f"{shlex.quote(sys.executable)} -m {HOOK_MARKER}"


def _is_ours(hook: Any) -> bool:
    return isinstance(hook, dict) and HOOK_MARKER in str(hook.get("command", ""))


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        raise GuardConfigError(f"{path} is not valid JSON; fix it first") from None
    if not isinstance(data, dict):
        raise GuardConfigError(f"{path} must contain a JSON object")
    return data


def _section(data: dict[str, Any], key: str, kind: type) -> Any:
    value = data.setdefault(key, kind())
    if not isinstance(value, kind):
        raise GuardConfigError(f"settings key {key!r} has an unexpected type")
    return value


def _strip_ours(pre: list[Any]) -> list[Any]:
    kept: list[Any] = []
    for entry in pre:
        hooks = entry.get("hooks") if isinstance(entry, dict) else None
        if isinstance(hooks, list) and any(_is_ours(h) for h in hooks):
            rest = [h for h in hooks if not _is_ours(h)]
            if not rest:
                continue
            entry = {**entry, "hooks": rest}
        kept.append(entry)
    return kept


def _write(path: Path, before: dict[str, Any], after: dict[str, Any]) -> Path | None:
    """Back up and atomically rewrite ``path`` if the content changed."""
    if before == after and path.exists():
        return None
    if path.is_symlink():
        path = path.resolve()
    path.parent.mkdir(mode=config.DIR_MODE, parents=True, exist_ok=True)
    backup = None
    mode = config.FILE_MODE
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.wayguard-bak-{stamp}")
        config.atomic_write(backup, path.read_bytes(), mode)
    config.atomic_write(path, (json.dumps(after, indent=2) + "\n").encode(), mode)
    return backup


@dataclass(frozen=True)
class Change:
    changed: bool
    backup: Path | None


def install(path: Path) -> Change:
    """Register the hook and deny rules (idempotent; refreshes a stale hook path)."""
    before = _read(path)
    after = json.loads(json.dumps(before))
    deny = _section(_section(after, "permissions", dict), "deny", list)
    deny.extend(r for r in DENY_RULES if r not in deny)
    hooks = _section(after, "hooks", dict)
    pre = _strip_ours(_section(hooks, "PreToolUse", list))
    pre.append({"matcher": "Bash", "hooks": [
        {"type": "command", "command": hook_command(), "timeout": HOOK_TIMEOUT_SECONDS}
    ]})  # fmt: skip
    hooks["PreToolUse"] = pre
    changed = before != after or not path.exists()
    return Change(changed, _write(path, before, after))


def uninstall(path: Path) -> Change:
    """Remove the hook and the deny rules ``install`` added."""
    if not path.exists():
        return Change(False, None)
    before = _read(path)
    after = json.loads(json.dumps(before))
    perms = after.get("permissions")
    if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
        perms["deny"] = [r for r in perms["deny"] if r not in DENY_RULES]
        if not perms["deny"]:
            del perms["deny"]
        if not perms:
            del after["permissions"]
    hooks = after.get("hooks")
    if isinstance(hooks, dict) and isinstance(hooks.get("PreToolUse"), list):
        hooks["PreToolUse"] = _strip_ours(hooks["PreToolUse"])
        if not hooks["PreToolUse"]:
            del hooks["PreToolUse"]
        if not hooks:
            del after["hooks"]
    return Change(before != after, _write(path, before, after))


@dataclass(frozen=True)
class Status:
    hook: bool
    current_path: bool
    missing_rules: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.hook and self.current_path and not self.missing_rules


def status(path: Path) -> Status:
    data = _read(path)
    perms = data.get("permissions")
    deny = perms.get("deny") if isinstance(perms, dict) else None
    deny = deny if isinstance(deny, list) else []
    hooks = data.get("hooks")
    pre = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    ours = [h for e in (pre if isinstance(pre, list) else [])
            if isinstance(e, dict) and e.get("matcher") == "Bash"
            and isinstance(e.get("hooks"), list)
            for h in e["hooks"] if _is_ours(h)]  # fmt: skip
    return Status(
        hook=bool(ours),
        current_path=any(h.get("command") == hook_command() for h in ours),
        missing_rules=tuple(r for r in DENY_RULES if r not in deny),
    )
