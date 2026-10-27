"""Policy loading, validation and the immutable loaded-policy model.

Fail closed (CON-005): any problem raises; callers treat a raise as denial.
Validation errors are sanitized: they name a JSON path and a fixed reason and
never echo policy values (only identifier-safe key names, truncated).
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import posixpath
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from wayguard import config

SCHEMA_VERSION = 2
MAX_ERRORS = 50
MAX_PATTERN_LENGTH = 256
MAX_STRING_LENGTH = 256
MAX_ENUM_VALUES = 64
MAX_SERVER_DESCRIPTION = 200
MAX_ACTION_DESCRIPTION = 500
MAX_ALIAS_LENGTH = 255
MAX_ACTIONS_PER_PROJECT = 200

VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}")
LIST_VAR_RE = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]{0,63})$")
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9_.@:+][A-Za-z0-9_.@:+-]*$")
PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]{0,63})\}$")

# fnmatch globs, matched case-insensitively against the executable basename.
DENYLIST: tuple[str, ...] = (
    "sh", "bash", "zsh", "dash", "python*", "perl*", "ruby*", "node*", "env", "sudo", "su",
    "busybox", "ksh", "fish", "csh", "tcsh", "php*", "lua*", "awk", "gawk", "mawk", "sed",
    "find", "xargs", "doas", "pkexec", "ssh", "scp", "sftp", "nohup", "timeout", "nice",
    "script", "expect", "vi*", "less", "more", "tee", "dd",
)  # fmt: skip
# Concrete names (one per denylist entry) used by tests as fixtures.
DENYLIST_SAMPLES: tuple[str, ...] = tuple(g.replace("*", "") for g in DENYLIST) + (
    "python3.12", "perl5", "ruby3", "nodejs", "php8", "lua5.4", "vim",
)  # fmt: skip

_FORBIDDEN_TYPES = frozenset({"raw", "shell", "command", "script", "args_extra"})
_PARAM_KEYS: dict[str, frozenset[str]] = {
    "integer": frozenset({"type", "minimum", "maximum"}),
    "enum": frozenset({"type", "values"}),
    "string": frozenset({"type", "max_length", "pattern"}),
}


class PolicyInvalidError(Exception):
    """The policy is invalid. `errors` are sanitized, path-addressed reasons."""

    def __init__(self, errors: list[str]) -> None:
        self.errors: list[str] = list(errors[:MAX_ERRORS])
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class Defaults:
    timeout_seconds: int
    max_output_bytes: int
    max_concurrent_actions: int


@dataclass(frozen=True)
class ParameterSpec:
    name: str
    type: Literal["integer", "enum", "string"]
    minimum: int | None = None
    maximum: int | None = None
    values: tuple[str, ...] | None = None
    max_length: int | None = None
    pattern: str | None = None  # use re.fullmatch; already compiled-checked at load


@dataclass(frozen=True)
class Action:
    id: str
    description: str
    risk: str
    executable: str
    args: tuple[str, ...]  # elements that are exactly "{name}" are placeholders
    parameters: Mapping[str, ParameterSpec]
    timeout_seconds: int  # effective (action value or policy default)
    max_output_bytes: int  # effective


@dataclass(frozen=True)
class Server:
    id: str
    enabled: bool
    ssh_alias: str  # never expose via MCP/CLI listings
    description: str | None
    actions: Mapping[str, Action]


@dataclass(frozen=True)
class Policy:
    defaults: Defaults
    servers: Mapping[str, Server]
    sha256: str  # hex SHA-256 of the policy bytes at load
    path: Path | None
    loaded_at: str  # UTC ISO-8601

    def get_enabled_server(self, server_id: str) -> Server | None:
        s = self.servers.get(server_id)
        return s if s is not None and s.enabled else None


# ---------------------------------------------------------------- helpers


def _is_control(ch: str) -> bool:
    return unicodedata.category(ch) in {"Cc", "Zl", "Zp"}


def has_control_chars(s: str) -> bool:
    return any(_is_control(c) for c in s)


def string_value_violation(value: str, max_length: int) -> str | None:
    """REQ-004 string rules shared by load-time enum checks and runtime input.

    Returns a fixed reason string, or None when the value is acceptable.
    """
    if has_control_chars(value):
        return "contains control characters"
    if value.startswith("-"):
        return "starts with '-'"
    if ".." in value.split("/"):
        return "contains a '..' path segment"
    if len(value) > max_length:
        return "exceeds max length"
    return None


def is_denied_executable(executable: str) -> bool:
    base = posixpath.basename(executable).lower()
    return any(fnmatch.fnmatchcase(base, g) for g in DENYLIST)


def _safe_key(key: object) -> str:
    s = str(key)[:40]
    return "".join(c if (c.isascii() and (c.isalnum() or c in "_.-")) else "?" for c in s)


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


class _Errors:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, path: str, reason: str) -> None:
        if len(self.items) < MAX_ERRORS:
            self.items.append(f"{path or '$'}: {reason}")


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def _check_keys(
    obj: dict[str, Any], required: set[str], optional: set[str], path: str, errs: _Errors
) -> bool:
    ok = True
    for k in obj:
        if k not in required and k not in optional:
            errs.add(path, f"unknown field '{_safe_key(k)}'")
            ok = False
    for k in sorted(required - obj.keys()):
        errs.add(path, f"missing required field '{k}'")
        ok = False
    return ok


def _positive_int(v: object, ceiling: int | None, path: str, errs: _Errors) -> int | None:
    if not _is_int(v):
        errs.add(path, "must be an integer")
        return None
    assert isinstance(v, int)
    if v <= 0:
        errs.add(path, "must be > 0")
        return None
    if ceiling is not None and v > ceiling:
        errs.add(path, f"exceeds limit {ceiling}")
        return None
    return v


# --------------------------------------------------------------- sections


def _parse_defaults(raw: object, errs: _Errors) -> Defaults | None:
    path = "defaults"
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    _check_keys(
        raw, {"decision", "timeout_seconds", "max_output_bytes", "max_concurrent_actions"}, set(),
        path, errs,
    )  # fmt: skip
    if "decision" in raw and raw["decision"] != "deny":
        errs.add("defaults.decision", 'must be "deny"')
    t = _positive_int(raw.get("timeout_seconds", 1), config.MAX_TIMEOUT_SECONDS,
                      "defaults.timeout_seconds", errs)  # fmt: skip
    b = _positive_int(raw.get("max_output_bytes", 1), config.MAX_STREAM_BYTES,
                      "defaults.max_output_bytes", errs)  # fmt: skip
    c = _positive_int(raw.get("max_concurrent_actions", 1), config.MAX_CONCURRENCY,
                      "defaults.max_concurrent_actions", errs)  # fmt: skip
    if t is None or b is None or c is None:
        return None
    return Defaults(t, b, c)


def _parse_parameter(name: str, raw: object, path: str, errs: _Errors) -> ParameterSpec | None:
    if not PARAM_NAME_RE.match(name):
        errs.add(path, "invalid parameter name")
        return None
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    ptype = raw.get("type")
    if not isinstance(ptype, str):
        errs.add(path, "missing or invalid 'type'")
        return None
    if ptype in _FORBIDDEN_TYPES:
        errs.add(path, "forbidden parameter type")
        return None
    if ptype not in _PARAM_KEYS:
        errs.add(path, "unsupported parameter type")
        return None
    keys = _PARAM_KEYS[ptype]
    if not _check_keys(raw, set(keys), set(), path, errs):
        return None
    if ptype == "integer":
        lo, hi = raw["minimum"], raw["maximum"]
        if not _is_int(lo) or not _is_int(hi):
            errs.add(path, "minimum and maximum must be integers")
            return None
        if lo > hi:
            errs.add(path, "minimum exceeds maximum")
            return None
        if lo < 0:
            errs.add(path, "minimum must not be negative")
            return None
        return ParameterSpec(name, "integer", minimum=lo, maximum=hi)
    if ptype == "enum":
        vals = raw["values"]
        if not isinstance(vals, list) or not 1 <= len(vals) <= MAX_ENUM_VALUES:
            errs.add(f"{path}.values", f"must be a list of 1-{MAX_ENUM_VALUES} strings")
            return None
        good = True
        for i, v in enumerate(vals):
            if not isinstance(v, str):
                errs.add(f"{path}.values[{i}]", "must be a string")
                good = False
                continue
            why = string_value_violation(v, MAX_STRING_LENGTH)
            if why:
                errs.add(f"{path}.values[{i}]", why)
                good = False
        return ParameterSpec(name, "enum", values=tuple(vals)) if good else None
    ml, pat = raw["max_length"], raw["pattern"]
    good = True
    if not _is_int(ml) or not 1 <= ml <= MAX_STRING_LENGTH:
        errs.add(f"{path}.max_length", f"must be an integer in 1-{MAX_STRING_LENGTH}")
        good = False
    if not isinstance(pat, str) or not 1 <= len(pat) <= MAX_PATTERN_LENGTH:
        errs.add(f"{path}.pattern", f"must be a string of 1-{MAX_PATTERN_LENGTH} characters")
        good = False
    else:
        try:
            re.compile(pat)
        except re.error:
            errs.add(f"{path}.pattern", "is not a valid regular expression")
            good = False
    return ParameterSpec(name, "string", max_length=ml, pattern=pat) if good else None


def _parse_action(
    aid: str, raw: object, path: str, defaults: Defaults | None, errs: _Errors
) -> Action | None:
    if not ID_RE.match(aid):
        errs.add(path, "invalid action id")
        return None
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    before = len(errs.items)
    _check_keys(
        raw, {"description", "risk", "executable", "args", "parameters"},
        {"timeout_seconds", "max_output_bytes"}, path, errs,
    )  # fmt: skip
    desc = raw.get("description")
    if "description" in raw:
        if (
            not isinstance(desc, str)
            or len(desc) > MAX_ACTION_DESCRIPTION
            or has_control_chars(desc)
        ):
            errs.add(f"{path}.description", "must be a string without control characters, max 500")
    if "risk" in raw and raw["risk"] != "read-only":
        errs.add(f"{path}.risk", 'must be "read-only"')
    exe = raw.get("executable")
    if "executable" in raw:
        _check_executable(exe, f"{path}.executable", errs)

    params: dict[str, ParameterSpec] = {}
    raw_params = raw.get("parameters", {})
    if "parameters" in raw:
        if not isinstance(raw_params, dict):
            errs.add(f"{path}.parameters", "must be an object")
        else:
            for pname, praw in raw_params.items():
                spec = _parse_parameter(pname, praw, f"{path}.parameters.{_safe_key(pname)}", errs)
                if spec:
                    params[pname] = spec

    args: list[str] = []
    used: set[str] = set()
    raw_args = raw.get("args", [])
    if "args" in raw:
        if not isinstance(raw_args, list):
            errs.add(f"{path}.args", "must be a list of strings")
        else:
            for i, a in enumerate(raw_args):
                apath = f"{path}.args[{i}]"
                if not isinstance(a, str):
                    errs.add(apath, "must be a string")
                    continue
                m = PLACEHOLDER_RE.match(a)
                if m:
                    used.add(m.group(1))
                    if isinstance(raw_params, dict) and m.group(1) not in raw_params:
                        errs.add(apath, "placeholder has no matching parameter")
                elif "{" in a or "}" in a:
                    errs.add(apath, "embedded interpolation or stray brace not allowed")
                elif any(c in a for c in "\x00\r\n"):
                    errs.add(apath, "contains NUL, CR or LF")
                args.append(a)
    if isinstance(raw_params, dict) and isinstance(raw_args, list):
        for pname in raw_params:
            if pname not in used:
                errs.add(f"{path}.parameters.{_safe_key(pname)}", "declared but unused in args")

    timeout = _action_limit(raw, "timeout_seconds", defaults, path, errs)
    cap = _action_limit(raw, "max_output_bytes", defaults, path, errs)
    if len(errs.items) > before or defaults is None or timeout is None or cap is None:
        return None
    return Action(
        id=aid, description=str(desc), risk="read-only", executable=str(exe), args=tuple(args),
        parameters=params, timeout_seconds=timeout, max_output_bytes=cap,
    )  # fmt: skip


def _action_limit(
    raw: dict[str, Any], key: str, defaults: Defaults | None, path: str, errs: _Errors
) -> int | None:
    default = getattr(defaults, key) if defaults is not None else None
    if key not in raw:
        return default
    ceiling = config.MAX_TIMEOUT_SECONDS if key == "timeout_seconds" else config.MAX_STREAM_BYTES
    v = _positive_int(raw[key], ceiling, f"{path}.{key}", errs)
    if v is None:
        return None
    return v if default is not None else None


def _check_executable(exe: object, path: str, errs: _Errors) -> None:
    if not isinstance(exe, str) or not exe:
        errs.add(path, "must be a non-empty string")
        return
    if any(_is_control(c) or c.isspace() for c in exe):
        errs.add(path, "contains whitespace or control characters")
    elif not exe.startswith("/"):
        errs.add(path, "must be an absolute path")
    elif ".." in exe.split("/"):
        errs.add(path, "contains '..'")
    elif posixpath.normpath(exe) != exe or exe == "/":
        errs.add(path, "must be a normalized path")
    elif is_denied_executable(exe):
        errs.add(path, "executable is on the interpreter denylist")


def _check_alias(alias: object, path: str, errs: _Errors) -> None:
    if (
        not isinstance(alias, str)
        or not alias
        or len(alias) > MAX_ALIAS_LENGTH
        or alias.startswith("-")
        or not ALIAS_RE.match(alias)
    ):
        errs.add(path, "invalid alias")


def _check_short_description(desc: object, path: str, errs: _Errors) -> None:
    if not isinstance(desc, str) or len(desc) > MAX_SERVER_DESCRIPTION or has_control_chars(desc):
        errs.add(path, "must be a string without control characters, max 200")


_VarScope = Mapping[str, str | tuple[str, ...]]


@dataclass(frozen=True)
class _Host:
    id: str
    ssh_alias: str
    description: str | None
    use: tuple[str, ...]
    vars: _VarScope
    actions: Mapping[str, Any]  # raw action dicts


@dataclass(frozen=True)
class _Ctx:
    defaults: Defaults | None
    shared: Mapping[str, Any]
    templates: Mapping[str, Mapping[str, Any]]


def _parse_use(
    raw: object, templates: Mapping[str, Mapping[str, Any]], path: str, errs: _Errors
) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        errs.add(path, "must be a list of template ids")
        return ()
    seen: set[str] = set()
    for tid in raw:
        if tid not in templates:
            errs.add(path, f"unknown template '{_safe_key(tid)}'")
        elif tid in seen:
            errs.add(path, f"duplicate template '{_safe_key(tid)}'")
        seen.add(tid)
    return tuple(raw)


def _parse_templates(raw: object, errs: _Errors) -> dict[str, Mapping[str, Any]]:
    path = "templates"
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return {}
    templates: dict[str, Mapping[str, Any]] = {}
    for tid, traw in raw.items():
        tpath = f"{path}.{_safe_key(tid)}"
        if not ID_RE.match(tid):
            errs.add(tpath, "invalid template id")
            continue
        if not isinstance(traw, dict):
            errs.add(tpath, "must be an object")
            continue
        before = len(errs.items)
        _check_keys(traw, {"actions"}, {"description"}, tpath, errs)
        if "description" in traw:
            _check_short_description(traw["description"], f"{tpath}.description", errs)
        if "actions" in traw and not isinstance(traw["actions"], dict):
            errs.add(f"{tpath}.actions", "must be an object")
        if len(errs.items) == before:
            templates[tid] = dict(traw["actions"])
    return templates


def _parse_host(
    hid: str,
    raw: object,
    errs: _Errors,
    templates: Mapping[str, Mapping[str, Any]] | None = None,
) -> _Host | None:
    path = f"hosts.{_safe_key(hid)}"
    if not ID_RE.match(hid):
        errs.add(path, "invalid host id")
        return None
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    before = len(errs.items)
    _check_keys(raw, {"ssh_alias"}, {"description", "actions", "use", "vars"}, path, errs)
    alias = raw.get("ssh_alias")
    if "ssh_alias" in raw:
        _check_alias(alias, f"{path}.ssh_alias", errs)
    desc = raw.get("description")
    if "description" in raw:
        _check_short_description(desc, f"{path}.description", errs)
    use: tuple[str, ...] = ()
    if "use" in raw:
        use = _parse_use(raw["use"], templates or {}, f"{path}.use", errs)
    host_vars = _parse_vars(raw["vars"], f"{path}.vars", errs) if "vars" in raw else {}
    actions: dict[str, Any] = {}
    if "actions" in raw:
        if isinstance(raw["actions"], dict):
            actions = dict(raw["actions"])
        else:
            errs.add(f"{path}.actions", "must be an object")
    if len(errs.items) > before or host_vars is None:
        return None
    return _Host(
        id=hid, ssh_alias=str(alias), description=desc if isinstance(desc, str) else None,
        use=use, vars=host_vars, actions=actions,
    )  # fmt: skip


def _parse_shared_parameters(raw: object, errs: _Errors) -> dict[str, Any]:
    path = "parameters"
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return {}
    shared: dict[str, Any] = {}
    for pid, spec in raw.items():
        ppath = f"{path}.{_safe_key(pid)}"
        if not ID_RE.match(pid):
            errs.add(ppath, "invalid shared parameter id")
            continue
        if (
            isinstance(spec, dict)
            and spec.get("type") == "enum"
            and isinstance(spec.get("values"), str)
        ):
            if _check_keys(spec, {"type", "values"}, set(), ppath, errs):
                if LIST_VAR_RE.match(spec["values"]):
                    shared[pid] = spec
                else:
                    errs.add(f"{ppath}.values", "must be a list or a '$name' variable reference")
        elif _parse_parameter("x", spec, ppath, errs):
            shared[pid] = spec
    return shared


def _parse_vars(raw: object, path: str, errs: _Errors) -> dict[str, str | tuple[str, ...]] | None:
    """Parse a `vars` object. Values are author-fixed constants: a string or 1-64 strings."""
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    before = len(errs.items)
    out: dict[str, str | tuple[str, ...]] = {}
    for name, val in raw.items():
        vpath = f"{path}.{_safe_key(name)}"
        if not PARAM_NAME_RE.match(name):
            errs.add(vpath, "invalid variable name")
        elif isinstance(val, str):
            if _check_var_string(val, vpath, errs):
                out[name] = val
        elif isinstance(val, list) and 1 <= len(val) <= MAX_ENUM_VALUES:
            ok = True
            for i, item in enumerate(val):
                if not isinstance(item, str):
                    errs.add(f"{vpath}[{i}]", "must be a string")
                    ok = False
                elif not _check_var_string(item, f"{vpath}[{i}]", errs):
                    ok = False
            if ok:
                out[name] = tuple(val)
        else:
            errs.add(vpath, f"must be a string or a list of 1-{MAX_ENUM_VALUES} strings")
    return out if len(errs.items) == before else None


def _check_var_string(value: str, path: str, errs: _Errors) -> bool:
    # Braces are banned so a substituted value can never form an agent `{param}` or a `${var}`.
    why = string_value_violation(value, MAX_STRING_LENGTH)
    if why is None and ("{" in value or "}" in value):
        why = "contains a brace"
    if why:
        errs.add(path, why)
        return False
    return True


def _resolve_action(
    raw: object,
    scope: _VarScope,
    ctx: _Ctx,
    path: str,
    errs: _Errors,
) -> object:
    """Inline shared parameters, `"$var"` enum values and `${var}` in args.

    Never mutates `raw`: template and host action dicts are shared by every project
    that expands them, and each project may resolve them differently.
    """
    if not isinstance(raw, dict):
        return raw
    out: dict[str, Any] = dict(raw)
    for key in ("executable", "description"):
        if isinstance(raw.get(key), str) and "${" in raw[key]:
            errs.add(f"{path}.{key}", "variables are not allowed here")
    if isinstance(raw.get("parameters"), dict):
        params: dict[str, Any] = {}
        for pname, pval in raw["parameters"].items():
            ppath = f"{path}.parameters.{_safe_key(pname)}"
            if isinstance(pval, str):
                if pval in ctx.shared:
                    pval = ctx.shared[pval]
                else:
                    errs.add(ppath, f"unknown shared parameter '{_safe_key(pval)}'")
            if isinstance(pval, dict):
                pval = copy.deepcopy(pval)
                if pval.get("type") == "enum" and isinstance(pval.get("values"), str):
                    m = LIST_VAR_RE.match(pval["values"])
                    if m:
                        var = m.group(1)
                        val = scope.get(var)
                        if val is None:
                            errs.add(f"{ppath}.values", f"undefined variable '{var}'")
                        elif not isinstance(val, tuple):
                            errs.add(f"{ppath}.values", f"variable '{var}' must be a list")
                        else:
                            pval["values"] = list(val)
            params[pname] = pval
        out["parameters"] = params
    if isinstance(raw.get("args"), list):
        out["args"] = [
            _substitute(a, scope, f"{path}.args[{i}]", errs) if isinstance(a, str) else a
            for i, a in enumerate(raw["args"])
        ]
    return out


def _substitute(arg: str, scope: _VarScope, path: str, errs: _Errors) -> str:
    """Replace each `${var}` with a string variable in one pass (no re-scan)."""
    # A literal brace next to a reference (e.g. "{${x}}") would let a variable select
    # an agent `{param}` placeholder, so braces may only belong to `${...}` here.
    if VAR_REF_RE.search(arg) and any(c in VAR_REF_RE.sub("", arg) for c in "{}"):
        errs.add(path, "stray brace around variable")
        return arg

    def one(m: re.Match[str]) -> str:
        var = m.group(1)
        val = scope.get(var)
        if val is None:
            errs.add(path, f"undefined variable '{var}'")
        elif not isinstance(val, str):
            errs.add(path, f"variable '{var}' must be a string")
        else:
            return val
        return m.group(0)

    return VAR_REF_RE.sub(one, arg)


def _expand_project(
    pid: str, raw: object, hosts: Mapping[str, _Host], ctx: _Ctx, errs: _Errors
) -> Server | None:
    path = f"projects.{_safe_key(pid)}"
    if not ID_RE.match(pid):
        errs.add(path, "invalid project id")
        return None
    if not isinstance(raw, dict):
        errs.add(path, "must be an object")
        return None
    before = len(errs.items)
    _check_keys(
        raw, {"enabled", "host"}, {"description", "actions", "disable", "use", "vars"}, path, errs
    )
    if "enabled" in raw and not isinstance(raw["enabled"], bool):
        errs.add(f"{path}.enabled", "must be a boolean")
    host: _Host | None = None
    if "host" in raw:
        href = raw["host"]
        if isinstance(href, str) and href in hosts:
            host = hosts[href]
        else:
            errs.add(f"{path}.host", "unknown host")
    desc = raw.get("description")
    if "description" in raw:
        _check_short_description(desc, f"{path}.description", errs)
    raw_actions = raw.get("actions", {})
    if not isinstance(raw_actions, dict):
        errs.add(f"{path}.actions", "must be an object")
        raw_actions = {}
    use: tuple[str, ...] = ()
    if "use" in raw:
        use = _parse_use(raw["use"], ctx.templates, f"{path}.use", errs)
    disable: list[str] = []
    if "disable" in raw:
        if isinstance(raw["disable"], list) and all(isinstance(x, str) for x in raw["disable"]):
            disable = raw["disable"]
        else:
            errs.add(f"{path}.disable", "must be a list of strings")
    proj_vars = _parse_vars(raw["vars"], f"{path}.vars", errs) if "vars" in raw else {}
    if host is None or proj_vars is None or len(errs.items) > before:
        return None
    # Host actions see host vars only; project actions see host vars overlaid by project vars.
    project_scope = {**host.vars, **proj_vars}

    hpath = f"hosts.{_safe_key(host.id)}"
    sources: list[tuple[str, Mapping[str, Any], _VarScope]] = []
    sources += [
        (f"{hpath}.use.{_safe_key(t)}.actions", ctx.templates[t], host.vars) for t in host.use
    ]
    sources.append((f"{hpath}.actions", host.actions, host.vars))
    sources += [
        (f"{path}.use.{_safe_key(t)}.actions", ctx.templates[t], project_scope) for t in use
    ]
    sources.append((f"{path}.actions", raw_actions, project_scope))
    first: dict[str, str] = {}
    actions: dict[str, Action] = {}
    for base, group, scope in sources:
        for aid, araw in group.items():
            apath = f"{base}.{_safe_key(aid)}"
            if aid in first:
                errs.add(apath, f"duplicate action id (also defined in {first[aid]})")
                continue
            first[aid] = apath
            n_errs = len(errs.items)
            resolved = _resolve_action(araw, scope, ctx, apath, errs)
            if len(errs.items) > n_errs:
                continue  # resolution failed; v1 checks on a half-resolved dict only add noise
            a = _parse_action(aid, resolved, apath, ctx.defaults, errs)
            if a:
                actions[aid] = a
    for did in disable:
        if did in first:
            actions.pop(did, None)
        else:
            errs.add(f"{path}.disable", f"unknown action '{_safe_key(did)}'")
    if len(first) > MAX_ACTIONS_PER_PROJECT:
        errs.add(path, f"too many actions (max {MAX_ACTIONS_PER_PROJECT})")
    if len(errs.items) > before:
        return None
    return Server(
        id=pid, enabled=bool(raw["enabled"]), ssh_alias=host.ssh_alias,
        description=desc if isinstance(desc, str) else None, actions=actions,
    )  # fmt: skip


# ------------------------------------------------------------- public API


def parse_policy(data: bytes, path: Path | None = None) -> Policy:
    """Parse and fully validate policy bytes. Raises PolicyInvalidError."""
    try:
        doc = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyInvalidError(["$: not valid JSON"]) from None
    errs = _Errors()
    if not isinstance(doc, dict):
        raise PolicyInvalidError(["$: must be a JSON object"])
    _check_keys(
        doc, {"version", "defaults", "hosts", "projects"}, {"parameters", "templates"}, "$", errs
    )
    if "version" in doc and (not _is_int(doc["version"]) or doc["version"] != SCHEMA_VERSION):
        errs.add("version", f"must be {SCHEMA_VERSION}")
    defaults = _parse_defaults(doc["defaults"], errs) if "defaults" in doc else None
    templates = _parse_templates(doc["templates"], errs) if "templates" in doc else {}
    hosts: dict[str, _Host] = {}
    if "hosts" in doc:
        if not isinstance(doc["hosts"], dict):
            errs.add("hosts", "must be an object")
        else:
            for hid, hraw in doc["hosts"].items():
                h = _parse_host(hid, hraw, errs, templates)
                if h:
                    hosts[hid] = h
    shared = _parse_shared_parameters(doc["parameters"], errs) if "parameters" in doc else {}
    ctx = _Ctx(defaults=defaults, shared=shared, templates=templates)
    servers: dict[str, Server] = {}
    if "projects" in doc:
        if not isinstance(doc["projects"], dict):
            errs.add("projects", "must be an object")
        else:
            for pid, praw in doc["projects"].items():
                s = _expand_project(pid, praw, hosts, ctx, errs)
                if s:
                    servers[pid] = s
    if errs.items or defaults is None:
        raise PolicyInvalidError(errs.items or ["defaults: invalid"])
    return Policy(
        defaults=defaults,
        servers=servers,
        sha256=hashlib.sha256(data).hexdigest(),
        path=path,
        loaded_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def load_policy(root: Path) -> Policy:
    """Check permissions (PolicyPermissionError), read, validate (PolicyInvalidError)."""
    resolved = config.check_policy_file(config.policy_path(root), root)
    try:
        data = resolved.read_bytes()
    except OSError:
        raise config.PolicyPermissionError("policy unreadable") from None
    return parse_policy(data, resolved)


def policy_changed_since_load(policy: Policy) -> bool:
    """True if the policy file's bytes differ from those loaded (or cannot be read)."""
    if policy.path is None:
        return False
    try:
        current = hashlib.sha256(policy.path.read_bytes()).hexdigest()
    except OSError:
        return True
    return current != policy.sha256
