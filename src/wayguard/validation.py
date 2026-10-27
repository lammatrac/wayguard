"""``run_action`` request validation (REQ-005) and audit-sink contract.

Pure functions: no I/O, no process spawning. Every failure raises
``RequestDenied`` (fail closed, CON-005). Reasons use the shared
``"<json.path>: <fixed reason>"`` format and never echo agent-supplied values.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from wayguard.policy import (
    ID_RE,
    Action,
    ParameterSpec,
    Policy,
    Server,
    string_value_violation,
)

# Shared denial reason-code vocabulary. Phases 4-6 extend this tuple
# (e.g. concurrency_limit, proposal_limit); never reuse a code for a new meaning.
POLICY_INVALID = "policy_invalid"
INVALID_REQUEST = "invalid_request"
EXTRA_FIELD = "extra_field"
UNKNOWN_SERVER = "unknown_server"
SERVER_DISABLED = "server_disabled"
UNKNOWN_ACTION = "unknown_action"
MISSING_PARAMETER = "missing_parameter"
EXTRA_PARAMETER = "extra_parameter"
INVALID_PARAMETER = "invalid_parameter"
CONCURRENCY_LIMIT = "concurrency_limit"  # phase 4 gate; audited as denied by phase 6

REASON_CODES: tuple[str, ...] = (
    POLICY_INVALID,
    INVALID_REQUEST,
    EXTRA_FIELD,
    UNKNOWN_SERVER,
    SERVER_DISABLED,
    UNKNOWN_ACTION,
    MISSING_PARAMETER,
    EXTRA_PARAMETER,
    INVALID_PARAMETER,
    CONCURRENCY_LIMIT,
)

REQUEST_FIELDS = frozenset({"server_id", "action_id", "parameters"})
MAX_SUMMARY_PARAMS = 64
_UNSAFE_KEY = re.compile(r"[^A-Za-z0-9_.-]")


class RequestDenied(Exception):
    """Request refused. ``reason`` is sanitized (safe to return to the agent)."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code}: {reason}")


@dataclass(frozen=True)
class ValidatedRequest:
    server: Server
    action: Action
    params: Mapping[str, str | int]  # read-only copy; ints are real ints, never bools


class AuditSink(Protocol):
    """What request/runner code calls; phase 5 implements it against audit.jsonl.

    ``params_summary`` is always the output of ``normalize_params`` (REQ-011).
    Implementations must not raise into the caller's denial path.
    """

    def record_denied(
        self,
        *,
        correlation_id: str,
        server_id: str | None,
        action_id: str | None,
        params_summary: Mapping[str, Any],
        reason_code: str,
    ) -> None: ...

    def record_start(
        self,
        *,
        correlation_id: str,
        server_id: str,
        action_id: str,
        params_summary: Mapping[str, Any],
    ) -> None: ...

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
    ) -> None: ...


def _safe_key(key: object) -> str:
    return _UNSAFE_KEY.sub("?", str(key)[:40])


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _utf8_ok(s: str) -> bool:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _check_param(path: str, spec: ParameterSpec, value: object) -> str | int:
    if spec.type == "integer":
        if not _is_int(value):
            raise RequestDenied(INVALID_PARAMETER, f"{path}: must be an integer")
        assert isinstance(value, int)
        if spec.minimum is None or spec.maximum is None:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: parameter spec is incomplete")
        if not spec.minimum <= value <= spec.maximum:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: out of range")
        return value
    if not isinstance(value, str):
        raise RequestDenied(INVALID_PARAMETER, f"{path}: must be a string")
    if not _utf8_ok(value):
        raise RequestDenied(INVALID_PARAMETER, f"{path}: not valid UTF-8 text")
    if spec.type == "enum":
        if spec.values is None or value not in spec.values:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: not an allowed value")
        return value
    if spec.type == "string":
        if spec.max_length is None or spec.pattern is None:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: parameter spec is incomplete")
        violation = string_value_violation(value, spec.max_length)
        if violation is not None:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: {violation}")
        if re.fullmatch(spec.pattern, value) is None:
            raise RequestDenied(INVALID_PARAMETER, f"{path}: does not match pattern")
        return value
    raise RequestDenied(INVALID_PARAMETER, f"{path}: unsupported parameter type")


def validate_request(policy: Policy | None, raw: object) -> ValidatedRequest:
    """REQ-005 order: policy valid, server, action, parameters. First failure wins."""
    if policy is None:
        raise RequestDenied(POLICY_INVALID, "policy: no valid policy is loaded")
    if not isinstance(raw, dict):
        raise RequestDenied(INVALID_REQUEST, "request: must be an object")
    for key in raw:
        if key not in REQUEST_FIELDS:
            raise RequestDenied(EXTRA_FIELD, f"{_safe_key(key)}: field is not allowed")
    for name in ("server_id", "action_id"):
        if not isinstance(raw.get(name), str):
            raise RequestDenied(INVALID_REQUEST, f"{name}: required string")
    params_raw = raw.get("parameters")
    if not isinstance(params_raw, dict):
        raise RequestDenied(INVALID_REQUEST, "parameters: required object")
    if any(not isinstance(k, str) for k in params_raw):
        raise RequestDenied(INVALID_REQUEST, "parameters: keys must be strings")

    server = policy.servers.get(raw["server_id"])
    if server is None:
        raise RequestDenied(UNKNOWN_SERVER, "server_id: unknown server")
    if not server.enabled:
        raise RequestDenied(SERVER_DISABLED, "server_id: server is disabled")
    action = server.actions.get(raw["action_id"])
    if action is None:
        raise RequestDenied(UNKNOWN_ACTION, "action_id: unknown action")

    for name in action.parameters:
        if name not in params_raw:
            raise RequestDenied(MISSING_PARAMETER, f"parameters.{_safe_key(name)}: required")
    for name in params_raw:
        if name not in action.parameters:
            raise RequestDenied(
                EXTRA_PARAMETER, f"parameters.{_safe_key(name)}: parameter is not declared"
            )
    checked = {
        name: _check_param(f"parameters.{_safe_key(name)}", spec, params_raw[name])
        for name, spec in action.parameters.items()
    }
    return ValidatedRequest(server=server, action=action, params=MappingProxyType(checked))


def normalize_params(
    params: object, specs: Mapping[str, ParameterSpec] | None = None
) -> dict[str, Any]:
    """REQ-011 normalization: ints as-is, strings -> {len, sha256_8}.

    Enum values are stored as-is only when ``specs`` marks them as already
    validated enums; otherwise (e.g. denied requests) they are hashed.
    """
    if not isinstance(params, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, value in list(params.items())[:MAX_SUMMARY_PARAMS]:
        k = _safe_key(key)
        spec = specs.get(key) if specs is not None and isinstance(key, str) else None
        if _is_int(value):
            out[k] = value
        elif isinstance(value, str):
            if spec is not None and spec.type == "enum":
                out[k] = value
            else:
                digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()
                out[k] = {"len": len(value), "sha256_8": digest[:8]}
        else:
            out[k] = {"type": type(value).__name__}
    return out


def _audit_id(value: object) -> str | None:
    return value if isinstance(value, str) and ID_RE.fullmatch(value) else None


def authorize_request(
    policy: Policy | None, raw: object, sink: AuditSink, correlation_id: str
) -> ValidatedRequest:
    """Validate; on denial write exactly one ``denied`` audit record, then re-raise."""
    try:
        return validate_request(policy, raw)
    except RequestDenied as denial:
        body = raw if isinstance(raw, dict) else {}
        sink.record_denied(
            correlation_id=correlation_id,
            server_id=_audit_id(body.get("server_id")),
            action_id=_audit_id(body.get("action_id")),
            params_summary=normalize_params(body.get("parameters")),
            reason_code=denial.code,
        )
        raise
