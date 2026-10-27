from typing import Any

import pytest

from tests.test_policy import dump, good
from wayguard import validation
from wayguard.policy import Policy, parse_policy
from wayguard.validation import (
    RequestDenied,
    ValidatedRequest,
    authorize_request,
    normalize_params,
    validate_request,
)


def make_policy() -> Policy:
    d = good()
    d["servers"]["prod"]["actions"]["grep"] = {
        "description": "grep",
        "risk": "read-only",
        "executable": "/usr/bin/grep",
        "args": ["-e", "{pat}", "--", "/var/log/x.log"],
        "parameters": {"pat": {"type": "string", "max_length": 32, "pattern": r"[\s\S]*"}},
    }
    d["servers"]["off"] = {
        "enabled": False,
        "ssh_alias": "off-host",
        "actions": d["servers"]["prod"]["actions"],
    }
    return parse_policy(dump(d))


def req(**over: Any) -> dict[str, Any]:
    r: dict[str, Any] = {"server_id": "prod", "action_id": "tail", "parameters": {"lines": 5}}
    r.update(over)
    return r


class FakeSink:
    def __init__(self) -> None:
        self.denied: list[dict[str, Any]] = []

    def record_denied(self, **kw: Any) -> None:
        self.denied.append(kw)

    def record_start(self, **kw: Any) -> None:  # pragma: no cover - protocol shape
        pass

    def record_end(self, **kw: Any) -> None:  # pragma: no cover - protocol shape
        pass


def test_valid_request() -> None:
    v = validate_request(make_policy(), req())
    assert isinstance(v, ValidatedRequest)
    assert v.server.id == "prod" and v.action.id == "tail"
    assert dict(v.params) == {"lines": 5}


CASES: list[tuple[str, Any, str, str]] = [
    ("unknown server", req(server_id="nope"), "unknown_server", "server_id: "),
    ("disabled server", req(server_id="off"), "server_disabled", "server_id: "),
    ("unknown action", req(action_id="nope"), "unknown_action", "action_id: "),
    ("missing param", req(parameters={}), "missing_parameter", "parameters.lines: "),
    ("extra param", req(parameters={"lines": 5, "x": 1}), "extra_parameter", "parameters.x: "),
    ("extra top-level", req(ssh_alias="evil"), "extra_field", "ssh_alias: "),
    ("bool for int", req(parameters={"lines": True}), "invalid_parameter", "parameters.lines: "),
    ("float for int", req(parameters={"lines": 5.0}), "invalid_parameter", "parameters.lines: "),
    ("string for int", req(parameters={"lines": "5"}), "invalid_parameter", "parameters.lines: "),
    ("int too big", req(parameters={"lines": 201}), "invalid_parameter", "parameters.lines: "),
    ("int too small", req(parameters={"lines": 0}), "invalid_parameter", "parameters.lines: "),
    (
        "bad enum",
        req(action_id="unit", parameters={"unit": "ssh", "name": "a"}),
        "invalid_parameter",
        "parameters.unit: ",
    ),
    (
        "overlong string",
        req(action_id="unit", parameters={"unit": "php", "name": "a" * 21}),
        "invalid_parameter",
        "parameters.name: ",
    ),
    (
        "pattern fail",
        req(action_id="unit", parameters={"unit": "php", "name": "A1"}),
        "invalid_parameter",
        "parameters.name: ",
    ),
    ("non-object request", ["x"], "invalid_request", ""),
    (
        "missing server_id",
        {"action_id": "tail", "parameters": {}},
        "invalid_request",
        "server_id: ",
    ),
    ("server_id not str", req(server_id=1), "invalid_request", "server_id: "),
    ("parameters not object", req(parameters=[1]), "invalid_request", "parameters: "),
]


@pytest.mark.parametrize(("name", "raw", "code", "prefix"), CASES, ids=[c[0] for c in CASES])
def test_denials_with_audit(name: str, raw: Any, code: str, prefix: str) -> None:
    sink = FakeSink()
    with pytest.raises(RequestDenied) as ei:
        authorize_request(make_policy(), raw, sink, "cid-1")
    assert ei.value.code == code
    assert ei.value.reason.startswith(prefix)
    assert len(sink.denied) == 1
    ev = sink.denied[0]
    assert ev["correlation_id"] == "cid-1" and ev["reason_code"] == code


def test_policy_invalid_denies_first() -> None:
    sink = FakeSink()
    with pytest.raises(RequestDenied) as ei:
        authorize_request(None, req(), sink, "c")
    assert ei.value.code == "policy_invalid"
    assert sink.denied[0]["reason_code"] == "policy_invalid"


def test_reason_never_echoes_values() -> None:
    with pytest.raises(RequestDenied) as ei:
        validate_request(make_policy(), req(server_id="x\nINJECT"))
    assert "\n" not in ei.value.reason and "INJECT" not in ei.value.reason
    with pytest.raises(RequestDenied) as ei2:
        validate_request(make_policy(), req(parameters={"lines": "SECRETVALUE"}))
    assert "SECRETVALUE" not in ei2.value.reason


def test_extra_parameter_key_is_escaped() -> None:
    with pytest.raises(RequestDenied) as ei:
        validate_request(make_policy(), req(parameters={"lines": 5, "a\nb;": 1}))
    assert ei.value.reason == "parameters.a?b?: parameter is not declared"


def test_denied_audit_hides_raw_strings() -> None:
    sink = FakeSink()
    with pytest.raises(RequestDenied):
        authorize_request(
            make_policy(),
            req(action_id="unit", parameters={"unit": "php", "name": "Secret1"}),
            sink,
            "c",
        )
    ev = sink.denied[0]
    assert "Secret1" not in repr(ev)
    assert ev["server_id"] == "prod" and ev["action_id"] == "unit"
    assert ev["params_summary"]["name"]["len"] == 7
    assert len(ev["params_summary"]["name"]["sha256_8"]) == 8
    assert ev["params_summary"]["unit"] != "php"  # unvalidated enum is hashed


def test_denied_audit_ids_sanitized() -> None:
    sink = FakeSink()
    with pytest.raises(RequestDenied):
        authorize_request(make_policy(), req(server_id="a\nb", action_id={"x": 1}), sink, "c")
    assert sink.denied[0]["server_id"] is None and sink.denied[0]["action_id"] is None


# string rules: option injection / control chars (AC-004 rejected set)
@pytest.mark.parametrize(
    "val", ["-rf", "--help", "../x", "a/../b", "a\nb", "a\0b", "a\tb", "a\x7fb"]
)
def test_string_rejected(val: str) -> None:
    with pytest.raises(RequestDenied) as ei:
        validate_request(make_policy(), req(action_id="grep", parameters={"pat": val}))
    assert ei.value.code == "invalid_parameter"


@pytest.mark.parametrize("val", ["a b", "'", '"', ";", "|", "$()", "`", "$(id)", "a&&b", "x*", "é"])
def test_string_shell_metachars_pass_validation(val: str) -> None:
    v = validate_request(make_policy(), req(action_id="grep", parameters={"pat": val}))
    assert v.params["pat"] == val


def test_lone_surrogate_rejected() -> None:
    with pytest.raises(RequestDenied):
        validate_request(make_policy(), req(action_id="grep", parameters={"pat": "a\ud800"}))


def test_params_are_immutable_copy() -> None:
    raw = req()
    v = validate_request(make_policy(), raw)
    raw["parameters"]["lines"] = 999
    assert v.params["lines"] == 5
    with pytest.raises(TypeError):
        v.params["lines"] = 1  # type: ignore[index]


def test_normalize_params() -> None:
    n = normalize_params({"a": 3, "b": "xyz", "c": True, "d": [1]})
    assert n["a"] == 3
    assert n["b"]["len"] == 3 and len(n["b"]["sha256_8"]) == 8
    assert n["c"] == {"type": "bool"} and n["d"] == {"type": "list"}
    assert normalize_params("nope") == {}


def test_normalize_enum_kept_when_validated() -> None:
    p = make_policy()
    v = validate_request(p, req(action_id="unit", parameters={"unit": "php", "name": "ab"}))
    n = normalize_params(v.params, v.action.parameters)
    assert n["unit"] == "php" and n["name"]["len"] == 2


def test_reason_codes_vocabulary() -> None:
    assert {
        "policy_invalid",
        "unknown_server",
        "server_disabled",
        "unknown_action",
        "missing_parameter",
        "extra_parameter",
        "invalid_parameter",
        "extra_field",
        "invalid_request",
    } <= set(validation.REASON_CODES)
