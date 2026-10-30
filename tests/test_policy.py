import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

from wayguard import config, policy
from wayguard.policy import PolicyInvalidError, parse_policy


def good() -> dict[str, Any]:
    return {
        "version": 2,
        "defaults": {
            "decision": "deny",
            "timeout_seconds": 15,
            "max_output_bytes": 32768,
            "max_concurrent_actions": 2,
        },
        "hosts": {"prod-host": {"ssh_alias": "prod-debug"}},
        "projects": {
            "prod": {
                "enabled": True,
                "host": "prod-host",
                "description": "Production",
                "actions": {
                    "tail": {
                        "description": "Tail log",
                        "risk": "read-only",
                        "executable": "/usr/bin/tail",
                        "args": ["-n", "{lines}", "--", "/var/log/x.log"],
                        "parameters": {
                            "lines": {"type": "integer", "minimum": 1, "maximum": 200},
                        },
                        "timeout_seconds": 10,
                        "max_output_bytes": 1000,
                    },
                    "unit": {
                        "description": "Status",
                        "risk": "read-only",
                        "executable": "/usr/bin/systemctl",
                        "args": ["status", "{unit}", "{name}"],
                        "parameters": {
                            "unit": {"type": "enum", "values": ["nginx", "php"]},
                            "name": {"type": "string", "max_length": 20, "pattern": "[a-z]+"},
                        },
                    },
                },
            }
        },
    }


def dump(d: dict[str, Any]) -> bytes:
    return json.dumps(d).encode()


def action(d: dict[str, Any]) -> dict[str, Any]:
    a: dict[str, Any] = d["projects"]["prod"]["actions"]["tail"]
    return a


def add_server(
    d: dict[str, Any],
    sid: str,
    *,
    enabled: bool,
    ssh_alias: str,
    actions: dict[str, Any],
    description: str | None = None,
) -> None:
    """Add host `<sid>-host` (with `ssh_alias`) and a project `sid` using it."""
    d["hosts"][f"{sid}-host"] = {"ssh_alias": ssh_alias}
    proj: dict[str, Any] = {"enabled": enabled, "host": f"{sid}-host", "actions": actions}
    if description is not None:
        proj["description"] = description
    d["projects"][sid] = proj


def test_valid_policy_builds_model() -> None:
    p = parse_policy(dump(good()))
    assert p.defaults.timeout_seconds == 15
    assert p.defaults.max_concurrent_actions == 2
    s = p.servers["prod"]
    assert s.enabled and s.ssh_alias == "prod-debug" and s.description == "Production"
    a = s.actions["tail"]
    assert a.timeout_seconds == 10 and a.max_output_bytes == 1000
    assert a.parameters["lines"].type == "integer"
    assert a.parameters["lines"].maximum == 200
    u = s.actions["unit"]
    assert u.timeout_seconds == 15 and u.max_output_bytes == 32768  # inherited defaults
    assert u.parameters["unit"].values == ("nginx", "php")
    assert u.parameters["name"].pattern == "[a-z]+"
    assert len(p.sha256) == 64


def test_two_projects_share_host() -> None:
    d = good()
    disk = {**copy.deepcopy(action(d)), "description": "Disk"}
    d["hosts"]["prod-host"]["actions"] = {"disk": disk}
    d["projects"]["b"] = {"enabled": True, "host": "prod-host"}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host"}
    p = parse_policy(dump(d))
    for pid in ("a", "b"):
        assert p.servers[pid].ssh_alias == "prod-debug"
        assert "disk" in p.servers[pid].actions
    assert "prod-host" not in p.servers


def test_disabled_project_still_validated() -> None:
    d = good()
    d["projects"]["prod"]["enabled"] = False
    action(d)["executable"] = "/bin/bash"
    with pytest.raises(PolicyInvalidError):
        parse_policy(dump(d))


def test_disable_host_action_per_project() -> None:
    d = good()
    d["hosts"]["prod-host"]["actions"] = {"disk": copy.deepcopy(action(d))}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "disable": ["disk"]}
    d["projects"]["b"] = {"enabled": True, "host": "prod-host"}
    p = parse_policy(dump(d))
    assert "disk" not in p.servers["a"].actions
    assert "disk" in p.servers["b"].actions


def test_duplicate_action_error_names_first_source() -> None:
    d = good()
    d["hosts"]["prod-host"]["actions"] = {"tail": copy.deepcopy(action(d))}
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any(
        x.startswith("projects.prod.actions.tail: duplicate action id")
        and "hosts.prod-host.actions.tail" in x
        for x in e.value.errors
    )


def test_action_cap_above_default_within_ceiling() -> None:
    d = good()
    action(d).update(max_output_bytes=262144, timeout_seconds=120)
    a = parse_policy(dump(d)).servers["prod"].actions["tail"]
    assert a.max_output_bytes == 262144 and a.timeout_seconds == 120


@pytest.mark.parametrize("key,val", [("max_output_bytes", 262145), ("timeout_seconds", 121)])
def test_action_cap_above_ceiling_rejected(key: str, val: int) -> None:
    d = good()
    action(d)[key] = val
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any("exceeds limit" in x for x in e.value.errors)


SHARED_LINES = {"type": "integer", "minimum": 1, "maximum": 200}


def use_shared(d: dict[str, Any], ref: str) -> None:
    action(d)["parameters"]["lines"] = ref


def test_shared_parameter_reference_inlined() -> None:
    d = good()
    d["parameters"] = {"lines": SHARED_LINES, "unused": {"type": "enum", "values": ["a"]}}
    use_shared(d, "lines")
    other = copy.deepcopy(action(d))
    other["args"] = ["-n", "{count}", "--", "/var/log/y.log"]
    other["parameters"] = {"count": "lines"}
    d["projects"]["prod"]["actions"]["tail2"] = other
    p = parse_policy(dump(d))
    acts = p.servers["prod"].actions
    a, b = acts["tail"].parameters["lines"], acts["tail2"].parameters["count"]
    assert (a.name, b.name) == ("lines", "count")
    assert (a.type, a.minimum, a.maximum) == (b.type, b.minimum, b.maximum) == ("integer", 1, 200)


def test_shared_parameter_unknown_ref_error_is_sanitized() -> None:
    d = good()
    d["parameters"] = {}
    use_shared(d, "no\nope")
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert (
        "projects.prod.actions.tail.parameters.lines: unknown shared parameter 'no?ope'"
        in e.value.errors
    )


def test_shared_parameter_enum_values_ref_shape_checked() -> None:
    d = good()
    d["parameters"] = {"e": {"type": "enum", "values": "$unit_names"}}
    # shape is valid; resolution of $vars comes later, so it is simply unused here
    parse_policy(dump(d))


def tpl_action(d: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(action(d))


def test_template_expands_for_each_project() -> None:
    d = good()
    d["templates"] = {"t": {"description": "T", "actions": {"disk": tpl_action(d)}}}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "use": ["t"]}
    d["projects"]["b"] = {"enabled": True, "host": "prod-host", "use": ["t"]}
    p = parse_policy(dump(d))
    assert "disk" in p.servers["a"].actions and "disk" in p.servers["b"].actions
    assert "disk" not in p.servers["prod"].actions


def test_host_template_actions_shared() -> None:
    d = good()
    d["templates"] = {"basics": {"actions": {"disk": tpl_action(d)}}}
    d["hosts"]["prod-host"]["use"] = ["basics"]
    d["projects"]["b"] = {"enabled": True, "host": "prod-host"}
    p = parse_policy(dump(d))
    assert "disk" in p.servers["prod"].actions and "disk" in p.servers["b"].actions


def test_template_action_equals_inline() -> None:
    d = good()
    d["templates"] = {"t": {"actions": {"disk": tpl_action(d)}}}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "use": ["t"]}
    d["projects"]["b"] = {
        "enabled": True,
        "host": "prod-host",
        "actions": {"disk": tpl_action(d)},
    }
    p = parse_policy(dump(d))
    assert p.servers["a"].actions["disk"] == p.servers["b"].actions["disk"]


def test_template_in_host_and_project_collides() -> None:
    d = good()
    d["templates"] = {"t": {"actions": {"disk": tpl_action(d)}}}
    d["hosts"]["prod-host"]["use"] = ["t"]
    d["projects"]["prod"]["use"] = ["t"]
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any(
        x.startswith("projects.prod.use.t.actions.disk: duplicate action id")
        and "hosts.prod-host.use.t.actions.disk" in x
        for x in e.value.errors
    )


def test_template_error_names_source() -> None:
    d = good()
    bad = tpl_action(d)
    bad["executable"] = "/bin/bash"
    d["templates"] = {"t": {"actions": {"disk": bad}}}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "use": ["t"]}
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any(x.startswith("projects.a.use.t.actions.") for x in e.value.errors)


def test_template_actions_resolve_shared_parameters() -> None:
    d = good()
    d["parameters"] = {"lines": SHARED_LINES}
    t = tpl_action(d)
    t["parameters"] = {"lines": "lines"}
    d["templates"] = {"t": {"actions": {"disk": t}}}
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "use": ["t"]}
    p = parse_policy(dump(d))
    assert p.servers["a"].actions["disk"].parameters["lines"].maximum == 200


def test_template_order_host_then_project_and_disable() -> None:
    d = good()
    d["templates"] = {"t": {"actions": {"disk": tpl_action(d)}}}
    d["projects"]["prod"]["use"] = ["t"]
    d["projects"]["prod"]["disable"] = ["disk"]
    assert "disk" not in parse_policy(dump(d)).servers["prod"].actions


def test_template_counts_toward_action_cap() -> None:
    d = good()
    d["templates"] = {"t": {"actions": {f"a{i}": tpl_action(d) for i in range(201)}}}
    d["projects"]["prod"]["use"] = ["t"]
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert any("too many actions" in x for x in e.value.errors)


def test_unused_template_accepted() -> None:
    d = good()
    d["templates"] = {"t": {"actions": {"disk": tpl_action(d)}}}
    parse_policy(dump(d))


def test_use_error_messages_sanitized() -> None:
    d = good()
    d["projects"]["prod"]["use"] = ["no\nope"]
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert "projects.prod.use: unknown template 'no?ope'" in e.value.errors


ENUM_VAR = {"type": "enum", "values": "$c"}


def set_vars(d: dict[str, Any], **kv: Any) -> None:
    d["projects"]["prod"].setdefault("vars", {}).update(kv)


def errors_of(d: dict[str, Any]) -> list[str]:
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    return e.value.errors


def test_string_var_substituted_inside_arg() -> None:
    d = good()
    set_vars(d, project_dir="/srv/a")
    action(d)["args"][3] = "${project_dir}/wp-content/debug.log"
    a = parse_policy(dump(d)).servers["prod"].actions["tail"]
    assert a.args == ("-n", "{lines}", "--", "/srv/a/wp-content/debug.log")


def test_string_var_used_several_times_in_one_arg() -> None:
    d = good()
    set_vars(d, a="x", b="y")
    action(d)["args"][3] = "/${a}/${b}/${a}.log"
    assert parse_policy(dump(d)).servers["prod"].actions["tail"].args[3] == "/x/y/x.log"


def test_list_var_becomes_enum() -> None:
    d = good()
    t = tpl_action(d)
    t["args"] = ["logs", "{container}"]
    t["parameters"] = {"container": {"type": "enum", "values": "$containers"}}
    d["templates"] = {"docker": {"actions": {"logs": t}}}
    d["projects"]["a"] = {
        "enabled": True, "host": "prod-host", "use": ["docker"],
        "vars": {"containers": ["a_wp", "a_db"]},
    }  # fmt: skip
    d["projects"]["b"] = {
        "enabled": True, "host": "prod-host", "use": ["docker"],
        "vars": {"containers": ["b_wp"]},
    }  # fmt: skip
    p = parse_policy(dump(d))
    assert p.servers["a"].actions["logs"].parameters["container"].values == ("a_wp", "a_db")
    assert p.servers["b"].actions["logs"].parameters["container"].values == ("b_wp",)


def test_shared_enum_list_var_resolved_per_project() -> None:
    d = good()
    d["parameters"] = {"container": {"type": "enum", "values": "$containers"}}
    t = tpl_action(d)
    t["args"] = ["logs", "{container}"]
    t["parameters"] = {"container": "container"}
    d["templates"] = {"docker": {"actions": {"logs": t}}}
    d["projects"]["a"] = {
        "enabled": True, "host": "prod-host", "use": ["docker"], "vars": {"containers": ["x"]},
    }  # fmt: skip
    d["projects"]["b"] = {
        "enabled": True, "host": "prod-host", "use": ["docker"], "vars": {"containers": ["y"]},
    }  # fmt: skip
    p = parse_policy(dump(d))
    assert p.servers["a"].actions["logs"].parameters["container"].values == ("x",)
    assert p.servers["b"].actions["logs"].parameters["container"].values == ("y",)


def test_template_vars_per_project_and_raw_not_mutated(monkeypatch: pytest.MonkeyPatch) -> None:
    d = good()
    t = tpl_action(d)
    t["args"] = ["-n", "{lines}", "--", "${dir}/debug.log"]
    host_t = tpl_action(d)
    host_t["args"] = ["-n", "{lines}", "--", "${dir}/host.log"]
    d["templates"] = {"t": {"actions": {"log": t}}, "h": {"actions": {"hlog": host_t}}}
    d["hosts"]["prod-host"].update(use=["h"], vars={"dir": "/srv/host"})
    d["projects"]["a"] = {"enabled": True, "host": "prod-host", "use": ["t"], "vars": {"dir": "/a"}}
    d["projects"]["b"] = {"enabled": True, "host": "prod-host", "use": ["t"], "vars": {"dir": "/b"}}
    tpls: dict[str, Any] = {}
    real = policy._parse_templates

    def spy(raw: object, errs: Any) -> Any:
        tpls.update(real(raw, errs))
        return tpls

    monkeypatch.setattr(policy, "_parse_templates", spy)
    before = copy.deepcopy(d)
    p = parse_policy(dump(d))
    assert p.servers["a"].actions["log"].args[3] == "/a/debug.log"
    assert p.servers["b"].actions["log"].args[3] == "/b/debug.log"
    assert p.servers["a"].actions["hlog"].args[3] == "/srv/host/host.log"
    assert tpls["t"].actions["log"] == before["templates"]["t"]["actions"]["log"]
    assert tpls["h"].actions["hlog"] == before["templates"]["h"]["actions"]["hlog"]


def test_resolve_action_does_not_mutate_input() -> None:
    raw: dict[str, Any] = {
        "executable": "/usr/bin/docker",
        "args": ["logs", "${d}/x", "{c}"],
        "parameters": {"c": {"type": "enum", "values": "$cs"}, "n": "shared"},
    }
    snapshot = copy.deepcopy(raw)
    ctx = policy._Ctx(defaults=None, shared={"shared": SHARED_LINES}, templates={})
    errs = policy._Errors()
    out = policy._resolve_action(raw, {"d": "/srv", "cs": ("a", "b")}, ctx, "p", errs)
    assert errs.items == []
    assert raw == snapshot
    assert isinstance(out, dict)
    assert out["args"] == ["logs", "/srv/x", "{c}"]
    assert out["parameters"]["c"] == {"type": "enum", "values": ["a", "b"]}
    assert out["parameters"]["c"] is not raw["parameters"]["c"]


def test_project_var_overrides_host_var() -> None:
    d = good()
    d["hosts"]["prod-host"]["vars"] = {"dir": "/host", "other": "/o"}
    set_vars(d, dir="/proj")
    action(d)["args"][3] = "${dir}${other}/x.log"
    assert parse_policy(dump(d)).servers["prod"].actions["tail"].args[3] == "/proj/o/x.log"


def test_host_actions_ignore_project_vars() -> None:
    d = good()
    host_act = tpl_action(d)
    host_act["args"][3] = "${dir}/x.log"
    d["hosts"]["prod-host"].update(vars={"dir": "/host"}, actions={"hlog": host_act})
    set_vars(d, dir="/proj")
    action(d)["args"][3] = "${dir}/x.log"
    p = parse_policy(dump(d))
    assert p.servers["prod"].actions["hlog"].args[3] == "/host/x.log"
    assert p.servers["prod"].actions["tail"].args[3] == "/proj/x.log"


def test_host_action_cannot_see_project_only_var() -> None:
    d = good()
    host_act = tpl_action(d)
    host_act["args"][3] = "${dir}/x.log"
    d["hosts"]["prod-host"]["actions"] = {"hlog": host_act}
    set_vars(d, dir="/proj")
    assert "hosts.prod-host.actions.hlog.args[3]: undefined variable 'dir'" in errors_of(d)


@pytest.mark.parametrize("value", ["{lines}", "${x}", "a}", ["ok", "{lines}"]])
def test_var_value_with_braces_rejected(value: Any) -> None:
    d = good()
    set_vars(d, v=value, x="ok")
    action(d)["args"][3] = "${v}"
    errs = errors_of(d)
    assert any(x.startswith("projects.prod.vars.v") and "contains a brace" in x for x in errs)


def test_var_errors_named_and_sanitized() -> None:
    d = good()
    set_vars(d, s="/secret-value", lst=["secret-item"])
    action(d)["args"][3] = "${lst}"
    action(d)["executable"] = "/usr/bin/${s}"
    u = d["projects"]["prod"]["actions"]["unit"]
    u["parameters"]["unit"] = {"type": "enum", "values": "$s"}
    errs = errors_of(d)
    assert "projects.prod.actions.tail.args[3]: variable 'lst' must be a string" in errs
    assert "projects.prod.actions.tail.executable: variables are not allowed here" in errs
    assert "projects.prod.actions.unit.parameters.unit.values: variable 's' must be a list" in errs
    assert not any("secret" in x for x in errs)


def test_var_value_errors_name_path() -> None:
    d = good()
    set_vars(d, x="-rf", y=["ok", "a\nb"])
    errs = errors_of(d)
    assert "projects.prod.vars.x: starts with '-'" in errs
    assert "projects.prod.vars.y[1]: contains control characters" in errs


def test_undefined_enum_var_error() -> None:
    d = good()
    d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"] = {
        "type": "enum",
        "values": "$nope",
    }
    errs = errors_of(d)
    assert errs == ["projects.prod.actions.unit.parameters.unit.values: undefined variable 'nope'"]


def test_substituted_text_not_rescanned() -> None:
    d = good()
    set_vars(d, a="$", b="x")
    action(d)["args"][3] = "/p/${a}{b}"
    # "${a}" -> "$" gives "/p/${b}"; it is not re-scanned, so "{b}" stays a stray brace
    assert any("stray brace" in x for x in errors_of(d))


@pytest.mark.parametrize("arg", ["{${x}}", "pre{${x}}", "${x}}", "{${x}/log"])
def test_literal_brace_around_var_rejected(arg: str) -> None:
    d = good()
    set_vars(d, x="lines")
    action(d)["args"][1] = arg
    assert errors_of(d) == ["projects.prod.actions.tail.args[1]: stray brace around variable"]


@pytest.mark.parametrize("arg,out", [("${x}", "/srv"), ("/srv/${x}/log", "/srv//srv/log")])
def test_var_without_literal_braces_accepted(arg: str, out: str) -> None:
    d = good()
    set_vars(d, x="/srv")
    action(d)["args"][3] = arg
    assert parse_policy(dump(d)).servers["prod"].actions["tail"].args[3] == out


def test_unused_host_vars_accepted() -> None:
    d = good()
    d["hosts"]["prod-host"]["vars"] = {"h": "x", "hl": ["a"]}
    parse_policy(dump(d))


def test_unused_project_var_rejected() -> None:
    # A misspelt project var must not silently fall back to the host value.
    d = good()
    d["hosts"]["prod-host"]["vars"] = {"log_dir": "/host"}
    set_vars(d, log_dri="/proj", lst=["a"])
    action(d)["args"][3] = "${log_dir}/x.log"
    errs = errors_of(d)
    assert "projects.prod.vars.log_dri: unused variable" in errs
    assert "projects.prod.vars.lst: unused variable" in errs


def test_project_var_used_only_by_host_action_is_unused() -> None:
    d = good()
    host_act = tpl_action(d)
    host_act["args"][3] = "${dir}/x.log"
    d["hosts"]["prod-host"].update(vars={"dir": "/host"}, actions={"hlog": host_act})
    set_vars(d, dir="/proj")
    assert "projects.prod.vars.dir: unused variable" in errors_of(d)


def test_project_vars_used_by_template_shared_enum_and_args_accepted() -> None:
    d = good()
    d["parameters"] = {"cs": ENUM_VAR}
    t_act = tpl_action(d)
    t_act["args"][3] = "${tdir}/x.log"
    d["templates"] = {"t": {"actions": {"disk": t_act}}}
    d["projects"]["prod"]["use"] = ["t"]
    d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"] = "cs"
    d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"] = {
        "type": "enum",
        "values": "$names",
    }
    set_vars(d, tdir="/srv", c=["nginx"], names=["a"])
    p = parse_policy(dump(d))
    assert p.servers["prod"].actions["unit"].parameters["unit"].values == ("nginx",)


@pytest.mark.parametrize(
    "values,reason",
    [
        (["$c"], "list variable must be the whole values field"),
        (["ok", "${c}"], "variables are not allowed here"),
        (["pre${c}post"], "variables are not allowed here"),
    ],
)
def test_misplaced_var_in_enum_values_rejected(values: list[str], reason: str) -> None:
    d = good()
    set_vars(d, c=["a"])
    d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"]["values"] = values
    i = len(values) - 1
    path = f"projects.prod.actions.unit.parameters.unit.values[{i}]"
    assert f"{path}: {reason}" in errors_of(d)


def test_misplaced_var_in_shared_enum_values_rejected() -> None:
    d = good()
    d["parameters"] = {"cs": {"type": "enum", "values": ["ok", "$c"]}}
    assert "parameters.cs.values[1]: list variable must be the whole values field" in errors_of(d)


def test_list_var_syntax_as_whole_arg_rejected() -> None:
    d = good()
    set_vars(d, containers=["a"])
    action(d)["args"][3] = "$containers"
    errs = errors_of(d)
    assert "projects.prod.actions.tail.args[3]: list variables are not allowed in args" in errs


@pytest.mark.parametrize("arg", ["$NF/x", "/srv/a$b", "$", "$$x", "price$"])
def test_dollar_inside_longer_arg_accepted(arg: str) -> None:
    d = good()
    action(d)["args"][3] = arg
    assert parse_policy(dump(d)).servers["prod"].actions["tail"].args[3] == arg


@pytest.mark.parametrize(
    "value,path", [("", "projects.prod.vars.v"), (["ok", ""], "projects.prod.vars.v[1]")]
)
def test_empty_var_value_rejected(value: Any, path: str) -> None:
    d = good()
    set_vars(d, v=value)
    action(d)["args"][3] = "${v}"
    assert f"{path}: must not be empty" in errors_of(d)


def test_two_templates_same_action_id_collide() -> None:
    d = good()
    d["templates"] = {
        "t1": {"actions": {"disk": tpl_action(d)}},
        "t2": {"actions": {"disk": tpl_action(d)}},
    }
    d["projects"]["prod"]["use"] = ["t1", "t2"]
    errs = errors_of(d)
    assert (
        "projects.prod.use.t2.actions.disk: duplicate action id"
        " (also defined in projects.prod.use.t1.actions.disk)"
    ) in errs


def dir_template(d: dict[str, Any], **tvars: Any) -> None:
    """Template `t` with one action `log` reading `${dir}/x.log`, defaults `tvars`."""
    t = tpl_action(d)
    t["args"][3] = "${dir}/x.log"
    d["templates"] = {"t": {"vars": tvars, "actions": {"log": t}}}


def test_template_default_var_used_when_unset() -> None:
    d = good()
    dir_template(d, dir="/tpl")
    d["projects"]["prod"]["use"] = ["t"]
    assert parse_policy(dump(d)).servers["prod"].actions["log"].args[3] == "/tpl/x.log"


def test_template_default_overridden_by_host_then_project() -> None:
    d = good()
    dir_template(d, dir="/tpl")
    d["hosts"]["prod-host"]["vars"] = {"dir": "/host"}
    d["projects"]["prod"]["use"] = ["t"]
    d["projects"]["b"] = {"enabled": True, "host": "prod-host", "use": ["t"], "vars": {"dir": "/b"}}
    p = parse_policy(dump(d))
    assert p.servers["prod"].actions["log"].args[3] == "/host/x.log"
    assert p.servers["b"].actions["log"].args[3] == "/b/x.log"


def test_host_template_default_overridden_by_host_not_project() -> None:
    d = good()
    dir_template(d, dir="/tpl")
    d["hosts"]["prod-host"]["use"] = ["t"]
    d["projects"]["b"] = {"enabled": True, "host": "prod-host"}
    d["hosts"]["other"] = {"ssh_alias": "o", "use": ["t"], "vars": {"dir": "/host"}}
    d["projects"]["c"] = {"enabled": True, "host": "other"}
    p = parse_policy(dump(d))
    assert p.servers["b"].actions["log"].args[3] == "/tpl/x.log"
    assert p.servers["c"].actions["log"].args[3] == "/host/x.log"


def test_template_default_list_var_becomes_enum() -> None:
    d = good()
    t = tpl_action(d)
    t["args"] = ["status", "{unit}"]
    t["parameters"] = {"unit": {"type": "enum", "values": "$units"}}
    d["templates"] = {"t": {"vars": {"units": ["nginx", "php"]}, "actions": {"st": t}}}
    d["projects"]["prod"]["use"] = ["t"]
    a = parse_policy(dump(d)).servers["prod"].actions["st"]
    assert a.parameters["unit"].values == ("nginx", "php")


def test_template_default_not_visible_outside_its_template() -> None:
    d = good()
    dir_template(d, dir="/tpl")
    d["projects"]["prod"]["use"] = ["t"]
    action(d)["args"][3] = "${dir}/y.log"
    assert "projects.prod.actions.tail.args[3]: undefined variable 'dir'" in errors_of(d)


def test_unused_template_var_rejected() -> None:
    d = good()
    dir_template(d, dir="/tpl", dri="/typo")
    assert "templates.t.vars.dri: unused variable" in errors_of(d)


def test_template_var_used_through_shared_enum_accepted() -> None:
    d = good()
    d["parameters"] = {"cs": ENUM_VAR}
    t = tpl_action(d)
    t["args"] = ["logs", "{c}"]
    t["parameters"] = {"c": "cs"}
    d["templates"] = {"t": {"vars": {"c": ["app"]}, "actions": {"logs": t}}}
    d["projects"]["prod"]["use"] = ["t"]
    assert parse_policy(dump(d)).servers["prod"].actions["logs"].parameters["c"].values == ("app",)


def test_invalid_template_var_rejected() -> None:
    d = good()
    dir_template(d, dir="/a{b}")
    assert "templates.t.vars.dir: contains a brace" in errors_of(d)


def _over_cap(d: dict[str, Any]) -> dict[str, Any]:
    for i in range(policy.MAX_ERRORS + 5):
        d[f"junk{i}"] = 1
    return d


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(templates={"t": {"description": "x"}}),
        lambda d: d.update(templates={"t": {"actions": [1, 2]}}),
        lambda d: d["projects"]["prod"].pop("enabled"),
        lambda d: d["hosts"]["prod-host"].update(vars=[1]),
        lambda d: d["projects"]["prod"].update(vars={"v": 1}),
        lambda d: action(d).update(args=7),
    ],
)
def test_error_cap_reached_never_crashes(mutate: Any) -> None:
    d = _over_cap(good())
    mutate(d)
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert len(e.value.errors) == policy.MAX_ERRORS


def mutations() -> list[tuple[str, Any]]:
    def f(fn: Any) -> Any:
        def run(d: dict[str, Any]) -> None:
            fn(d)

        return run

    def srv(d: dict[str, Any]) -> dict[str, Any]:
        s: dict[str, Any] = d["projects"]["prod"]
        return s

    def host(d: dict[str, Any]) -> dict[str, Any]:
        h: dict[str, Any] = d["hosts"]["prod-host"]
        return h

    cases: list[tuple[str, Any]] = [
        ("unknown_top", f(lambda d: d.update(extra=1))),
        ("unknown_defaults", f(lambda d: d["defaults"].update(extra=1))),
        ("unknown_project_field", f(lambda d: srv(d).update(extra=1))),
        ("unknown_host_field", f(lambda d: host(d).update(extra=1))),
        ("unknown_action", f(lambda d: action(d).update(extra=1))),
        ("unknown_param", f(lambda d: action(d)["parameters"]["lines"].update(extra=1))),
        ("version1", f(lambda d: d.update(version=1))),
        ("missing_hosts", f(lambda d: d.pop("hosts"))),
        ("missing_projects", f(lambda d: d.pop("projects"))),
        ("servers_present", f(lambda d: d.update(servers={}))),
        ("unknown_host_ref", f(lambda d: srv(d).update(host="nope"))),
        ("host_alias_dash", f(lambda d: host(d).update(ssh_alias="-oProxyCommand=x"))),
        ("project_enabled_not_bool", f(lambda d: srv(d).update(enabled="yes"))),
        (
            "dup_id_host_vs_project",
            f(lambda d: host(d).update(actions={"tail": copy.deepcopy(action(d))})),
        ),
        ("disable_unknown", f(lambda d: srv(d).update(disable=["nope"]))),
        ("disable_not_list", f(lambda d: srv(d).update(disable="tail"))),
        (
            "too_many_actions",
            f(
                lambda d: srv(d)["actions"].update(
                    {f"a{i}": copy.deepcopy(action(d)) for i in range(201)}
                )
            ),
        ),
        ("version_bool", f(lambda d: d.update(version=True))),
        ("missing_defaults", f(lambda d: d.pop("defaults"))),
        ("missing_alias", f(lambda d: host(d).pop("ssh_alias"))),
        ("decision_allow", f(lambda d: d["defaults"].update(decision="allow"))),
        ("bad_project_id", f(lambda d: d["projects"].update({"-x": srv(d)}))),
        ("bad_host_id", f(lambda d: d["hosts"].update({"-x": host(d)}))),
        ("bad_action_id", f(lambda d: srv(d)["actions"].update({"a b": action(d)}))),
        ("alias_dash", f(lambda d: host(d).update(ssh_alias="-oProxyCommand=x"))),
        ("alias_empty", f(lambda d: host(d).update(ssh_alias=""))),
        ("alias_space", f(lambda d: host(d).update(ssh_alias="a b"))),
        ("alias_meta", f(lambda d: host(d).update(ssh_alias="a;b"))),
        ("alias_ctrl", f(lambda d: host(d).update(ssh_alias="a\nb"))),
        ("risk_write", f(lambda d: action(d).update(risk="write"))),
        ("timeout_zero", f(lambda d: d["defaults"].update(timeout_seconds=0))),
        ("timeout_121", f(lambda d: d["defaults"].update(timeout_seconds=121))),
        ("bytes_262145", f(lambda d: d["defaults"].update(max_output_bytes=262145))),
        ("conc_9", f(lambda d: d["defaults"].update(max_concurrent_actions=9))),
        ("conc_bool", f(lambda d: d["defaults"].update(max_concurrent_actions=True))),
        ("desc_long", f(lambda d: srv(d).update(description="x" * 201))),
        ("desc_ctrl", f(lambda d: srv(d).update(description="a\x00b"))),
        ("desc_nonstr", f(lambda d: srv(d).update(description=5))),
        ("exec_relative", f(lambda d: action(d).update(executable="tail"))),
        ("exec_dotdot", f(lambda d: action(d).update(executable="/usr/../bin/tail"))),
        ("exec_space", f(lambda d: action(d).update(executable="/usr/bin/ta il"))),
        ("exec_unnormalized", f(lambda d: action(d).update(executable="/usr//bin/tail"))),
        ("exec_nonstr", f(lambda d: action(d).update(executable=3))),
        ("args_embedded", f(lambda d: action(d).update(args=["--lines={lines}", "x"]))),
        ("args_lone_brace", f(lambda d: action(d).update(args=["{lines}", "}"]))),
        ("args_unknown_placeholder", f(lambda d: action(d).update(args=["{lines}", "{nope}"]))),
        ("args_unused_param", f(lambda d: action(d).update(args=["-n"]))),
        ("args_nul", f(lambda d: action(d).update(args=["{lines}", "a\x00b"]))),
        ("args_lf", f(lambda d: action(d).update(args=["{lines}", "a\nb"]))),
        ("args_nonstr", f(lambda d: action(d).update(args=["{lines}", 1]))),
        ("param_raw", f(lambda d: action(d)["parameters"].update(lines={"type": "raw"}))),
        ("param_shell", f(lambda d: action(d)["parameters"].update(lines={"type": "shell"}))),
        (
            "param_args_extra",
            f(lambda d: action(d)["parameters"].update(lines={"type": "args_extra"})),
        ),
        ("param_unknown_type", f(lambda d: action(d)["parameters"].update(lines={"type": "x"}))),
        ("int_float", f(lambda d: action(d)["parameters"]["lines"].update(minimum=1.5))),
        ("int_bool", f(lambda d: action(d)["parameters"]["lines"].update(minimum=True))),
        ("int_min_gt_max", f(lambda d: action(d)["parameters"]["lines"].update(minimum=300))),
        ("int_negative_min", f(lambda d: action(d)["parameters"]["lines"].update(minimum=-5))),
        ("int_missing_max", f(lambda d: action(d)["parameters"]["lines"].pop("maximum"))),
        (
            "enum_empty",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=[]
                )
            ),
        ),
        (
            "enum_dash",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=["-x"]
                )
            ),
        ),
        (
            "enum_dotdot",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=["a/../b"]
                )
            ),
        ),
        (
            "enum_ctrl",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=["a\tb"]
                )
            ),
        ),
        (
            "enum_toolong",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=["a" * 257]
                )
            ),
        ),
        (
            "enum_65",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["unit"].update(
                    values=[str(i) for i in range(65)]
                )
            ),
        ),
        (
            "str_maxlen_0",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"].update(
                    max_length=0
                )
            ),
        ),
        (
            "str_maxlen_257",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"].update(
                    max_length=257
                )
            ),
        ),
        (
            "str_bad_regex",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"].update(
                    pattern="("
                )
            ),
        ),
        (
            "str_long_pattern",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"].update(
                    pattern="a" * 257
                )
            ),
        ),
        (
            "str_missing_pattern",
            f(
                lambda d: d["projects"]["prod"]["actions"]["unit"]["parameters"]["name"].pop(
                    "pattern"
                )
            ),
        ),
        ("projects_not_dict", f(lambda d: d.update(projects=[]))),
        ("shared_params_not_dict", f(lambda d: d.update(parameters=[]))),
        ("shared_param_unknown_ref", f(lambda d: d.update(parameters={}) or use_shared(d, "nope"))),
        (
            "shared_param_invalid_spec",
            f(
                lambda d: d.update(
                    parameters={"lines": {"type": "integer", "minimum": 9, "maximum": 1}}
                )
            ),
        ),
        (
            "shared_param_bad_id",
            f(lambda d: d.update(parameters={"-bad": SHARED_LINES})),
        ),
        (
            "shared_param_forbidden_type",
            f(lambda d: d.update(parameters={"lines": {"type": "raw"}})),
        ),
        (
            "shared_param_bad_values_ref",
            f(lambda d: d.update(parameters={"e": {"type": "enum", "values": "nginx"}})),
        ),
        ("templates_not_dict", f(lambda d: d.update(templates=[]))),
        ("template_bad_id", f(lambda d: d.update(templates={"-bad": {"actions": {}}}))),
        ("template_not_object", f(lambda d: d.update(templates={"t": []}))),
        ("template_unknown_field", f(lambda d: d.update(templates={"t": {"actions": {}, "x": 1}}))),
        ("template_missing_actions", f(lambda d: d.update(templates={"t": {}}))),
        ("template_actions_not_dict", f(lambda d: d.update(templates={"t": {"actions": []}}))),
        (
            "template_description_too_long",
            f(lambda d: d.update(templates={"t": {"actions": {}, "description": "x" * 201}})),
        ),
        ("use_unknown_template", f(lambda d: d["projects"]["prod"].update(use=["nope"]))),
        ("use_not_list", f(lambda d: d["projects"]["prod"].update(use="t"))),
        ("use_item_not_string", f(lambda d: d["projects"]["prod"].update(use=[1]))),
        (
            "use_duplicate",
            f(
                lambda d: (
                    d.update(templates={"t": {"actions": {}}}),
                    d["projects"]["prod"].update(use=["t", "t"]),
                )
            ),
        ),
        ("host_use_unknown_template", f(lambda d: d["hosts"]["prod-host"].update(use=["nope"]))),
        ("host_use_not_list", f(lambda d: d["hosts"]["prod-host"].update(use={}))),
        ("hosts_not_dict", f(lambda d: d.update(hosts=[]))),
        ("var_undefined_arg", f(lambda d: action(d)["args"].__setitem__(3, "${nope}/x.log"))),
        (
            "var_undefined_enum",
            f(lambda d: action(d).update(args=["{c}"], parameters={"c": ENUM_VAR})),
        ),
        (
            "var_list_in_arg",
            f(lambda d: (set_vars(d, c=["a"]), action(d)["args"].__setitem__(3, "${c}"))),
        ),
        (
            "var_string_in_enum",
            f(
                lambda d: (
                    set_vars(d, c="a"),
                    action(d).update(args=["{c}"], parameters={"c": ENUM_VAR}),
                )
            ),
        ),
        (
            "var_in_executable",
            f(lambda d: (set_vars(d, b="/usr/bin"), action(d).update(executable="${b}/tail"))),
        ),
        (
            "var_in_description",
            f(lambda d: (set_vars(d, b="x"), action(d).update(description="Tail ${b}"))),
        ),
        ("var_value_dash", f(lambda d: set_vars(d, x="-rf"))),
        ("var_value_dotdot", f(lambda d: set_vars(d, x="/a/../b"))),
        ("var_value_newline", f(lambda d: set_vars(d, x="a\nb"))),
        ("var_list_empty", f(lambda d: set_vars(d, x=[]))),
        ("var_list_65", f(lambda d: set_vars(d, x=[f"v{i}" for i in range(65)]))),
        ("var_bad_name", f(lambda d: set_vars(d, **{"1x": "a"}))),
        ("var_value_not_string", f(lambda d: set_vars(d, x=5))),
        ("var_list_item_not_string", f(lambda d: set_vars(d, x=["a", 5]))),
        ("var_list_item_brace", f(lambda d: set_vars(d, x=["a", "{b}"]))),
        ("vars_not_dict", f(lambda d: d["projects"]["prod"].update(vars=[]))),
        ("host_vars_not_dict", f(lambda d: d["hosts"]["prod-host"].update(vars="x"))),
        ("host_var_value_dash", f(lambda d: d["hosts"]["prod-host"].update(vars={"x": "-r"}))),
    ]
    for name in policy.DENYLIST_SAMPLES:
        cases.append(
            (f"deny_{name}", f(lambda d, n=name: action(d).update(executable=f"/usr/bin/{n}")))
        )
    return cases


@pytest.mark.parametrize("name,mut", mutations(), ids=[m[0] for m in mutations()])
def test_invalid_policy_rejected(name: str, mut: Any) -> None:
    d = copy.deepcopy(good())
    mut(d)
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert e.value.errors


def test_invalid_json_rejected() -> None:
    with pytest.raises(PolicyInvalidError):
        parse_policy(b"{not json")


def test_non_utf8_and_non_object_rejected() -> None:
    for raw in (b"\xff\xfe", b"[]", b"1"):
        with pytest.raises(PolicyInvalidError):
            parse_policy(raw)


def test_duplicate_keys_rejected() -> None:
    raw = b'{"version":2,"version":2}'
    with pytest.raises(PolicyInvalidError):
        parse_policy(raw)


def test_nan_rejected() -> None:
    d = dump(good()).replace(b"15", b"NaN", 1)
    with pytest.raises(PolicyInvalidError):
        parse_policy(d)


def test_denylist_covers_spec_names() -> None:
    for n in [
        "sh",
        "bash",
        "zsh",
        "dash",
        "python",
        "python3",
        "python3.12",
        "perl",
        "perl5.34",
        "ruby",
        "node",
        "nodejs",
        "env",
        "sudo",
        "su",
        "busybox",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "php",
        "php8.1",
        "lua",
        "lua5.4",
        "awk",
        "gawk",
        "mawk",
        "sed",
        "find",
        "xargs",
        "doas",
        "pkexec",
        "ssh",
        "scp",
        "sftp",
        "nohup",
        "timeout",
        "nice",
        "script",
        "expect",
        "vi",
        "vim",
        "view",
        "less",
        "more",
        "tee",
        "dd",
    ]:
        assert policy.is_denied_executable(f"/usr/bin/{n}"), n
    for n in ["tail", "cat", "systemctl", "journalctl", "df"]:
        assert not policy.is_denied_executable(f"/usr/bin/{n}"), n


def test_error_messages_sanitized_and_name_path() -> None:
    d = good()
    d["projects"]["prod"]["actions"]["tail"]["executable"] = "/bin/SECRET\x1b[31m bash"
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    text = "\n".join(e.value.errors)
    d["hosts"]["prod-host"]["ssh_alias"] = "SECRETALIAS;rm"
    with pytest.raises(PolicyInvalidError) as e2:
        parse_policy(dump(d))
    text += "\n".join(e2.value.errors)
    assert "hosts.prod-host.ssh_alias" in text
    assert "projects.prod.actions.tail.executable" in text
    assert "SECRET" not in text
    assert "\x1b" not in text


def test_unknown_key_name_is_escaped_in_error() -> None:
    d = good()
    d["evil\x1b[2J" + "k" * 200] = 1
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    text = "\n".join(e.value.errors)
    assert "\x1b" not in text
    assert len(text) < 400


def test_error_list_capped() -> None:
    d = good()
    d["projects"] = {f"-{i}": {} for i in range(500)}
    with pytest.raises(PolicyInvalidError) as e:
        parse_policy(dump(d))
    assert len(e.value.errors) <= policy.MAX_ERRORS


def test_string_value_violation() -> None:
    v = policy.string_value_violation
    assert v("abc", 10) is None
    assert v("abc", 2) is not None
    assert v("-x", 10) is not None
    assert v("a\x00", 10) is not None
    assert v("a\nb", 10) is not None
    assert v("a/../b", 10) is not None
    assert v("..", 10) is not None
    assert v("a..b", 10) is None
    assert v("", 10) is None


def write_policy(root: Path, d: dict[str, Any], mode: int = 0o600) -> Path:
    config.ensure_layout(root)
    p = config.policy_path(root)
    p.write_bytes(dump(d))
    p.chmod(mode)
    return p


def test_load_policy_ok_and_records_hash(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    write_policy(root, good())
    p = policy.load_policy(root)
    assert p.path == config.policy_path(root).resolve()
    assert not policy.policy_changed_since_load(p)
    config.policy_path(root).write_bytes(dump(good()) + b" ")
    assert policy.policy_changed_since_load(p)


def test_changed_when_file_removed(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    path = write_policy(root, good())
    p = policy.load_policy(root)
    path.unlink()
    assert policy.policy_changed_since_load(p)


def test_load_rejects_0644(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    write_policy(root, good(), 0o666)
    with pytest.raises(config.PolicyPermissionError):
        policy.load_policy(root)


def test_load_rejects_escaping_symlink(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    config.ensure_layout(root)
    outside = tmp_path / "outside.json"
    outside.write_bytes(dump(good()))
    outside.chmod(0o600)
    os.symlink(outside, config.policy_path(root))
    with pytest.raises(config.PolicyPermissionError):
        policy.load_policy(root)


def test_load_missing(tmp_path: Path) -> None:
    config.ensure_layout(tmp_path / "wg")
    with pytest.raises(config.PolicyPermissionError):
        policy.load_policy(tmp_path / "wg")


def test_load_invalid_raises_invalid(tmp_path: Path) -> None:
    root = tmp_path / "wg"
    d = good()
    d["version"] = 1
    write_policy(root, d)
    with pytest.raises(PolicyInvalidError):
        policy.load_policy(root)


STARTER = Path(__file__).parents[1] / "examples" / "policy.starter.json"
V1_CAPS = {
    a: 65536
    for a in (
        "nginx_error_tail", "nginx_error_grep", "nginx_rotated_log_read", "nginx_config_test",
        "apache_error_tail", "apache_php_fatal_grep", "apache_config_test", "apache_vhosts",
        "php_fpm_error_tail", "php_fpm_slow_tail", "wordpress_debug_tail", "service_status",
        "service_journal", "docker_ps", "docker_logs_tail", "docker_logs_since",
        "docker_compose_logs", "docker_stats", "journal_errors", "kernel_oom_events",
        "kernel_messages", "failed_services", "disk_usage", "disk_inodes", "memory_usage",
        "load_average", "listening_ports",
    )
}  # fmt: skip
V1_CAPS.update(
    {
        a: 32768
        for a in (
            "nginx_access_tail", "nginx_access_grep", "nginx_rotated_log_grep",
            "apache_access_tail",
        )
    }
)  # fmt: skip


def test_starter_policy_is_valid_and_keeps_v1_limits() -> None:
    p = parse_policy(STARTER.read_bytes())
    found = {aid: a for s in p.servers.values() for aid, a in s.actions.items()}
    for aid, cap in V1_CAPS.items():
        assert found[aid].max_output_bytes == cap and found[aid].timeout_seconds == 20
    w = found["docker_logs_window"]
    assert w.max_output_bytes == 262144
    assert w.parameters["since"].values == ("60m", "50m", "40m", "30m", "20m", "10m")
    assert all(not s.enabled for s in p.servers.values())


# The v1 starter (commit 49bd344), kept verbatim so the v2 rewrite stays pinned to it.
V1_STARTER = Path(__file__).parent / "fixtures" / "policy.v1.starter.json"


def _spec_as_v1(spec: policy.ParameterSpec) -> dict[str, Any]:
    if spec.type == "integer":
        return {"type": "integer", "minimum": spec.minimum, "maximum": spec.maximum}
    if spec.type == "enum":
        return {"type": "enum", "values": list(spec.values or ())}
    return {"type": "string", "max_length": spec.max_length, "pattern": spec.pattern}


def test_starter_expands_to_v1_commands() -> None:
    v1 = json.loads(V1_STARTER.read_bytes())["servers"]["web-prod"]["actions"]
    p = parse_policy(STARTER.read_bytes())
    found: dict[str, policy.Action] = {}
    for s in p.servers.values():
        for aid, a in s.actions.items():
            # an action that several projects share must expand identically in each
            assert found.setdefault(aid, a) == a
    assert set(v1) <= set(found)
    assert set(found) - set(v1) == {"docker_logs_window"}
    for aid, raw in v1.items():
        a = found[aid]
        assert a.executable == raw["executable"], aid
        assert list(a.args) == raw["args"], aid
        assert {k: _spec_as_v1(v) for k, v in a.parameters.items()} == raw["parameters"], aid
