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
        ("templates_still_unknown", f(lambda d: d.update(templates={}))),
        ("hosts_not_dict", f(lambda d: d.update(hosts=[]))),
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


def test_starter_template_is_valid() -> None:
    path = Path(__file__).resolve().parent.parent / "examples" / "policy.starter.json"
    p = parse_policy(path.read_bytes())
    assert not p.servers["web-prod"].enabled  # copied template grants nothing until enabled
