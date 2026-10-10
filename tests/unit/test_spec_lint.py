"""Negative tests for `ulpf spec lint`: every rule must actually fire."""
import textwrap

import pytest

from ulpf.spec import lint_file

BASE = textwrap.dedent("""\
    id: test.vendor.product
    version: 1.0.0
    vendor: T
    product: P
    samples: synthetic
    ocsf: {class: network_activity, profiles: [security_control]}
    match:
      all:
        - {field: kv.logtype, equals: traffic}
    parse: {kind: kv}
    time:
      - {field: ts, format: epoch_auto}
    fields:
      src: {to: src_endpoint.ip, type: ip}
      sport: {to: src_endpoint.port, type: port}
    enums:
      - source: act
        map:
          allow: {activity_id: 6, action_id: 1}
    tests:
      - {name: t1, raw: "logtype=traffic src=10.0.0.1 sport=1 act=allow ts=1791368130"}
    """)


def errors(tmp_spec, text):
    _, issues = lint_file(tmp_spec(text))
    return [str(i) for i in issues if i.level == "error"]


def test_base_spec_is_clean(tmp_spec):
    assert errors(tmp_spec, BASE) == []


@pytest.mark.parametrize("old,new,needle", [
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: src_endpoint.ipaddr, type: ip}", "not an attribute"),
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: src_endpoint.ip, type: port}", "cannot be written"),
    ("sport: {to: src_endpoint.port, type: port}", "sport: {to: src_endpoint.ip, type: ip}", "already written"),
    ("allow: {activity_id: 6, action_id: 1}", "allow: {activity_id: 6, action_id: 7}", "not a valid action_id"),
    ("allow: {activity_id: 6, action_id: 1}", "allow: {activity_id: 6, action: Allowed}", "is not of type 'integer'"),
    ("allow: {activity_id: 6, action_id: 1}", "allow: {activity_id: 6, severity: 1}", "not an enum attribute"),
    ("class: network_activity", "class: network_activityy", "unknown OCSF class"),
    ("profiles: [security_control]", "profiles: []", "requires profile"),
    ("profiles: [security_control]", "profiles: [security_control, nosuch]", "not defined for class"),
    ("version: 1.0.0", "version: 1.0.x", "does not match"),
    ("version: 1.0.0", "version: 1.0", "is not of type 'string'"),     # YAML float, rejected structurally
    ("id: test.vendor.product", "id: Test-Vendor", "does not match"),
    ("all:\n    - {field: kv.logtype, equals: traffic}", "all: []", "non-empty"),
    ("{field: kv.logtype, equals: traffic}", "{field: kv.logtype, regex: '(?=x)traffic'}", "look-around"),
    ("{field: kv.logtype, equals: traffic}", "{field: logtype, equals: traffic}", "must be body"),
    ("format: epoch_auto", "format: '%H:%M:%S'", "no year"),
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: class_uid, type: int}", "owned by ULPF"),
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: action, type: string}", "caption sibling"),
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: activity_id, type: int}", "enum attribute"),
    ("src: {to: src_endpoint.ip, type: ip}", "src: {to: src_endpoint, type: string}", "is an object"),
    ("sport: {to: src_endpoint.port, type: port}", "src: {to: src_endpoint.port, type: port}", "duplicate key"),
    ("sport: {to: src_endpoint.port, type: port}", "ts: {to: src_endpoint.port, type: port}", "used by both time and fields"),
])
def test_lint_rule_fires(tmp_spec, old, new, needle):
    assert old in BASE, old
    errs = errors(tmp_spec, BASE.replace(old, new))
    assert any(needle in e for e in errs), errs


def test_duplicate_yaml_key_is_a_lint_error(tmp_spec):
    text = BASE.replace("  sport: {to: src_endpoint.port, type: port}\n",
                        "  sport: {to: src_endpoint.port, type: port}\n  src: {to: dst_endpoint.ip, type: ip}\n")
    errs = errors(tmp_spec, text)
    assert any("duplicate key 'src'" in e for e in errs), errs


def test_missing_class_constraint_is_reported(tmp_spec):
    text = BASE.replace("src: {to: src_endpoint.ip, type: ip}", "src: {to: traffic.bytes_in, type: long}")
    text = text.replace("sport: {to: src_endpoint.port, type: port}", "sport: {to: traffic.bytes_out, type: long}")
    errs = errors(tmp_spec, text)
    assert any("at_least_one" in e for e in errs), errs
