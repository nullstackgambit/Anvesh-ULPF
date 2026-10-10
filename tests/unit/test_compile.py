import textwrap

import pytest

from ulpf import paths, pipeline, settings, vector
from ulpf.compile import CompileError, compile_specs
from ulpf.spec import discover

BAD = textwrap.dedent("""\
    id: test.bad.spec
    version: 1.0.0
    vendor: T
    product: P
    ocsf: {class: network_activity}
    match: {all: [{field: kv.a, equals: b}]}
    parse: {kind: kv}
    fields:
      a: {to: src_endpoint.nope, type: ip}
    tests: [{name: t, raw: "a=b"}]
    """)


def test_compiler_refuses_specs_with_lint_errors(tmp_spec):
    with pytest.raises(CompileError, match="refusing to compile"):
        compile_specs([tmp_spec(BAD)])


@pytest.mark.vector
def test_all_approved_specs_compile_validate_and_have_no_vrl_warnings():
    pl, _ = compile_specs(discover())
    for p in pl.parsers:
        assert p.vrl.startswith("# GENERATED FILE - DO NOT EDIT"), p.spec_id
        assert f"spec sha256: {p.spec_sha256}" in p.vrl
        assert vector.vrl_warnings(p.vrl) == [], p.spec_id
    cfg = paths.RUNTIME / "tmp" / "test-live.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(pipeline.dump(pipeline.live_config(settings.load(), pl), specs=pl.parsers, purpose="test"))
    ok, log = vector.validate(cfg)
    assert ok, log[-3000:]


def test_hand_edited_generated_file_is_detected(tmp_path):
    f = tmp_path / "g.yaml"
    f.write_text(pipeline.dump({"sources": {}}, specs=[], purpose="t"))
    assert pipeline.check_generated(f)[0]
    f.write_text(f.read_text() + "# sneaky edit\n")
    ok, msg = pipeline.check_generated(f)
    assert not ok and "modified after generation" in msg
