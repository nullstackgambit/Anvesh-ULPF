"""Scenario 3 - unknown-source onboarding, end to end, in an isolated home.

unknown traffic (SYNTHETIC TEST DATA, fictional "Blackbox Gateway") is in the
archive + DLQ -> `ulpf fingerprint` finds one cluster -> `ulpf onboard` writes
a draft -> `ulpf gate` PASS -> a reviewer edits the draft -> `ulpf promote`
refuses the stale gate -> re-gate -> `ulpf promote` -> replaying the archive
now parses every event with values equal to the generator's ground truth.
Negative: a greedy draft that would steal other sources' events fails the
regression gate.

Runs real Vector batch pipelines (several minutes).
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import helpers  # noqa: E402

pytestmark = [pytest.mark.vector, pytest.mark.slow]
SPEC = "acme.blackbox.flow"


@pytest.fixture(scope="module")
def home(tmp_path_factory):
    d = tmp_path_factory.mktemp("onboarding")
    h = d / "home"
    env = helpers.isolated_home(h)
    truth = d / "truth.ndjson"
    p = subprocess.run([sys.executable, str(helpers.REPO / "tests" / "helpers.py"), "seed-unknown", "120", "11", str(truth)],
                       env=env, capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr[-3000:]
    return env, h, truth


def test_unknown_source_onboarding_end_to_end(home):
    env, h, truth = home
    cl = json.loads(helpers.ulpf(env, "fingerprint", "--json").stdout)
    assert [(c["count"], c["format"]) for c in cl] == [(120, "text")]
    fp = cl[0]["fingerprint"]

    out = helpers.ulpf(env, "onboard", fp, "--id", SPEC, "--vendor", "Blackbox (fictional)",
                       "--product", "Blackbox Gateway", "--samples", "synthetic").stdout
    draft = h / "specs" / "_drafts" / f"{SPEC}.yaml"
    assert draft.exists() and "review required:" in out
    # a draft is never live
    rep = json.loads(helpers.ulpf(env, "spec", "compile", "--check").stdout)
    assert SPEC not in {s["id"] for s in rep["specs"]}

    g = helpers.ulpf(env, "gate", str(draft), check=False)
    assert g.returncode == 0, g.stdout
    gate = json.loads((h / "runtime" / "data" / "onboarding" / SPEC / "gate.json").read_text())
    assert gate["verdict"] == "PASS" and [x["name"] for x in gate["gates"]] == ["lint", "compile", "draft_tests", "regression", "samples"]

    # reviewer maps the gateway name; the earlier gate no longer applies
    text = draft.read_text()
    text = text.replace("  profiles:\n  - security_control\n", "  profiles: [host, security_control]\n", 1)
    text = re.sub(r"  # not mapped \(kept in `unmapped` automatically\): h0, h2, h3",
                  "  h2: {to: device.hostname, type: string}  # reviewer\n  # not mapped: h0, h3", text, count=1)
    assert "h2: {to: device.hostname" in text
    draft.write_text(text)
    p = helpers.ulpf(env, "promote", str(draft), "--approver", "Test Reviewer", check=False)
    assert p.returncode != 0 and "changed after it was gated" in p.stderr
    p = helpers.ulpf(env, "promote", str(draft), "--approver", "llm", check=False)
    assert p.returncode != 0 and "human approver" in p.stderr

    helpers.ulpf(env, "gate", str(draft))
    res = json.loads(helpers.ulpf(env, "promote", str(draft), "--approver", "Test Reviewer", "--note", "e2e").stdout)
    spec_file = h / "specs" / "acme" / "blackbox_flow.yaml"
    assert res["promoted"] == "specs/acme/blackbox_flow.yaml" and spec_file.exists() and not draft.exists()
    body = spec_file.read_text()
    assert "status: approved" in body and "approved_by: Test Reviewer" in body
    assert len(list((h / "tests" / "golden" / SPEC).glob("*.expected.json"))) == 5
    assert (h / "runtime" / "data" / "state" / "drift" / f"{SPEC}.baseline.json").exists()
    build = json.loads((h / "pipeline" / "vector" / "generated" / "BUILD.json").read_text())
    assert SPEC in {s["id"] for s in build["specs"]}
    audit = [json.loads(x) for x in (h / "runtime" / "data" / "state" / "promotions.ndjson").read_text().splitlines()]
    assert audit[-1]["spec_id"] == SPEC and audit[-1]["config_sha256"] == build["config_sha256"]

    # the promoted spec's own vectors (with goldens) pass through `ulpf test`
    helpers.ulpf(env, "test", "--spec", SPEC)
    # replay the archive: every event now parsed, values == ground truth
    p = subprocess.run([sys.executable, str(helpers.REPO / "tests" / "helpers.py"), "replay-check", str(truth), SPEC],
                       env=env, capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr[-3000:]
    chk = json.loads(p.stdout)
    assert chk["records"] == chk["events"] == 120 and chk["status"] == {"parsed": 120}, chk
    assert chk["n_bad"] == 0, chk["mismatches"]


def test_greedy_draft_fails_regression_gate(home):
    env, h, _ = home
    src = h / "specs" / "acme" / "blackbox_flow.yaml"
    if not src.exists():
        pytest.skip("depends on the promoted spec from the previous test")
    text = src.read_text()
    text = text.replace("id: acme.blackbox.flow", "id: acme.greedy.flow").replace("status: approved", "status: draft")
    text = re.sub(r"^priority: \d+$", "priority: 999", text, flags=re.M)
    text = re.sub(r"^match:\n(?:  .*\n)+", "match:\n  any:\n  - {field: body, regex: '.'}\n", text, flags=re.M)
    text = text.replace("ulpf.parser.id: acme.blackbox.flow", "ulpf.parser.id: acme.greedy.flow")
    text = text.split("\napproval:\n")[0] + "\n"
    draft = h / "specs" / "_drafts" / "acme.greedy.flow.yaml"
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(text)
    p = helpers.ulpf(env, "gate", str(draft), "--json", check=False)
    assert p.returncode == 1
    rep = json.loads(p.stdout)
    gates = {g["name"]: g for g in rep["gates"]}
    assert rep["verdict"] == "FAIL" and gates["regression"]["ok"] is False
    stolen = gates["regression"]["data"]["failures"]
    assert stolen and all("acme.greedy.flow" in json.dumps(v) for v in stolen.values())
