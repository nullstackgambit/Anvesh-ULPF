"""Run every approved spec's test vectors through the real Vector pipeline.

Each vector is checked for routing, expectations, OCSF + envelope validity,
completeness (independent oracle), raw round-trip and the golden file.
"""
import pytest

from ulpf.spec import discover
from ulpf.testing import run_spec_tests

pytestmark = pytest.mark.vector


@pytest.fixture(scope="module")
def results():
    return run_spec_tests(discover())


def test_there_are_vectors(results):
    assert len(results) >= 6


def test_every_vector_passes_every_check(results):
    failures = {f"{r.spec_id}::{r.name}": {k: v for k, v in r.checks.items() if v != "ok" and not v.startswith("skipped")}
                for r in results if not r.ok}
    assert not failures, failures


def test_completeness_oracle_ran(results):
    ran = [r for r in results if r.checks.get("completeness") == "ok"]
    assert len(ran) >= len(results) // 2, {r.name: r.checks.get("completeness") for r in results}
