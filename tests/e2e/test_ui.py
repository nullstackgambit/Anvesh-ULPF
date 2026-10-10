"""Every UI page renders against the running stack without exceptions."""
from pathlib import Path

import pytest

pytestmark = [pytest.mark.opensearch]
APP = Path(__file__).resolve().parents[2] / "ulpf" / "ui" / "app.py"


def test_all_pages_render():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP), default_timeout=180)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert {m.label for m in at.metric} >= {"OpenSearch", "Events indexed"}
    # the stack is up (this test needs OpenSearch): the tile must say so, with
    # the UI's own (reader) credentials when security is on
    assert {m.label: m.value for m in at.metric}["OpenSearch"] == "healthy"
    for page in ("Live feed", "Event explorer", "Unknown sources & onboarding", "Archive integrity", "Replay", "Detections"):
        at.radio(key="page").set_value(page).run()
        assert not at.exception, (page, [e.value for e in at.exception])
        assert not at.error, (page, [e.value for e in at.error])
        assert at.query_params["page"] == {"Live feed": "live", "Event explorer": "explorer",
                                           "Unknown sources & onboarding": "onboarding",
                                           "Archive integrity": "integrity", "Replay": "replay",
                                           "Detections": "detections"}[page]   # the view is a shareable URL


def test_page_and_text_size_come_from_the_url():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(APP), default_timeout=180)
    at.query_params["page"] = "integrity"
    at.query_params["ts"] = "lg"
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.radio(key="page").value == "Archive integrity"
    assert any("font-size: 18px" in h.proto.body for h in at.get("html"))


def _live(monkeypatch, demo_mode: bool):
    from streamlit.testing.v1 import AppTest

    if demo_mode:
        monkeypatch.setenv("ULPF_DEMO", "1")
    else:
        monkeypatch.delenv("ULPF_DEMO", raising=False)
    at = AppTest.from_file(str(APP), default_timeout=180)
    at.query_params["page"] = "live"
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error, [e.value for e in at.error]
    return at


def test_live_feed_has_demo_controls_only_in_demo_mode(monkeypatch):
    at = _live(monkeypatch, demo_mode=False)
    assert {"Events / second", "Received", "Parsed"} <= {m.label for m in at.metric}
    assert not [b for b in at.button if b.label in ("Start", "Stop")]
    at = _live(monkeypatch, demo_mode=True)
    assert [b for b in at.button if b.label in ("Start", "Stop")]       # nothing is clicked: no traffic is sent
