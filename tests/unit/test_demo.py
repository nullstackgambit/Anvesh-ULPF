"""Demo traffic (ulpf/demo.py): the stream mix, the auto-stop caps and process
handling. The real generators are `ulpf gen` (SYNTHETIC TEST DATA); here a
sleeping Python child stands in for them, so nothing is sent anywhere."""
import sys

import pytest

from ulpf import demo, paths


def _opt(argv, flag):
    return argv[argv.index(flag) + 1]


def _vendors(argv):
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--vendor"]


def test_unknown_source_only_when_enabled():
    with_u = demo.commands(3, unknown=True, malformed=False)
    without = demo.commands(3, unknown=False, malformed=False)
    assert _vendors(with_u["main"]) == demo.VENDORS + ["blackbox"]
    assert _vendors(without["main"]) == demo.VENDORS
    assert set(with_u) == set(without) == {"main"}


def test_malformed_stream_and_auto_stop_caps():
    c = demo.commands(3, unknown=True, malformed=True)
    assert set(c) == {"main", "malformed"}
    assert _opt(c["main"], "--count") == str(3 * 15 * 60)              # stops after 15 minutes at 3/s
    assert _opt(c["malformed"], "--scenario") == "malformed"
    assert _opt(c["malformed"], "--eps") == "0.2"                        # max(0.2, 3/20)
    assert _opt(c["malformed"], "--count") == "180"                      # 0.2/s for 15 minutes
    big = demo.commands(40, unknown=False, malformed=True, minutes=2)
    assert _opt(big["malformed"], "--eps") == "2" and _opt(big["malformed"], "--count") == "240"
    for argv in [*c.values(), *big.values()]:
        assert argv[1] == "gen" and _opt(argv, "--transport") == "udp"
        assert _opt(argv, "--sendlog").endswith(".ndjson")


@pytest.mark.parametrize("eps,minutes", [(0, 5), (51, 5), (3, 0), (3, 16)])
def test_out_of_range_settings_are_refused(eps, minutes):
    with pytest.raises(ValueError):
        demo.commands(eps, unknown=True, malformed=True, minutes=minutes)


@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ("RUN", "LOGS", "RUNTIME", "HOME"):
        monkeypatch.setattr(paths, name, tmp_path / name.lower())
    (tmp_path / "home").mkdir()                  # the generators run with cwd = ULPF_HOME
    return tmp_path


def test_status_and_stop_without_a_demo_are_harmless(home):
    assert demo.status() == {"running": False}
    assert demo.stop() == {"running": False, "stopped": 0}


def test_start_status_stop(home, monkeypatch):
    # argv contains "gen", like the real `ulpf gen` command line
    monkeypatch.setattr(demo, "commands", lambda eps, **kw: {
        "main": [sys.executable, "-c", "import time; time.sleep(60)", "gen"],
        "malformed": [sys.executable, "-c", "import time; time.sleep(60)", "gen"]})
    st = demo.start(3, unknown=True, malformed=True, minutes=1)
    assert st["running"] and st["alive"] == ["main", "malformed"] and st["eps"] == 3
    assert demo.start(5)["eps"] == 3                                     # no second demo while one runs
    assert demo.stop()["stopped"] == 2
    assert demo.status() == {"running": False}                           # stopped children are reaped, not zombies


def test_a_finished_demo_reports_not_running(home, monkeypatch):
    monkeypatch.setattr(demo, "commands", lambda eps, **kw: {"main": [sys.executable, "-c", "pass", "gen"]})
    demo.start(3, minutes=1)
    import time
    deadline = time.time() + 10
    while demo.status()["running"] and time.time() < deadline:
        time.sleep(0.1)
    st = demo.status()
    assert not st["running"] and st["started_at"] and st["sent"] == 0   # state kept for "last demo finished"
