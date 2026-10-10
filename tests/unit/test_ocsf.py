import copy

import pytest

from ulpf.ocsf import Ocsf


@pytest.fixture(scope="module")
def o():
    return Ocsf()


GOOD = {
    "activity_id": 6, "activity_name": "Traffic", "category_uid": 4, "category_name": "Network Activity",
    "class_uid": 4001, "class_name": "Network Activity", "severity_id": 1, "severity": "Informational",
    "time": 1791368130123, "type_uid": 400106, "type_name": "Network Activity: Traffic",
    "metadata": {"version": "1.9.0", "product": {"name": "X", "vendor_name": "Y"}, "profiles": ["security_control"]},
    "src_endpoint": {"ip": "10.0.0.1", "port": 1234}, "action_id": 1, "action": "Allowed",
    "ulpf": {"ignored": "by the OCSF layers"},
}


def test_vendored_files_match_manifest(o):
    assert o.version == "1.9.0"
    assert o.verify_files() == []


def test_good_event_validates(o):
    r = o.validate(GOOD)
    assert r.ok, [str(i) for i in r.issues]


@pytest.mark.parametrize("mutate,needle", [
    (lambda e: e.update(type_uid=400101), "type_uid"),
    (lambda e: e.update(action="Denied"), "action"),
    (lambda e: e.update(invented=1), "invented"),
    (lambda e: e["src_endpoint"].update(port="abc"), "integer"),
    (lambda e: e["src_endpoint"].update(port=70000), "70000"),
    (lambda e: e.update(action_id=7), "action_id"),
    (lambda e: e["metadata"].update(version="1.8.0"), "metadata.version"),
    (lambda e: e.pop("src_endpoint"), "src_endpoint"),       # class constraint at_least_one
    (lambda e: e["metadata"].update(profiles=[]), "action"),  # profile attribute without profile
])
def test_invalid_events_are_caught(o, mutate, needle):
    e = copy.deepcopy(GOOD)
    mutate(e)
    r = o.validate(e)
    assert not r.ok
    assert any(needle in str(i) for i in r.issues), [str(i) for i in r.issues]


def test_resolve_honours_profiles(o):
    assert o.resolve("network_activity", "action_id", ["security_control"]).enum[2] == "Denied"
    with pytest.raises(KeyError, match="requires profile"):
        o.resolve("network_activity", "action_id", [])
    with pytest.raises(KeyError, match="requires profile"):
        o.resolve("network_activity", "device.hostname", ["security_control"])
    assert o.resolve("network_activity", "device.hostname", ["host", "security_control"]).type == "hostname_t"


def test_resolve_rejects_invented_and_array_paths(o):
    with pytest.raises(KeyError, match="not an attribute"):
        o.resolve("network_activity", "src_endpoint.nonexistent", [])
    with pytest.raises(KeyError, match="array"):
        o.resolve("network_activity", "observables.name", [])
