"""Drift signals on synthetic profiles (no Vector needed)."""
from ulpf.drift import Profile, compare


def _ev(status="parsed", lineage=None, unmapped=None, errors=None, fp="aaaa", version="1.0.0", cov=(10, 8, 2, 0)):
    f, m, u, e = cov
    return {"ulpf": {"status": status, "lineage": lineage if lineage is not None else {"src_endpoint.ip": "src", "dst_endpoint.ip": "dst"},
                     "errors": errors or [], "fingerprint": fp, "parser": {"version": version, "spec_sha256": "ab" * 32},
                     "coverage": {"fields": f, "mapped": m, "unmapped": u, "empty": e}},
            "unmapped": unmapped or {}}


def _prof(events):
    p = Profile()
    for e in events:
        p.add(e)
    return p


BASE = _prof([_ev() for _ in range(100)])


def kinds(sigs):
    return sorted(s.kind for s in sigs)


def test_no_drift_on_same_traffic():
    assert compare("x", BASE, _prof([_ev() for _ in range(50)])) == []


def test_low_volume_is_not_compared():
    assert kinds(compare("x", BASE, _prof([_ev(status="failed")] * 5))) == ["LOW_VOLUME"]


def test_new_unmapped_field():
    cur = _prof([_ev(unmapped={"newfield": "1"}) for _ in range(30)] + [_ev() for _ in range(20)])
    sig = compare("x", BASE, cur)
    assert kinds(sig) == ["NEW_UNMAPPED_FIELD"] and sig[0].data["key"] == "newfield"


def test_mapped_field_missing_and_ratio_drop():
    cur = _prof([_ev(lineage={"dst_endpoint.ip": "dst"}, cov=(10, 4, 6, 0)) for _ in range(50)])
    sig = compare("x", BASE, cur)
    assert kinds(sig) == ["MAPPED_FIELD_MISSING", "MAPPED_RATIO_DROP"]
    assert sig[0].severity == "high" and sig[0].data["attribute"] == "src_endpoint.ip"


def test_status_shift_and_new_error():
    cur = _prof([_ev(status="partial", errors=[{"code": "invalid_ip", "field": "src"}]) for _ in range(10)]
                + [_ev() for _ in range(40)])
    assert kinds(compare("x", BASE, cur)) == ["NEW_ERROR", "STATUS_SHIFT"]


def test_new_fingerprint_and_parser_version_are_informational():
    cur = _prof([_ev(fp="bbbb", version="1.1.0") for _ in range(50)])
    sig = compare("x", BASE, cur)
    assert kinds(sig) == ["NEW_FINGERPRINT", "PARSER_CHANGED"]
    assert {s.severity for s in sig} == {"info"}


def test_profile_round_trip():
    assert Profile.from_dict(BASE.to_dict()).to_dict() == BASE.to_dict()
