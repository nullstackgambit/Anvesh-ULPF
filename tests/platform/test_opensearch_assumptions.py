"""Regression tests for the OpenSearch behaviours ULPF relies on (P0 O1-O7, V11)."""
import json
import uuid

import pytest

from ulpf.opensearch import Client, OpenSearchError, index_template

pytestmark = pytest.mark.opensearch


@pytest.fixture
def c():
    return Client.from_settings()


@pytest.fixture
def idx(c):
    name = f"ulpf-platformtest-v{uuid.uuid4().hex[:8]}"
    yield name
    try:
        c.request("DELETE", f"/{name}")
    except OpenSearchError:
        pass


def test_O2_invalid_ip_rejects_document_without_ignore_malformed(c, idx):
    c.request("PUT", f"/{idx}", {"settings": {"number_of_replicas": 0},
                                 "mappings": {"properties": {"ip": {"type": "ip"}}}})
    with pytest.raises(OpenSearchError) as e:
        c.request("POST", f"/{idx}/_doc", {"ip": "10.1.1.300"})
    assert "mapper_parsing_exception" in e.value.body


def test_O3_ignore_malformed_keeps_document(c, idx):
    c.request("PUT", f"/{idx}", {"settings": {"number_of_replicas": 0, "index.mapping.ignore_malformed": True},
                                 "mappings": {"properties": {"ip": {"type": "ip"}}}})
    c.request("POST", f"/{idx}/_doc?refresh=true", {"ip": "10.1.1.300"})
    hits = c.search(idx, {"query": {"match_all": {}}})["hits"]["hits"]
    assert hits[0]["_ignored"] == ["ip"] and hits[0]["_source"]["ip"] == "10.1.1.300"


def test_O4_O5_template_types_flat_object_and_cidr(c, idx):
    t = index_template(index_prefix=idx[:-9])
    body = {"settings": t["template"]["settings"], "mappings": t["template"]["mappings"]}
    c.request("PUT", f"/{idx}", body)
    c.request("POST", f"/{idx}/_doc?refresh=true", {"src_endpoint": {"ip": "10.1.2.3", "port": 443},
                                                    "time": 1791368130123, "unmapped": {"a.b": "v", "n": {"x": "y"}}})
    m = c.request("GET", f"/{idx}/_mapping")[idx]["mappings"]["properties"]
    assert m["src_endpoint"]["properties"]["ip"]["type"] == "ip"
    assert m["src_endpoint"]["properties"]["port"]["type"] == "integer"
    assert m["time"] == {"type": "date", "format": "epoch_millis"}
    assert c.count(idx, {"term": {"src_endpoint.ip": "10.0.0.0/8"}}) == 1
    assert c.count(idx, {"term": {"unmapped.n.x": "y"}}) == 1


def test_O6_alias_swap_is_atomic(c, idx):
    other = idx + "b"
    c.request("PUT", f"/{idx}", {"settings": {"number_of_replicas": 0}})
    c.request("PUT", f"/{other}", {"settings": {"number_of_replicas": 0}})
    alias = idx + "-alias"
    try:
        c.aliases([{"add": {"index": idx, "alias": alias}}])
        c.aliases([{"remove": {"index": idx, "alias": alias}}, {"add": {"index": other, "alias": alias}}])
        assert c.alias_targets(alias) == [other]
    finally:
        c.request("DELETE", f"/{other}")
