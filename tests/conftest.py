import shutil

import pytest

from ulpf import paths


def _vector_ok() -> bool:
    return paths.VECTOR_BIN.exists()


def _opensearch_ok() -> bool:
    from ulpf.opensearch import Client

    try:
        Client.from_settings().info()   # https + CA + credentials when secured
        return True
    except Exception:  # noqa: BLE001
        return False


def pytest_collection_modifyitems(config, items):
    has_vector, has_os = _vector_ok(), _opensearch_ok()
    for item in items:
        if "vector" in item.keywords and not has_vector:
            item.add_marker(pytest.mark.skip(reason="Vector binary not installed"))
        if "opensearch" in item.keywords and not has_os:
            item.add_marker(pytest.mark.skip(reason="OpenSearch not reachable (ulpf stack up opensearch)"))


@pytest.fixture
def tmp_spec(tmp_path):
    """Write a spec YAML string to a temp file and return its path."""
    def _write(text: str, name: str = "s.yaml"):
        p = tmp_path / name
        p.write_text(text)
        return p
    return _write


@pytest.fixture(scope="session")
def scratch(tmp_path_factory):
    d = tmp_path_factory.mktemp("ulpf")
    yield d
    shutil.rmtree(d, ignore_errors=True)
