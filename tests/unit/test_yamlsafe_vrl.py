import pytest

from ulpf import vrl
from ulpf.yamlsafe import DuplicateKeyError, load_text


def test_duplicate_keys_are_rejected():
    with pytest.raises(DuplicateKeyError, match="duplicate key 'srcip'"):
        load_text("fields:\n  srcip: {to: a}\n  srcip: {to: b}\n")


def test_nested_duplicate_keys_are_rejected():
    with pytest.raises(DuplicateKeyError):
        load_text("a:\n  b: 1\n  c:\n    d: 1\n    d: 2\n")


@pytest.mark.parametrize("word", ["yes", "no", "on", "off", "y", "n", "Yes", "OFF"])
def test_yaml11_booleans_stay_strings(word):
    assert load_text(f"k: {word}") == {"k": word}


@pytest.mark.parametrize("word,val", [("true", True), ("false", False), ("True", True), ("FALSE", False)])
def test_yaml12_booleans(word, val):
    assert load_text(f"k: {word}") == {"k": val}


def test_vrl_string_escapes_template_braces_and_quotes():
    s = vrl.string('a "{{ x }}" \\ \n\t\x00é')
    assert s == '"a \\"\\{\\{ x \\}\\}\\" \\\\ \\n\\t\\u{0}\\u{E9}"'


def test_vrl_regex_rejects_single_quote():
    with pytest.raises(ValueError):
        vrl.regex("it's")


def test_vrl_key_rejects_unsafe_names():
    assert vrl.key("s", "id.orig_h") == 's."id.orig_h"'
    for bad in ['a"b', "a\\b", "{{x}}"]:
        with pytest.raises(ValueError):
            vrl.key("s", bad)


def test_ocsf_path_segments_validated():
    assert vrl.ocsf_path("", "src_endpoint.ip") == ".src_endpoint.ip"
    with pytest.raises(ValueError):
        vrl.ocsf_path("", "src_endpoint.ip; abort")
