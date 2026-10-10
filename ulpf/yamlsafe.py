"""Strict YAML loading for specifications and configuration.

PyYAML's ``safe_load`` has two behaviours that are dangerous for a mapping
DSL and are therefore disabled here:

* duplicate mapping keys are silently collapsed (the last one wins), which
  would let a spec define the same source field twice without anyone noticing;
* YAML 1.1 implicit booleans turn ``yes``/``no``/``on``/``off`` into booleans,
  which corrupts enum tables such as ``{on: 1, off: 0}``.

Only ``true``/``false`` (any case) are booleans; every other plain scalar that
is not a number or null stays a string.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


class DuplicateKeyError(yaml.YAMLError):
    pass


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with duplicate-key detection and YAML 1.2-style booleans."""


# Replace the YAML 1.1 bool resolver with a YAML 1.2 one.
StrictLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:bool"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def _construct_mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    seen: dict[Any, yaml.Node] = {}
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            first = seen[key].start_mark
            raise DuplicateKeyError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1} "
                f"(first defined at line {first.line + 1})"
            )
        seen[key] = key_node
    return loader.construct_mapping(node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def load_text(text: str) -> Any:
    return yaml.load(text, Loader=StrictLoader)  # noqa: S506 (StrictLoader derives from SafeLoader)


def load_file(path: str | Path) -> Any:
    return load_text(Path(path).read_text(encoding="utf-8"))
