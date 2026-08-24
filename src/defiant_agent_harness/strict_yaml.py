"""Bounded, alias-free, duplicate-safe YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

from .bounded_io import read_bounded_path_text

STRICT_YAML_PROFILE = "strict_yaml_v1"


class StrictYamlError(ValueError):
    """YAML input is ambiguous or unsafe to interpret as authority."""


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _StrictSafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise StrictYamlError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            line = key_node.start_mark.line + 1
            raise StrictYamlError(
                f"YAML contains a duplicate mapping key at line {line}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_bounded_yaml(
    path: str | Path,
    maximum: int,
    label: str,
) -> Any:
    """Read and strictly construct one bounded operator-authored YAML file."""

    document = read_bounded_path_text(path, maximum, label)
    try:
        if any(
            isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(document)
        ):
            raise StrictYamlError(f"{label} YAML aliases are not supported")
        return yaml.load(document, Loader=_StrictSafeLoader)
    except StrictYamlError:
        raise
    except (RecursionError, yaml.YAMLError) as exc:
        raise StrictYamlError(f"{label} is not valid YAML") from exc
