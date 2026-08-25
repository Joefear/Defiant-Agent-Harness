from __future__ import annotations

import pytest

import defiant_agent_harness.strict_yaml as strict_yaml_module
from defiant_agent_harness.strict_yaml import StrictYamlError, load_bounded_yaml


def _load(tmp_path, content: str):
    path = tmp_path / "authority.yaml"
    path.write_text(content, encoding="utf-8")
    return load_bounded_yaml(path, 1024 * 1024, "authority document")


def test_yaml_nesting_exact_boundary_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NESTING_DEPTH", 2)

    assert _load(tmp_path, "value: [one]") == {"value": ["one"]}


def test_yaml_nesting_is_rejected_before_construction(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NESTING_DEPTH", 2)

    with pytest.raises(StrictYamlError, match="nesting exceeds maximum depth of 2"):
        _load(tmp_path, "value: [[one]]")


def test_deep_yaml_has_deterministic_structural_error(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NESTING_DEPTH", 64)
    content = "value: " + "[" * 300 + "one" + "]" * 300

    with pytest.raises(StrictYamlError, match="nesting exceeds maximum depth of 64"):
        _load(tmp_path, content)


def test_yaml_node_exact_boundary_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NODES", 5)

    assert _load(tmp_path, "values: [one, two]") == {"values": ["one", "two"]}


def test_yaml_node_count_is_rejected_before_construction(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NODES", 4)

    with pytest.raises(StrictYamlError, match="node count exceeds maximum of 4"):
        _load(tmp_path, "values: [one, two]")


def test_yaml_node_count_includes_mapping_keys_and_empty_collections(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NODES", 4)

    with pytest.raises(StrictYamlError, match="node count exceeds maximum of 4"):
        _load(tmp_path, "first: {}\nsecond: []\n")


def test_yaml_structural_failures_do_not_echo_source_or_path(tmp_path, monkeypatch):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NODES", 2)
    secret = "sensitive-authority-value"

    with pytest.raises(StrictYamlError) as failure:
        _load(tmp_path, f"first: {secret}\nsecond: another\n")

    assert secret not in str(failure.value)
    assert str(tmp_path) not in str(failure.value)
