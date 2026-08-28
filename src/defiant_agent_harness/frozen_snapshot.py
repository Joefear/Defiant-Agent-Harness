"""Immutable retention and defensive projection for canonical snapshots."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any


def freeze_snapshot(value: Any) -> Any:
    """Recursively freeze an already validated exact built-in tree."""
    if type(value) is dict:
        return MappingProxyType(
            {key: freeze_snapshot(child) for key, child in value.items()}
        )
    if type(value) in {list, tuple}:
        return tuple(freeze_snapshot(child) for child in value)
    return value


def thaw_snapshot(value: Any) -> Any:
    """Return a fresh built-in projection of a recursively frozen tree."""
    if isinstance(value, MappingProxyType):
        return {key: thaw_snapshot(child) for key, child in value.items()}
    if type(value) is tuple:
        return [thaw_snapshot(child) for child in value]
    return value
