"""Duplicate-safe, finite, strict-UTF-8 JSON loading."""

from __future__ import annotations

import json
from typing import Any

STRICT_JSON_PROFILE = "strict_json_v1"


class StrictJsonError(ValueError):
    """JSON input is ambiguous or unsafe to interpret as authority."""


def loads_strict_json(
    document: str | bytes | bytearray,
    *,
    label: str = "JSON input",
) -> Any:
    """Decode one JSON document without duplicate keys or non-finite numbers."""

    if isinstance(document, (bytes, bytearray)):
        try:
            text = bytes(document).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise StrictJsonError(f"{label} is not valid UTF-8 JSON") from exc
    elif isinstance(document, str):
        text = document
    else:
        raise TypeError("strict JSON input must be text or bytes")

    try:
        return json.loads(
            text,
            object_pairs_hook=lambda pairs: _unique_object(pairs, label),
            parse_constant=lambda value: _reject_constant(value, label),
        )
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise StrictJsonError(f"{label} is not valid JSON") from exc


def _unique_object(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(f"{label} contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str, label: str) -> None:
    raise StrictJsonError(f"{label} contains a non-finite JSON number")
