"""Duplicate-safe, finite, strict-UTF-8 JSON loading."""

from __future__ import annotations

import json
from typing import Any

from .limits import MAX_JSON_LEXICAL_TOKENS, MAX_JSON_NESTING_DEPTH

STRICT_JSON_PROFILE = "strict_json_v2"


class StrictJsonError(ValueError):
    """JSON input is ambiguous or unsafe to interpret as authority."""


def loads_strict_json(
    document: str | bytes | bytearray,
    *,
    label: str = "JSON input",
) -> Any:
    """Decode unambiguous JSON after bounded structural preflight."""

    if isinstance(document, (bytes, bytearray)):
        try:
            text = bytes(document).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise StrictJsonError(f"{label} is not valid UTF-8 JSON") from exc
    elif isinstance(document, str):
        text = document
    else:
        raise TypeError("strict JSON input must be text or bytes")

    _preflight_structure(text, label)
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


def _preflight_structure(text: str, label: str) -> None:
    depth = 0
    tokens = 0
    in_string = False
    escaped = False
    in_scalar = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if in_scalar:
            if character.isspace() or character in '{}[],:"':
                in_scalar = False
            else:
                continue

        if character == '"':
            in_string = True
            tokens += 1
        elif character in "[{":
            depth += 1
            tokens += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                raise StrictJsonError(
                    f"{label} exceeds maximum JSON nesting depth of "
                    f"{MAX_JSON_NESTING_DEPTH}"
                )
        elif character in "]}":
            if depth:
                depth -= 1
        elif character.isspace() or character in ",:":
            continue
        else:
            in_scalar = True
            tokens += 1

        if tokens > MAX_JSON_LEXICAL_TOKENS:
            raise StrictJsonError(
                f"{label} exceeds maximum JSON lexical token count of "
                f"{MAX_JSON_LEXICAL_TOKENS}"
            )
