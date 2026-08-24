"""Bounded text readers for untrusted protocol and configuration inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, TextIO


class InputLimitError(ValueError):
    """An input exceeded its pre-parse resource ceiling."""


def read_bounded_text(stream: TextIO, maximum: int, label: str) -> str:
    _validate_maximum(maximum)
    value = stream.read(maximum + 1)
    require_bounded_text(value, maximum, label)
    return value


def iter_bounded_text_lines(
    stream: TextIO,
    maximum: int,
    label: str,
) -> Iterator[str]:
    _validate_maximum(maximum)
    while True:
        line = stream.readline(maximum + 1)
        if not line:
            return
        require_bounded_text(line, maximum, label)
        yield line


def read_bounded_path_text(path: str | Path, maximum: int, label: str) -> str:
    _validate_maximum(maximum)
    source = Path(path)
    with source.open("rb") as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise InputLimitError(f"{label} exceeds {maximum} bytes")
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InputLimitError(f"{label} is not valid UTF-8") from exc


def require_bounded_text(value: str, maximum: int, label: str) -> None:
    _validate_maximum(maximum)
    if len(value) > maximum or len(value.encode("utf-8")) > maximum:
        raise InputLimitError(f"{label} exceeds {maximum} bytes")


def _validate_maximum(maximum: int) -> None:
    if type(maximum) is not int or maximum < 1:
        raise ValueError("input byte ceiling must be a positive integer")
