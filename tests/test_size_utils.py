"""Tests for :mod:`lib.size_utils` — ``parse_size_bytes`` size-string parsing."""

from __future__ import annotations

import pytest

from lib.exceptions import ConfigValidationError
from lib.size_utils import parse_size_bytes


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("50b", 50),
        ("50", 50),
        ("50kb", 50 * 1024),
        ("50mb", 50 * 1024 * 1024),
        ("50gb", 50 * 1024 * 1024 * 1024),
        ("1b", 1),
    ],
)
def test_parse_size_valid_inputs(raw: str, expected: int) -> None:
    """Valid size strings (and bare numbers as bytes) parse to the byte count."""
    assert parse_size_bytes(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1B", 1),
        ("1b", 1),
        ("1KB", 1024),
        ("1Kb", 1024),
        ("1kB", 1024),
        ("1kb", 1024),
        ("1MB", 1024 * 1024),
        ("1mB", 1024 * 1024),
        ("1Gb", 1024 * 1024 * 1024),
        ("1gB", 1024 * 1024 * 1024),
        ("1GB", 1024 * 1024 * 1024),
    ],
)
def test_parse_size_case_insensitive(raw: str, expected: int) -> None:
    """Unit suffixes are matched case-insensitively."""
    assert parse_size_bytes(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (" 50 kb ", 50 * 1024),
        ("50kb", 50 * 1024),
        ("  1mb  ", 1 * 1024 * 1024),
    ],
)
def test_parse_size_whitespace_tolerated(raw: str, expected: int) -> None:
    """Surrounding whitespace around the number/unit is tolerated."""
    assert parse_size_bytes(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "kb",
        "abc kb",
        "50tb",
        "-50kb",
        "50.5kb",
        "1 2kb",
        "50 bb",
        "garbage",
    ],
)
def test_parse_size_rejects_invalid(raw: str) -> None:
    """Invalid size strings raise :class:`ConfigValidationError`."""
    with pytest.raises(ConfigValidationError):
        parse_size_bytes(raw)


@pytest.mark.parametrize("raw", ["0", "0b", "0kb", "0gb"])
def test_parse_size_rejects_nonpositive(raw: str) -> None:
    """Size strings that evaluate to fewer than one byte are rejected."""
    with pytest.raises(ConfigValidationError):
        parse_size_bytes(raw)


@pytest.mark.parametrize("raw", ["50tb", "garbage", "0", "-50kb", "50.5kb"])
def test_parse_size_error_does_not_leak_raw_value(raw: str) -> None:
    """`ConfigValidationError` messages never echo the raw offending input,
    while ``field`` stays intact as the structured channel."""
    with pytest.raises(ConfigValidationError) as exc:
        parse_size_bytes(raw)
    message = str(exc.value)
    assert raw not in message
    assert exc.value.field == "settings.max_output_length"
