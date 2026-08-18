"""Pure size-string parsing utilities for the SSH MCP server.

This module contains no I/O and no import-time side effects; it is safe to
import from anywhere.  It exposes a single public function,
:func:`parse_size_bytes`, used to normalise human-readable size strings
(e.g. ``"50kb"``) into an integer byte count.
"""

from __future__ import annotations

import re

from lib.constants import SIZE_UNIT_MULTIPLIERS
from lib.exceptions import ConfigValidationError

# A bare number is treated as bytes (\"b\"), so the unit is optional.  The
# numeric part must be a non-negative integer; surrounding whitespace and
# whitespace between the number and the unit are tolerated.
_SIZE_RE = re.compile(r"^\s*(\d+)\s*([a-zA-Z]+)?\s*$")


def parse_size_bytes(value: str) -> int:
    """Parse a human-readable size string into an integer byte count.

    Accepts ``"<number><unit>"`` where *unit* is one of ``b``/``kb``/``mb``/
    ``gb``, case-insensitively (e.g. ``"50kb"``, ``"10MB"``, ``"1gb"``).  A
    bare number with no unit is interpreted as bytes (e.g. ``"50"`` -> 50).
    The numeric part must be a non-negative integer; the multiplier is applied
    and the result guaranteed to be ``>= 1``.

    Args:
        value: The size string to parse.

    Returns:
        The equivalent number of bytes as a positive ``int``.

    Raises:
        ConfigValidationError: If *value* is not a well-formed size string, if
            it uses an unsupported unit, or if it resolves to a non-positive
            byte count.
    """
    match = _SIZE_RE.match(value)
    if match is None:
        raise ConfigValidationError(
            "Invalid size string; expected an integer optionally followed by "
            "a unit (b, kb, mb, or gb), e.g. '50kb'",
            field="settings.max_output_length",
        )
    number = int(match.group(1))
    unit = (match.group(2) or "b").lower()
    if unit not in SIZE_UNIT_MULTIPLIERS:
        raise ConfigValidationError(
            "Invalid size unit; expected b, kb, mb, or gb (case-insensitive)",
            field="settings.max_output_length",
        )
    result = number * SIZE_UNIT_MULTIPLIERS[unit]
    if result < 1:
        raise ConfigValidationError(
            "Size must be a positive value",
            field="settings.max_output_length",
        )
    return result
