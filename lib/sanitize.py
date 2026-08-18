"""Input sanitization helpers for the SSH MCP server.

Provides three pure helpers:
- :func:`sanitize_command` — normalize before authorization/execution.
- :func:`sanitize_server_name` — validate a server identifier.
- :func:`sanitize_log_string` — collapse newlines for single-line log fields.
"""

from __future__ import annotations

import re
import unicodedata

from lib.constants import (
    MAX_API_KEY_LENGTH,
    MAX_SERVER_NAME_LENGTH,
    SERVER_NAME_PATTERN,
)
from lib.exceptions import AuthorizationError

# Control characters other than tab, newline, and carriage return.  These are
# stripped because they are unnecessary in a command and could be used to
# smuggle terminal escape sequences or other hostile bytes.  ``\t``, ``\n``
# and ``\r`` are deliberately preserved (see :func:`sanitize_command`).
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# One or more newline / carriage-return characters, collapsed to a single
# space for single-line log fields.
_LOG_NEWLINE_RE = re.compile(r"[\r\n]+")


def sanitize_command(raw: str) -> str:
    """Normalize a raw command string before authorization.

    Order matters:
    1. strip null bytes;
    2. strip control chars except ``\\t`` ``\\n`` ``\\r``;
    3. NFKC-normalize (collapses homoglyphs/confusables);
    4. strip leading/trailing whitespace.

    ``\\n``/``\\r`` are deliberately preserved so the downstream
    dangerous-pattern check can still reject newline/CR injection.

    Args:
        raw: The raw command string supplied by the caller.

    Returns:
        The normalized command string.  Returns ``""`` if *raw* is empty or
        becomes empty after sanitization.
    """
    text = raw.replace("\x00", "")
    text = _CONTROL_CHARS_RE.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text.strip()


def sanitize_server_name(raw: str) -> str:
    """Validate and return a server identifier.

    A valid name matches ``[a-zA-Z0-9._-]{1,MAX_SERVER_NAME_LENGTH}``.

    Args:
        raw: The raw server name supplied by the caller.

    Returns:
        The trimmed, validated server name.

    Raises:
        AuthorizationError: if the name is empty, too long, or contains
            characters outside the allowed set.
    """
    name = raw.strip()
    if not name or len(name) > MAX_SERVER_NAME_LENGTH:
        raise AuthorizationError(
            f"Invalid server name (must be 1-{MAX_SERVER_NAME_LENGTH} characters)"
        )
    if SERVER_NAME_PATTERN.fullmatch(name) is None:
        raise AuthorizationError(
            "Invalid server name (allowed: letters, digits, '.', '_', '-')"
        )
    return name


def sanitize_log_string(raw: str) -> str:
    """Collapse newlines/carriage returns in a single-line log field.

    Prevents log-poisoning by ensuring no user-supplied value injects a
    spurious JSONL record.

    Args:
        raw: The value to sanitize for a single-line log field.

    Returns:
        *raw* with any run of newlines/carriage returns replaced by a single
        space.  Returns ``""`` if *raw* is not a string.
    """
    if not isinstance(raw, str):
        return ""
    return _LOG_NEWLINE_RE.sub(" ", raw)
