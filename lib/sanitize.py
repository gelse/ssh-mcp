"""Input sanitization helpers for the SSH MCP server.

Provides four pure helpers:
- :func:`sanitize_command` — normalize before authorization/execution.
- :func:`sanitize_target_name` — validate a target identifier.
- :func:`sanitize_log_string` — collapse newlines for single-line log fields.
- :func:`validate_log_path` — validate a log file/directory path for safety.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from lib.constants import (
    MAX_TARGET_NAME_LENGTH,
    TARGET_NAME_PATTERN,
)
from lib.exceptions import AuthorizationError, ConfigValidationError

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


def sanitize_target_name(raw: str) -> str:
    """Validate and return a target identifier.

    A valid name matches ``[a-zA-Z0-9._-]{1,MAX_TARGET_NAME_LENGTH}``.

    Args:
        raw: The raw target name supplied by the caller.

    Returns:
        The trimmed, validated target name.

    Raises:
        AuthorizationError: if the name is empty, too long, or contains
            characters outside the allowed set.
    """
    name = raw.strip()
    if not name or len(name) > MAX_TARGET_NAME_LENGTH:
        raise AuthorizationError(
            f"Invalid target name (must be 1-{MAX_TARGET_NAME_LENGTH} characters)"
        )
    if TARGET_NAME_PATTERN.fullmatch(name) is None:
        raise AuthorizationError(
            "Invalid target name (allowed: letters, digits, '.', '_', '-')"
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


def validate_log_path(file_path: str, base_dir: str | None = None) -> Path:
    """Validate a log file/directory path for safety.

    Rejects null bytes, resolves symlinks and traversal sequences, and
    optionally asserts containment within a base directory.

    Args:
        file_path: The log file or directory path to validate.
        base_dir: Optional base directory.  When provided, the resolved
            *file_path* must be inside (or equal to) the resolved
            *base_dir*.

    Returns:
        The resolved, validated :class:`~pathlib.Path`.

    Raises:
        ConfigValidationError: If the path is empty, contains null bytes,
            resolves to a location outside *base_dir*, or is otherwise
            invalid.
    """
    if not file_path or not file_path.strip():
        raise ConfigValidationError("Log path must not be empty")

    if "\x00" in file_path:
        raise ConfigValidationError("Log path contains null bytes")

    resolved = Path(file_path).resolve()

    if base_dir is not None:
        resolved_base = Path(base_dir).resolve()
        try:
            resolved.relative_to(resolved_base)
        except ValueError:
            raise ConfigValidationError(
                f"Log path escapes base directory: "
                f"{resolved} is not under {resolved_base}"
            )

    return resolved
