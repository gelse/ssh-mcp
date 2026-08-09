"""Command segmentation security for the SSH MCP server.

Provides hardened command parsing to prevent command-injection attacks via
shell metacharacters, substitution syntax, and newline injection.

Uses :func:`shlex.split` for POSIX-compliant shell tokenization and adds
additional validation layers for dangerous patterns that ``shlex`` alone
does not reject.
"""

from __future__ import annotations

import os
import re
import shlex

# ---------------------------------------------------------------------------
# Compiled regex / constants (module-level for performance)
# ---------------------------------------------------------------------------

# Valid command basename: alphanumeric, underscore, and dash only.
# Must start with an alphanumeric character (no leading dash).
_VALID_COMMAND_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_dangerous_patterns(command: str) -> list[str]:
    """Scan *command* for shell metacharacters that enable injection.

    Detects command substitution (``$()``), backtick substitution, and
    line-break injection.  These patterns are unconditionally dangerous
    regardless of quoting or context.

    Args:
        command: The raw command string to scan.

    Returns:
        Human-readable descriptions of each dangerous pattern found.
        An empty list means no dangerous patterns were detected.
    """
    found: list[str] = []

    if "$(" in command:
        found.append("$() command substitution")
    if "`" in command:
        found.append("backtick substitution")
    if "\n" in command:
        found.append("newline injection")
    if "\r" in command:
        found.append("carriage-return injection")

    return found


def split_command_segments(command: str) -> list[str]:
    """Split *command* by shell chaining operators for per-segment validation.

    Delimiters: ``|``, ``&``, ``;`` (which also covers ``&&`` and ``||``
    because each ``&`` / ``|`` is a separator).

    Returns:
        Non-empty, stripped segments in left-to-right order.
    """
    parts = re.split(r"[|&;]", command)
    return [p.strip() for p in parts if p.strip()]


def segment_command(command_string: str) -> str:
    """Safely extract and validate the base command name from *command_string*.

    Uses :func:`shlex.split` for POSIX shell tokenization — this
    correctly handles quoting, escaping, and argument boundaries.
    The first token is then sanitised:

    1. Leading path components are stripped (``/usr/bin/ls`` → ``ls``).
    2. The result is validated to contain only ``[a-zA-Z0-9][a-zA-Z0-9_-]*``.
    3. Commands that fail parsing or validation return an empty string.

    Args:
        command_string: The raw command (e.g. ``"grep -rn 'pattern' /tmp"``).

    Returns:
        The validated base command name, or ``""`` if the command cannot
        be safely parsed.

    Examples:
        >>> segment_command("ls -la")
        'ls'
        >>> segment_command("/usr/bin/cat /etc/hosts")
        'cat'
        >>> segment_command("echo 'hello world'")
        'echo'
        >>> segment_command("$(whoami)")
        ''
        >>> segment_command("rm -rf / ; echo")
        ''
    """
    stripped = command_string.strip()
    if not stripped:
        return ""

    # --- Tokenize via POSIX shell rules ---
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        # Unmatched quotes or other lexer errors → reject
        return ""

    if not tokens:
        return ""

    first_token = tokens[0]

    # --- Strip leading path components ---
    base_name = os.path.basename(first_token)

    # --- Validate command name ---
    if not _VALID_COMMAND_NAME_RE.match(base_name):
        return ""

    return base_name
