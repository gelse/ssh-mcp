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

from lib.constants import REDIRECT_FD_DUP_RE

# ---------------------------------------------------------------------------
# Compiled regex / constants (module-level for performance)
# ---------------------------------------------------------------------------

# Valid command basename: alphanumeric, underscore, and dash only.
# Must start with an alphanumeric character (no leading dash).
_VALID_COMMAND_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

# fd-dup/fd-close redirection forms as single tokens: 2>&1, >&2, 3>&1, 2>&-
_FD_DUP_CLOSE = re.compile(rf"^{REDIRECT_FD_DUP_RE}$")

# file-redirect operators, longest-match first
_FILE_REDIRECT_OPS = ("&>>", "2>>", "1>>", "&>", "2>", "1>", ">>", ">")

# shell chaining operators preserved as segment separators
_CHAINING_OPS = {"|", "||", "&", "&&", ";"}


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


def strip_redirects(command: str) -> str:
    """Remove shell redirection operators and their targets from *command*.

    Shell output/stderr redirection operators (``2>&1``, ``>&2``, ``2>&-``,
    ``>file``, ``>>file``, ``2>/dev/null``, ``&>file``, fd-duplication such
    as ``3>&1``) are stripped from the raw command **before** segmentation.
    Without this step, the ``&`` inside ``2>&1`` would be treated as a
    chaining separator by :func:`split_command_segments`, producing a phantom
    segment (e.g. ``"1"``) that is not present in any allow-list and therefore
    denies otherwise legitimate commands.

    Quoted redirection-looking characters (e.g. ``echo "a>b"``,
    ``echo 'a>b'``, ``awk '$1 > 5'``) are preserved verbatim because
    :func:`shlex.split` emits the quoted ``>`` as part of a larger token,
    never as a standalone redirect operator.

    Chaining operators (``|``, ``||``, ``&``, ``&&``, ``;``) are preserved
    untouched so multi-segment commands still split correctly.

    Here-strings/here-docs (``<<``, ``<<<``) are **not** stripped — they are
    out of scope.

    Args:
        command: The raw command string to strip.

    Returns:
        *command* with redirection operators and their targets removed and
        tokens re-joined with single spaces.  If *command* is empty, it is
        returned unchanged; if tokenization fails (unbalanced quotes), the
        original *command* is returned unchanged as a safe fallback.

    Examples:
        >>> strip_redirects("docker logs t 2>&1 | grep -i cert")
        'docker logs t | grep -i cert'
        >>> strip_redirects("uptime 2>/dev/null")
        'uptime'
        >>> strip_redirects("cmd1 && cmd2")
        'cmd1 && cmd2'
        >>> strip_redirects("echo 'a>b'")
        "echo 'a>b'"
    """
    if not command:
        return command
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return command

    result: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        # fd-dup / fd-close forms are single tokens: 2>&1, >&2, 2>&-, 3>&1
        if _FD_DUP_CLOSE.fullmatch(tok):
            i += 1
            continue
        # file-redirect: operator may be standalone or glued to its target (">file")
        op = next((o for o in _FILE_REDIRECT_OPS if tok.startswith(o)), None)
        if op:
            i += 1
            # if operator had no glued target, consume the following token as target
            # unless it is a chaining operator
            if tok == op and i < n and tokens[i] not in _CHAINING_OPS:
                i += 1
            continue
        result.append(tok)
        i += 1
    return " ".join(result)
