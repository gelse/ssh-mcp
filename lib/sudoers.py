"""Build a sudoers drop-in from the configured sudo grants.

The runtime grants ``sudo`` per rule: a rule lists ``commands`` and a
``sudo_allowed`` subset of them.  One target is served by many rules — the
default rules, every API-key entry and every network entry can each grant sudo
for it — while all callers log in as the target's single OS user.  A single
``/etc/sudoers.d`` file therefore has to union the grants of every layer,
restricted to that one user.

This module holds the pure part: which commands the config grants, how the
file is named, and how the document is rendered.  Path resolution (the only
step that needs the remote host) lives in
:func:`lib.ssh_operations.resolve_command_paths`.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Iterable

from lib.constants import (
    SUDOERS_COMMAND_NAME_PATTERN,
    SUDOERS_DROPIN_DIR,
    SUDOERS_FILENAME_PREFIX,
    SUDOERS_FILENAME_UNSAFE_PATTERN,
    SUDOERS_PATH_PATTERN,
    SUDO_ALLOWED_WILDCARD,
)
from lib.types import SudoGrants

_COMMAND_NAME_RE = re.compile(SUDOERS_COMMAND_NAME_PATTERN)
_PATH_RE = re.compile(SUDOERS_PATH_PATTERN)
_UNSAFE_RE = re.compile(SUDOERS_FILENAME_UNSAFE_PATTERN)

#: Layers of ``allowed_commands`` that carry rules, in the order the
#: authorization chain consults them.
_RULE_LAYERS = ("api_keys", "networks")


def _iter_rules(allowed_commands: dict) -> Iterable[tuple[str, dict]]:
    """Yield ``(label, rule)`` for every rule of every layer.

    Args:
        allowed_commands: The ``allowed_commands`` section of the config.

    Yields:
        A label naming the layer (``"default"``, ``"api_keys/<name>"``,
        ``"networks/<name>"``) and the rule dict.
    """
    for rule in allowed_commands.get("default") or []:
        if isinstance(rule, dict):
            yield "default", rule
    for layer in _RULE_LAYERS:
        for entry in allowed_commands.get(layer) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            label = f"{layer}/{name}" if isinstance(name, str) and name else layer
            for rule in entry.get("rules") or []:
                if isinstance(rule, dict):
                    yield label, rule


def _append_once(target: list[str], value: str) -> None:
    """Append *value* to *target* unless it is already there."""
    if value not in target:
        target.append(value)


def is_command_name(name: str) -> bool:
    """Return ``True`` when *name* is a bare command name we can look up.

    Args:
        name: A value taken from a rule's ``commands`` or ``sudo_allowed``.

    Returns:
        Whether it matches :data:`~lib.constants.SUDOERS_COMMAND_NAME_PATTERN`.
    """
    return bool(_COMMAND_NAME_RE.fullmatch(name))


def is_sudoers_path(path: str) -> bool:
    """Return ``True`` when *path* can be written into a sudoers line.

    sudoers has no quoting for command paths, so the path must be absolute
    and consist of safe characters only.

    Args:
        path: A resolved command path.

    Returns:
        Whether it matches :data:`~lib.constants.SUDOERS_PATH_PATTERN`.
    """
    return bool(_PATH_RE.fullmatch(path))


def collect_sudo_grants(allowed_commands: dict, target: str) -> SudoGrants:
    """Union the sudo grants of every rule that applies to *target*.

    A rule contributes the commands named in its own ``sudo_allowed``; when
    that list holds the wildcard, every command of the rule contributes.  A
    rule that grants sudo for ``commands: ["*"]`` is not emitted at all — the
    file never hands out unrestricted root — and is reported in ``skipped``.

    Args:
        allowed_commands: The ``allowed_commands`` section of the config.
        target: The target identifier the file is generated for.

    Returns:
        ``commands`` (sorted, de-duplicated), ``skipped`` (labels of rules
        omitted for granting sudo on every command) and ``invalid`` (configured
        values that are not plausible command names).
    """
    commands: set[str] = set()
    skipped: list[str] = []
    invalid: list[str] = []

    for label, rule in _iter_rules(allowed_commands):
        targets = rule.get("targets")
        if not isinstance(targets, list):
            continue
        if SUDO_ALLOWED_WILDCARD not in targets and target not in targets:
            continue

        rule_commands = [
            c for c in (rule.get("commands") or []) if isinstance(c, str)
        ]
        sudo_allowed = [
            c for c in (rule.get("sudo_allowed") or []) if isinstance(c, str)
        ]
        if not sudo_allowed:
            continue

        if SUDO_ALLOWED_WILDCARD in sudo_allowed:
            if SUDO_ALLOWED_WILDCARD in rule_commands:
                _append_once(skipped, f"{label}: sudo for every command")
                continue
            granted = rule_commands
        else:
            # Defensive: validation already keeps sudo_allowed inside
            # commands, but a hand-edited file may not.
            granted = [c for c in sudo_allowed if c in rule_commands]

        for name in granted:
            if name == SUDO_ALLOWED_WILDCARD:
                continue
            if is_command_name(name):
                commands.add(name)
            else:
                _append_once(invalid, name)

    return {
        "commands": sorted(commands),
        "skipped": skipped,
        "invalid": invalid,
    }


def _sanitized_target(target: str) -> str:
    """Return *target* with every character sudoers cannot take replaced."""
    return _UNSAFE_RE.sub("_", target)


def sudoers_filename(target: str) -> str:
    """Return the suggested drop-in file name for *target*.

    Args:
        target: The target identifier.

    Returns:
        ``mcp-ssh-`` plus the target with dots and other unsafe characters
        replaced by ``_``, so sudo does not skip the installed file.
    """
    return f"{SUDOERS_FILENAME_PREFIX}{_sanitized_target(target)}"


def render_sudoers(
    *,
    target: str,
    username: str,
    host: str,
    resolved: list[tuple[str, str]],
    unresolved: list[str],
    skipped: list[str],
    generated_at: _dt.datetime | None = None,
) -> str:
    """Render the sudoers drop-in document.

    Each command specification is a bare absolute path, with no argument
    pattern.  A spec without a pattern permits every argument, which is what
    the config means by granting a command name.  A trailing ``*`` would read
    the same to classic sudo but is fatal to sudo-rs before 0.2.9, which does
    not implement the argument wildcard and then never matches the line — so
    the pattern is omitted rather than written out.  sudoers has no
    line-continuation character, so the grant is a single line however many
    commands it holds.  The user specification is emitted only when at least
    one path resolved.

    Args:
        target: The target identifier.
        username: The target's OS user, the only user the file grants to.
        host: The target's configured host, used in the header only.
        resolved: ``(command, path)`` pairs, in the order to render.
        unresolved: Command names that have no usable path on the host.
        skipped: Labels of rules omitted for granting sudo on everything.
        generated_at: Timestamp for the header; defaults to UTC now.

    Returns:
        The file contents, ending with a newline.
    """
    stamp = (generated_at or _dt.datetime.now(_dt.timezone.utc)).strftime(
        "%Y-%m-%d %H:%M:%SZ"
    )
    filename = sudoers_filename(target)

    lines = [
        f"# Generated by mcp-ssh for target {target} ({host})",
        f"# User: {username}",
        f"# Generated: {stamp}",
        "#",
        "# Every entry mirrors a rule in the mcp-ssh config that allows the",
        "# command with sudo=True. A command spec without an argument pattern",
        "# permits any arguments, so every invocation of that binary is",
        "# covered — including the ones the server runs.",
        "#",
        "# Install on this host:",
        f"#   visudo -c -f {filename}",
        f"#   install -m 0440 -o root -g root {filename} "
        f"{SUDOERS_DROPIN_DIR}/{filename}",
        "#   visudo -c",
        "#",
        "# The file applies to the machine it is installed on; the Host field",
        "# is ALL because sudo would not match an address there.",
    ]

    for label in skipped:
        lines.append(f"# skipped: {label}")

    if unresolved:
        joined = ", ".join(unresolved)
        lines.append(f"# not found on {host}: {joined}")

    if resolved:
        entries = ", ".join(path for _, path in resolved)
        lines.append("")
        lines.append(f"{username} ALL = (root) NOPASSWD: {entries}")
    else:
        lines.append("")
        lines.append("# No sudo command could be resolved on this host.")

    return "\n".join(lines) + "\n"
