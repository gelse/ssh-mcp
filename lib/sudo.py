"""Centralized sudo command wrapping and validation for SSH MCP.

Provides a single :class:`SudoHandler` that is the source of truth for all
sudo-related logic: detecting sudo in command strings, validating that
callers use the ``sudo`` parameter correctly, and wrapping commands with
the appropriate ``sudo`` flags.
"""

from __future__ import annotations

import re

from lib.constants import SUDO_NO_PASSWORD_FLAG, SUDO_PASSWORD_PROMPT_FLAGS


class SudoHandler:
    """Centralized handler for sudo command wrapping and validation.

    Consolidates the sudo logic that was previously split between
    ``server.py`` command wrapping and ``auth.py`` block-pattern checks.
    """

    @staticmethod
    def wrap_sudo_command(
        command: str, sudo: bool, sudo_password: str | None
    ) -> str:
        """Conditionally wrap *command* with sudo flags.

        Args:
            command: The raw (unwrapped) command string.
            sudo: Whether sudo elevation was requested by the caller.
            sudo_password: The password to pass via stdin when using
                           ``sudo -S``, or ``None`` for passwordless sudo.

        Returns:
            The command string, possibly prefixed with ``sudo -S -p ''``
            (password-based) or ``sudo -n`` (passwordless).  Returns
            *command* unchanged when ``sudo=False``.
        """
        if not sudo:
            return command
        if sudo_password:
            return f"{SUDO_PASSWORD_PROMPT_FLAGS} {command}"
        return f"{SUDO_NO_PASSWORD_FLAG} {command}"

    @staticmethod
    def is_sudo_command(command: str) -> bool:
        """Check whether *command* contains the word ``sudo`` (case-insensitive).

        Args:
            command: A shell command string.

        Returns:
            ``True`` if the word ``sudo`` appears as a word boundary match.
        """
        return bool(re.search(r"\bsudo\b", command, re.IGNORECASE))

    @staticmethod
    def validate_sudo(command: str, sudo: bool) -> str | None:
        """Validate that ``sudo=True`` callers do not embed ``sudo`` in *command*.

        When a caller sets ``sudo=True``, the server automatically prepends
        the appropriate sudo flags.  Therefore the raw command must *not*
        already contain ``sudo`` — that would result in double-wrapping.

        Args:
            command: The raw command string to validate.
            sudo: Whether sudo elevation was requested.

        Returns:
            A human-readable error message if validation fails, or
            ``None`` if the combination is valid.
        """
        if sudo and SudoHandler.is_sudo_command(command):
            return (
                "ERROR: When sudo=True, the command must not contain "
                "'sudo'. Remove 'sudo' from the command and use the sudo "
                "parameter instead."
            )
        return None
