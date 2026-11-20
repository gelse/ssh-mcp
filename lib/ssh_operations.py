"""Standalone SSH operation functions callable by both MCP tools and config API.

This module extracts the core SSH operations from ``server.py`` tool handlers
into importable, testable functions.  In the unified container, the config API
calls these directly instead of going through HTTP (MCPClient).  In standalone
mode, the MCP tool handlers delegate here as well.

All functions use explicit dependency injection (no module-level state, no
I/O at import time) following the project's closure-based DI pattern.
"""

from __future__ import annotations

import logging
import os
import shlex
import socket
from typing import Any

import paramiko

logger = logging.getLogger(__name__)

from lib.config import ConfigManager
from lib.constants import (
    DEFAULT_CHECK_COMMAND,
    DEFAULT_SSH_CHECK_TIMEOUT_MAX,
    DEFAULT_SSH_CHECK_TIMEOUT_MIN,
    DEFAULT_SSH_PORT,
    LOG_FORMAT_VERSION,
    SUDOERS_RESOLVE_MAX_OUTPUT_BYTES,
    SUDOERS_RESOLVE_TIMEOUT_SECONDS,
)
from lib.exceptions import (
    MCPSSHError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
)
from lib.ssh_client import SSHClientManager
from lib.types import CheckConnectionResult


def build_auth_target(
    config_manager: ConfigManager,
    target_name: str,
    ssh_key_path: str,
) -> tuple[dict[str, Any], str | None]:
    """Build an auth-style target dict from the stored configuration.

    Adapts the flat config format (``private_key`` / ``password`` on
    target) to the structured auth dict expected by
    :meth:`SSHClientManager.connect`.

    Args:
        config_manager: The active config manager instance.
        target_name: The identifier of the SSH target.
        ssh_key_path: Default path to the SSH private key (used as
            fallback when a target does not specify its own key).

    Returns:
        ``(auth_target, password_or_none)`` — the auth target dict
        suitable for :meth:`SSHClientManager.connect`, and the password
        string (or ``None``) for sudo usage.

    Raises:
        SSHConnectionError: When the target is not found, or has neither
            a valid key nor a password.
    """
    logger.debug("build_auth_target entry: target_name=%s", target_name)
    target = config_manager.get_ssh_target(target_name)
    if target is None:
        available = ", ".join(config_manager.list_ssh_targets())
        raise SSHConnectionError(
            f"Server '{target_name}' not found. Available: {available}"
        )

    key_path = target.get("private_key") or ssh_key_path
    password = target.get("password")

    auth_target: dict[str, Any] = {
        "host": target["host"],
        "port": target.get("port", DEFAULT_SSH_PORT),
        "username": target["username"],
    }

    if key_path and os.path.exists(os.path.expanduser(key_path)):
        auth_target["auth"] = {
            "type": "key",
            "key_filename": key_path,
        }
    elif password:
        auth_target["auth"] = {
            "type": "password",
            "password": password,
        }
    else:
        raise SSHConnectionError(
            f"SSH target '{target_name}' has neither a valid key "
            f"nor a password"
        )

    logger.debug(
        "build_auth_target exit: host=%s, port=%s, auth_type=%s",
        auth_target.get("host"), auth_target.get("port"),
        auth_target.get("auth", {}).get("type"),
    )
    return auth_target, password


def execute_ssh_command(
    client: paramiko.SSHClient,
    command: str,
    timeout: int,
    max_output: int,
    sudo: bool = False,
    sudo_password: str | None = None,
) -> tuple[str, str, int]:
    """Run *command* on *client* and return captured output.

    Args:
        client: A connected paramiko SSH client.
        command: The shell command to execute.
        timeout: Command timeout in seconds.
        max_output: Maximum bytes to read from stdout/stderr.
        sudo: Whether the command is wrapped with sudo.
        sudo_password: Password to inject via stdin when *sudo* is True.

    Returns:
        ``(stdout, stderr, exit_code)`` tuple.

    Raises:
        SSHTimeoutError: When the command times out.
    """
    logger.debug(
        "execute_ssh_command entry: command=%s, timeout=%d, sudo=%s",
        command, timeout, sudo,
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            command, timeout=timeout
        )
        if sudo and sudo_password:
            stdin.write(sudo_password + "\n")
            stdin.flush()
            stdin.close()
        out = stdout.read(max_output).decode("utf-8", errors="replace")
        err = stderr.read(max_output).decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        logger.debug(
            "execute_ssh_command exit: exit_code=%d, stdout_len=%d, stderr_len=%d",
            exit_code, len(out), len(err),
        )
        return out, err, exit_code
    except socket.timeout as exc:
        raise SSHTimeoutError(
            f"Command timed out after {timeout}s: {command}"
        ) from exc


def _build_resolve_script(commands: list[str]) -> str:
    """Build the POSIX shell loop that resolves every command name.

    ``command -v`` answers for shell builtins with the bare name, which is
    useless for sudoers, so a non-absolute answer falls back to a ``PATH``
    scan for an executable file — exactly the lookup sudo performs.

    Args:
        commands: Validated command names.

    Returns:
        A shell script printing ``name<TAB>path`` per command.
    """
    names = " ".join(shlex.quote(name) for name in commands)
    return (
        f"for c in {names}; do\n"
        '  p=$(command -v "$c" 2>/dev/null) || p=\n'
        '  case "$p" in\n'
        "    /*) printf '%s\\t%s\\n' \"$c\" \"$p\"; continue ;;\n"
        "  esac\n"
        "  old_ifs=$IFS; IFS=:\n"
        '  for d in $PATH; do\n'
        '    if [ -x "$d/$c" ] && [ ! -d "$d/$c" ]; then '
        'p="$d/$c"; break; fi\n'
        "  done\n"
        "  IFS=$old_ifs\n"
        "  printf '%s\\t%s\\n' \"$c\" \"$p\"\n"
        "done\n"
    )


def resolve_command_paths(
    ssh_client_manager: SSHClientManager,
    config_manager: ConfigManager,
    target_name: str,
    ssh_key_path: str,
    commands: list[str],
    timeout: int = SUDOERS_RESOLVE_TIMEOUT_SECONDS,
    max_command_output: int = SUDOERS_RESOLVE_MAX_OUTPUT_BYTES,
) -> dict[str, str | None]:
    """Resolve command names to absolute paths on a target.

    Opens one connection to *target_name* and looks every name up the way the
    login shell would, so the paths match what the server actually executes.
    This bypasses the authorization chain on purpose: it runs a fixed,
    read-only lookup, not a caller-supplied command.

    Args:
        ssh_client_manager: The active SSH client manager.
        config_manager: The config manager holding the target's credentials.
        target_name: The identifier of the SSH target.
        ssh_key_path: Default path to the SSH private key.
        commands: Command names to resolve; empty returns ``{}``.
        timeout: Connection and command timeout in seconds.
        max_command_output: Maximum bytes to read from the output.

    Returns:
        A mapping of command name to the resolved path, or ``None`` when the
        name does not resolve to an executable file.  Names missing from the
        output are also reported as ``None``.

    Raises:
        SSHConnectionError: When the target is unknown or unreachable.
        SSHAuthenticationError: When SSH authentication fails.
        SSHTimeoutError: When the connection or command times out.
    """
    if not commands:
        return {}

    target = config_manager.get_ssh_target(target_name)
    if target is None:
        available = ", ".join(config_manager.list_ssh_targets())
        raise SSHConnectionError(
            f"Server '{target_name}' not found. Available: {available}"
        )

    logger.debug(
        "resolve_command_paths entry: target_name=%s commands=%d",
        target_name,
        len(commands),
    )
    auth_target, _ = build_auth_target(config_manager, target_name, ssh_key_path)
    with ssh_client_manager.connect(auth_target) as client:
        out, err, exit_code = execute_ssh_command(
            client,
            _build_resolve_script(commands),
            timeout,
            max_command_output,
        )

    resolved: dict[str, str | None] = {name: None for name in commands}
    for line in out.splitlines():
        name, _, path = line.partition("\t")
        if name in resolved:
            resolved[name] = path.strip() or None

    logger.debug(
        "resolve_command_paths exit: target_name=%s resolved=%d exit_code=%d "
        "stderr_len=%d",
        target_name,
        sum(1 for value in resolved.values() if value),
        exit_code,
        len(err or ""),
    )
    return resolved


def check_ssh_connection(
    ssh_client_manager: SSHClientManager,
    config_manager: ConfigManager,
    target_name: str,
    ssh_key_path: str,
    timeout: int = 10,
    max_command_output: int = 50_000,
) -> CheckConnectionResult:
    """Check SSH connectivity to a remote server.

    Executes the target's configured ``checkcommand`` (default:
    ``"echo ping"``) to verify that SSH authentication and connectivity
    work.  This is a lightweight diagnostic — it does NOT go through the
    full authorization chain for the checkcommand itself, but it DOES
    require the target to exist and the SSH credentials to be valid.

    Args:
        ssh_client_manager: The active SSH client manager.
        config_manager: The active config manager instance.
        target_name: The identifier of the SSH target.
        ssh_key_path: Default path to the SSH private key.
        timeout: Connection and command timeout in seconds (clamped to
            1–30).
        max_command_output: Maximum bytes to read from command output.

    Returns:
        A :class:`~lib.types.CheckConnectionResult` dict with
        ``success``, ``output``, ``error``, ``exit_code``, and
        ``checkcommand`` fields.

    Raises:
        SSHAuthenticationError: When SSH authentication fails.
        SSHTimeoutError: When the connection or command times out.
        SSHConnectionError: On any other SSH connection failure.
    """
    # Clamp timeout
    timeout = max(DEFAULT_SSH_CHECK_TIMEOUT_MIN, min(timeout, DEFAULT_SSH_CHECK_TIMEOUT_MAX))

    # Look up the target and its checkcommand
    target = config_manager.get_ssh_target(target_name)
    if target is None:
        available = ", ".join(config_manager.list_ssh_targets())
        raise SSHConnectionError(
            f"Server '{target_name}' not found. Available: {available}"
        )

    checkcommand = target.get("checkcommand", DEFAULT_CHECK_COMMAND)

    logger.debug(
        "check_ssh_connection entry: target_name=%s, timeout=%d",
        target_name, timeout,
    )
    # Build the auth target and connect
    auth_target, _ = build_auth_target(config_manager, target_name, ssh_key_path)
    with ssh_client_manager.connect(auth_target) as client:
        out, err, exit_code = execute_ssh_command(
            client,
            checkcommand,
            timeout,
            max_command_output,
            sudo=False,
            sudo_password=None,
        )

    result: CheckConnectionResult = {
        "success": exit_code == 0,
        "output": out.strip(),
        "error": err.strip() if err else None,
        "exit_code": exit_code,
        "checkcommand": checkcommand,
    }
    logger.debug(
        "check_ssh_connection exit: target_name=%s, success=%s, exit_code=%d",
        target_name, result["success"], exit_code,
    )
    return result
