"""Standalone SSH operation functions callable by both MCP tools and config API.

This module extracts the core SSH operations from ``server.py`` tool handlers
into importable, testable functions.  In the unified container, the config API
calls these directly instead of going through HTTP (MCPClient).  In standalone
mode, the MCP tool handlers delegate here as well.

All functions use explicit dependency injection (no module-level state, no
I/O at import time) following the project's closure-based DI pattern.
"""

from __future__ import annotations

import os
import socket
from typing import Any

import paramiko

from lib.config import ConfigManager
from lib.constants import (
    DEFAULT_CHECK_COMMAND,
    DEFAULT_SSH_CHECK_TIMEOUT_MAX,
    DEFAULT_SSH_CHECK_TIMEOUT_MIN,
    DEFAULT_SSH_PORT,
    LOG_FORMAT_VERSION,
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
        return out, err, exit_code
    except socket.timeout as exc:
        raise SSHTimeoutError(
            f"Command timed out after {timeout}s: {command}"
        ) from exc


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

    return {
        "success": exit_code == 0,
        "output": out.strip(),
        "error": err.strip() if err else None,
        "exit_code": exit_code,
        "checkcommand": checkcommand,
    }
