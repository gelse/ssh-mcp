"""Lightweight SSH connection checker for the config API.

Performs a single SSH connect + command execution to verify
connectivity.  Uses paramiko directly (no connection pooling).
"""

from __future__ import annotations

import os
import socket
import tempfile
from dataclasses import dataclass
from pathlib import Path

import paramiko


@dataclass
class CheckResult:
    """Result of an SSH connection check."""
    success: bool
    output: str
    error: str | None = None
    exit_code: int = -1


def check_ssh_connection(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    private_key: str | None = None,
    checkcommand: str = "echo ping",
    timeout: int = 10,
) -> CheckResult:
    """Execute checkcommand on the target and return the result.

    Args:
        host: Target hostname or IP.
        port: SSH port.
        username: SSH username.
        password: Optional password auth.
        private_key: Optional path to private key file.
        checkcommand: Command to execute for the check.
        timeout: Connection timeout in seconds.

    Returns:
        CheckResult with success flag, output, error, and exit code.
    """
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Resolve key path (handle relative paths from config)
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
        }

        if private_key:
            key_path = os.path.expanduser(private_key)
            if not os.path.isabs(key_path):
                # Try relative to /app/ (container working dir)
                key_path = os.path.join("/app", private_key)
            if os.path.exists(key_path):
                connect_kwargs["key_filename"] = key_path
            elif password:
                connect_kwargs["password"] = password
            else:
                return CheckResult(
                    success=False,
                    output="",
                    error=f"Private key not found: {private_key}",
                )
        elif password:
            connect_kwargs["password"] = password
        else:
            return CheckResult(
                success=False,
                output="",
                error="No authentication method configured (no password or key)",
            )

        client.connect(**connect_kwargs)

        # Execute the check command
        stdin, stdout, stderr = client.exec_command(
            checkcommand, timeout=timeout
        )
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()

        return CheckResult(
            success=exit_code == 0,
            output=out,
            error=err if err else None,
            exit_code=exit_code,
        )

    except paramiko.AuthenticationException as e:
        return CheckResult(
            success=False, output="", error=f"Authentication failed: {e}"
        )
    except (paramiko.SSHException, socket.error) as e:
        return CheckResult(
            success=False, output="", error=f"Connection failed: {e}"
        )
    finally:
        client.close()
