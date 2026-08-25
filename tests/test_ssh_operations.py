"""Unit tests for :mod:`lib.ssh_operations`.

All tests use ``unittest.mock`` to avoid making real SSH connections:
paramiko classes are patched, key files are written to ``tmp_path``,
and connection failures are simulated by raising from the mocked
``SSHClientManager``.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from lib.config import ConfigManager
from lib.constants import (
    DEFAULT_CHECK_COMMAND,
    DEFAULT_SSH_CHECK_TIMEOUT_MAX,
    DEFAULT_SSH_CHECK_TIMEOUT_MIN,
    DEFAULT_SSH_PORT,
)
from lib.exceptions import (
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
)
from lib.ssh_operations import (
    build_auth_target,
    check_ssh_connection,
    execute_ssh_command,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(config_dir: Path, data: dict) -> Path:
    """Write a config dict to ssh-mcp-config.json in the given directory."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(data))
    return config_path


def _make_config_manager(tmp_path: Path, config: dict) -> ConfigManager:
    """Create a ConfigManager pointing to tmp_path with the given config.

    Returns the manager WITHOUT starting the watcher thread.
    """
    _write_config(tmp_path, config)
    return ConfigManager(str(tmp_path))


def _minimal_config(**overrides) -> dict:
    """Return a minimal valid config dict, with optional overrides."""
    base = {
        "version": 1,
        "ssh_targets": {
            "testserver": {
                "host": "10.0.0.1",
                "username": "testuser",
                "port": 22,
                "password": "testpass",
            },
        },
        "block_patterns": [],
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": ["*"]},
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }
    base.update(overrides)
    return base


def _key_config(tmp_path: Path, **overrides) -> dict:
    """Return a config dict using key-based auth with a real key file."""
    key_file = tmp_path / "id_ed25519"
    key_file.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-data\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    target = {
        "host": "10.0.0.2",
        "username": "keyuser",
        "port": 2222,
        "private_key": str(key_file),
    }
    target.update(overrides.pop("target_overrides", {}))
    config = _minimal_config(ssh_targets={"keyserv": target})
    config.update(overrides)
    return config


# ---------------------------------------------------------------------------
# build_auth_target tests
# ---------------------------------------------------------------------------


class TestBuildAuthTarget:
    """Tests for build_auth_target()."""

    def test_password_auth(self, tmp_path):
        """Password-based target returns correct auth dict."""
        config = _minimal_config()
        mgr = _make_config_manager(tmp_path, config)

        auth_target, password = build_auth_target(
            mgr, "testserver", "/app/ssh_key"
        )

        assert auth_target["host"] == "10.0.0.1"
        assert auth_target["port"] == DEFAULT_SSH_PORT
        assert auth_target["username"] == "testuser"
        assert auth_target["auth"]["type"] == "password"
        assert auth_target["auth"]["password"] == "testpass"
        assert password == "testpass"

    def test_key_auth_with_target_key(self, tmp_path):
        """Key-based target with existing key file uses key auth."""
        config = _key_config(tmp_path)
        mgr = _make_config_manager(tmp_path, config)

        auth_target, password = build_auth_target(
            mgr, "keyserv", "/app/ssh_key"
        )

        assert auth_target["auth"]["type"] == "key"
        assert "key_filename" in auth_target["auth"]
        assert password is None

    def test_key_auth_fallback_to_default_key(self, tmp_path):
        """Target without private_key falls back to default ssh_key_path."""
        default_key = tmp_path / "default_key"
        default_key.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfallback\n"
            "-----END OPENSSH PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        config = _minimal_config()
        mgr = _make_config_manager(tmp_path, config)

        auth_target, password = build_auth_target(
            mgr, "testserver", str(default_key)
        )

        assert auth_target["auth"]["type"] == "key"
        assert auth_target["auth"]["key_filename"] == str(default_key)

    def test_target_not_found_raises(self, tmp_path):
        """Non-existent target raises SSHConnectionError."""
        config = _minimal_config()
        mgr = _make_config_manager(tmp_path, config)

        with pytest.raises(SSHConnectionError, match="not found"):
            build_auth_target(mgr, "nosuchserver", "/app/ssh_key")

    def test_no_credentials_raises(self, tmp_path):
        """Target whose key path doesn't exist and has no password raises."""
        config = _minimal_config(
            ssh_targets={
                "badserver": {
                    "host": "10.0.0.99",
                    "username": "user",
                    "port": 22,
                    "private_key": "/nonexistent/key",
                },
            }
        )
        mgr = _make_config_manager(tmp_path, config)

        with pytest.raises(SSHConnectionError, match="neither a valid key"):
            build_auth_target(mgr, "badserver", "/also/nonexistent")

    def test_custom_port(self, tmp_path):
        """Target with a custom port is preserved in auth_target."""
        config = _minimal_config(
            ssh_targets={
                "custom": {
                    "host": "10.0.0.5",
                    "username": "admin",
                    "port": 2222,
                    "password": "pw",
                },
            }
        )
        mgr = _make_config_manager(tmp_path, config)

        auth_target, _ = build_auth_target(mgr, "custom", "/app/ssh_key")
        assert auth_target["port"] == 2222


# ---------------------------------------------------------------------------
# execute_ssh_command tests
# ---------------------------------------------------------------------------


class TestExecuteSSHCommand:
    """Tests for execute_ssh_command()."""

    def test_successful_command(self):
        """Successful command returns stdout, stderr, and exit code 0."""
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"hello world"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        out, err, exit_code = execute_ssh_command(
            mock_client, "echo hello", timeout=10, max_output=50000
        )

        assert out == "hello world"
        assert err == ""
        assert exit_code == 0
        mock_client.exec_command.assert_called_once_with(
            "echo hello", timeout=10
        )

    def test_command_with_stderr(self):
        """Command with stderr output returns both streams."""
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"output"
        mock_stderr.read.return_value = b"error msg"
        mock_stdout.channel.recv_exit_status.return_value = 1

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        out, err, exit_code = execute_ssh_command(
            mock_client, "failing_cmd", timeout=5, max_output=1000
        )

        assert out == "output"
        assert err == "error msg"
        assert exit_code == 1

    def test_timeout_raises_ssh_timeout_error(self):
        """Socket timeout during command raises SSHTimeoutError."""
        mock_client = MagicMock()
        mock_client.exec_command.side_effect = socket.timeout("timed out")

        with pytest.raises(SSHTimeoutError, match="timed out"):
            execute_ssh_command(
                mock_client, "slow_cmd", timeout=5, max_output=50000
            )

    def test_sudo_writes_password_to_stdin(self):
        """Sudo command writes password to stdin."""
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"root"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        out, err, exit_code = execute_ssh_command(
            mock_client,
            "sudo whoami",
            timeout=10,
            max_output=50000,
            sudo=True,
            sudo_password="rootpw",
        )

        mock_stdin.write.assert_called_once_with("rootpw\n")
        mock_stdin.flush.assert_called_once()
        mock_stdin.close.assert_called_once()
        assert out == "root"

    def test_no_sudo_skips_stdin_write(self):
        """Non-sudo command does not write to stdin."""
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        execute_ssh_command(
            mock_client,
            "hostname",
            timeout=10,
            max_output=50000,
            sudo=False,
        )

        mock_stdin.write.assert_not_called()

    def test_utf8_replacement_for_invalid_bytes(self):
        """Invalid UTF-8 bytes in output are replaced instead of raising."""
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"good\xff\xfebad"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )

        out, err, exit_code = execute_ssh_command(
            mock_client, "cmd", timeout=10, max_output=50000
        )

        assert "\ufffd" in out  # Unicode replacement character


# ---------------------------------------------------------------------------
# check_ssh_connection tests
# ---------------------------------------------------------------------------


class TestCheckSSHConnection:
    """Tests for check_ssh_connection()."""

    def _make_manager_and_mock(self, tmp_path, config):
        """Create a ConfigManager and mock SSHClientManager."""
        mgr = _make_config_manager(tmp_path, config)
        ssh_mgr = MagicMock()
        return mgr, ssh_mgr

    def test_successful_check(self, tmp_path):
        """Successful check returns success=True with output."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"ping"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
                timeout=10,
            )

        assert result["success"] is True
        assert result["output"] == "ping"
        assert result["error"] is None
        assert result["exit_code"] == 0
        assert result["checkcommand"] == DEFAULT_CHECK_COMMAND

    def test_failed_check_command(self, tmp_path):
        """Check command with non-zero exit returns success=False."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"command not found"
        mock_stdout.channel.recv_exit_status.return_value = 127

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
            )

        assert result["success"] is False
        assert result["exit_code"] == 127
        assert result["error"] is not None
        assert "command not found" in result["error"]

    def test_custom_checkcommand(self, tmp_path):
        """Target with custom checkcommand uses that command."""
        config = _minimal_config(
            ssh_targets={
                "testserver": {
                    "host": "10.0.0.1",
                    "username": "testuser",
                    "port": 22,
                    "password": "testpass",
                    "checkcommand": "uptime",
                },
            }
        )
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"12:00  up 5 days"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
            )

        assert result["checkcommand"] == "uptime"
        mock_client.exec_command.assert_called_once_with(
            "uptime", timeout=10
        )

    def test_checkcommand_read_from_config_manager(self, tmp_path):
        """checkcommand is read from the ConfigManager's in-memory data."""
        config = _minimal_config(
            ssh_targets={
                "testserver": {
                    "host": "10.0.0.1",
                    "username": "testuser",
                    "port": 22,
                    "password": "testpass",
                    "checkcommand": "uptime",
                },
            }
        )
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"ok"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
            )

        assert result["checkcommand"] == "uptime"
        mock_client.exec_command.assert_called_once_with(
            "uptime", timeout=10
        )

    def test_timeout_clamped_to_min(self, tmp_path):
        """Timeout below minimum is clamped to DEFAULT_SSH_CHECK_TIMEOUT_MIN."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"ok"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
                timeout=0,  # below min
            )

        mock_client.exec_command.assert_called_once_with(
            "echo ping", timeout=DEFAULT_SSH_CHECK_TIMEOUT_MIN
        )

    def test_timeout_clamped_to_max(self, tmp_path):
        """Timeout above maximum is clamped to DEFAULT_SSH_CHECK_TIMEOUT_MAX."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"ok"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
                timeout=999,  # above max
            )

        mock_client.exec_command.assert_called_once_with(
            "echo ping", timeout=DEFAULT_SSH_CHECK_TIMEOUT_MAX
        )

    def test_target_not_found(self, tmp_path):
        """Non-existent target raises SSHConnectionError."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        with pytest.raises(SSHConnectionError, match="not found"):
            check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "nosuchserver",
                "/app/ssh_key",
            )

    def test_auth_failure_propagates(self, tmp_path):
        """SSHAuthenticationError from connect() propagates up."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            side_effect=SSHAuthenticationError("auth failed")
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            with pytest.raises(SSHAuthenticationError):
                check_ssh_connection(
                    ssh_mgr,
                    config_mgr,
                    "testserver",
                    "/app/ssh_key",
                )

    def test_connection_failure_propagates(self, tmp_path):
        """SSHConnectionError from connect() propagates up."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            side_effect=SSHConnectionError("refused")
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            with pytest.raises(SSHConnectionError, match="refused"):
                check_ssh_connection(
                    ssh_mgr,
                    config_mgr,
                    "testserver",
                    "/app/ssh_key",
                )

    def test_timeout_error_propagates(self, tmp_path):
        """SSHTimeoutError from command execution propagates up."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_client.exec_command.side_effect = socket.timeout("timed out")

        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            with pytest.raises(SSHTimeoutError):
                check_ssh_connection(
                    ssh_mgr,
                    config_mgr,
                    "testserver",
                    "/app/ssh_key",
                )

    def test_stderr_output_tracked(self, tmp_path):
        """Stderr output from check command is captured in result."""
        config = _minimal_config()
        config_mgr, ssh_mgr = self._make_manager_and_mock(tmp_path, config)

        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"some warning"
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (
            mock_stdin,
            mock_stdout,
            mock_stderr,
        )
        ssh_mgr.connect.return_value.__enter__ = MagicMock(
            return_value=mock_client
        )
        ssh_mgr.connect.return_value.__exit__ = MagicMock(return_value=False)

        with patch(
            "lib.ssh_operations.os.path.exists", return_value=True
        ):
            result = check_ssh_connection(
                ssh_mgr,
                config_mgr,
                "testserver",
                "/app/ssh_key",
            )

        assert result["error"] == "some warning"
        assert result["success"] is True
