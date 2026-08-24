"""Tests for config_api.ssh_checker — lightweight SSH connection checker."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import paramiko
import pytest

from config_api.ssh_checker import CheckResult, check_ssh_connection


class TestCheckSSHConnection:
    """Tests for check_ssh_connection()."""

    def test_successful_connection_and_command(self):
        """Successful SSH connection and command execution returns CheckResult."""
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"ping\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
                checkcommand="echo ping",
            )

        assert result.success is True
        assert result.output == "ping"
        assert result.exit_code == 0
        mock_client.connect.assert_called_once()

    def test_authentication_failure(self):
        """Authentication failure returns CheckResult with error."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="wrong",
            )

        assert result.success is False
        assert "Authentication failed" in result.error

    def test_connection_failure(self):
        """SSH connection failure returns CheckResult with error."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.SSHException("Connection refused")

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
            )

        assert result.success is False
        assert "Connection failed" in result.error

    def test_no_auth_configured(self):
        """No password or key configured returns error."""
        result = check_ssh_connection(
            host="192.168.1.100",
            port=22,
            username="testuser",
        )

        assert result.success is False
        assert "No authentication method" in result.error

    def test_private_key_not_found(self):
        """Non-existent private key file returns error."""
        result = check_ssh_connection(
            host="192.168.1.100",
            port=22,
            username="testuser",
            private_key="/nonexistent/key",
        )

        assert result.success is False
        assert "not found" in result.error

    def test_command_execution_failure(self):
        """Command that exits with non-zero code returns success=False."""
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 127
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"command not found\n"
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
                checkcommand="nonexistent-command",
            )

        assert result.success is False
        assert result.exit_code == 127
        assert "command not found" in result.error

    def test_client_always_closed(self):
        """SSH client is always closed even on error."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.SSHException("fail")

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
            )

        mock_client.close.assert_called_once()

    def test_default_checkcommand(self):
        """Default checkcommand is 'echo ping' when none specified."""
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b"ping\n"
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
            )

        # Verify the default command was used
        mock_client.exec_command.assert_called_once()
        call_args = mock_client.exec_command.call_args
        assert call_args[0][0] == "echo ping"

    def test_check_result_dataclass_fields(self):
        """CheckResult dataclass has all expected fields."""
        result = CheckResult(success=True, output="ok", exit_code=0)
        assert result.success is True
        assert result.output == "ok"
        assert result.error is None
        assert result.exit_code == 0

    def test_stderr_included_on_error(self):
        """Stderr output is included in error field when command fails."""
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 1
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b"permission denied\n"
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

        with patch("config_api.ssh_checker.paramiko.SSHClient", return_value=mock_client):
            result = check_ssh_connection(
                host="192.168.1.100",
                port=22,
                username="testuser",
                password="testpass",
                checkcommand="cat /etc/shadow",
            )

        assert result.success is False
        assert result.exit_code == 1
        assert "permission denied" in result.error
