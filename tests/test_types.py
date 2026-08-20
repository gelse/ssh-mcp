"""Tests for lib.types — TypedDict definitions for MCP tool return values."""

from __future__ import annotations

from typing import get_type_hints

import pytest

from lib.types import (
    AllowedCommand,
    AllowedCommandsResult,
    CommandError,
    CommandResult,
    FileDownloadResult,
    FileUploadResult,
    HealthCheckResult,
    ServerInfo,
    ServerListResult,
    SSHTarget,
)


# ---------------------------------------------------------------------------
# Test: each TypedDict is actually a dict subclass at runtime
# ---------------------------------------------------------------------------


class TestTypedDictRuntimeBehavior:
    """TypedDict instances are plain dicts at runtime."""

    @pytest.mark.parametrize(
        "cls",
        [
            ServerInfo,
            ServerListResult,
            AllowedCommand,
            AllowedCommandsResult,
            CommandResult,
            CommandError,
            FileDownloadResult,
            FileUploadResult,
            HealthCheckResult,
            SSHTarget,
        ],
        ids=[
            "ServerInfo",
            "ServerListResult",
            "AllowedCommand",
            "AllowedCommandsResult",
            "CommandResult",
            "CommandError",
            "FileDownloadResult",
            "FileUploadResult",
            "HealthCheckResult",
            "SSHTarget",
        ],
    )
    def test_typed_dict_is_dict_subclass(self, cls: type) -> None:
        """Every TypedDict is a dict subclass at runtime."""
        assert issubclass(cls, dict)

    @pytest.mark.parametrize(
        "cls",
        [
            ServerInfo,
            ServerListResult,
            AllowedCommand,
            AllowedCommandsResult,
            CommandResult,
            CommandError,
            FileDownloadResult,
            FileUploadResult,
            HealthCheckResult,
            SSHTarget,
        ],
        ids=[
            "ServerInfo",
            "ServerListResult",
            "AllowedCommand",
            "AllowedCommandsResult",
            "CommandResult",
            "CommandError",
            "FileDownloadResult",
            "FileUploadResult",
            "HealthCheckResult",
            "SSHTarget",
        ],
    )
    def test_typed_dict_instantiation_as_dict(self, cls: type) -> None:
        """TypedDicts can be instantiated as plain dicts (no __init__ validation)."""
        instance = cls()  # type: ignore[call-arg]
        assert isinstance(instance, dict)
        assert len(instance) == 0


# ---------------------------------------------------------------------------
# Test: required keys via type hints
# ---------------------------------------------------------------------------


class TestTypedDictRequiredKeys:
    """Each TypedDict declares the expected set of required keys."""

    @pytest.mark.parametrize(
        "cls,expected_keys",
        [
            (
                ServerInfo,
                {"host", "port", "user", "description"},
            ),
            (
                ServerListResult,
                {"servers"},
            ),
            (
                AllowedCommand,
                {"command", "description"},
            ),
            (
                AllowedCommandsResult,
                {"target_name", "commands"},
            ),
            (
                CommandResult,
                {"target_name", "command", "stdout", "stderr", "exit_code"},
            ),
            (
                CommandError,
                {"error", "target_name", "command"},
            ),
            (
                FileDownloadResult,
                {"filename", "content"},
            ),
            (
                FileUploadResult,
                {"target_name", "remote_path", "bytes_written"},
            ),
            (
                HealthCheckResult,
                {"status", "server_count"},
            ),
        ],
        ids=[
            "ServerInfo",
            "ServerListResult",
            "AllowedCommand",
            "AllowedCommandsResult",
            "CommandResult",
            "CommandError",
            "FileDownloadResult",
            "FileUploadResult",
            "HealthCheckResult",
        ],
    )
    def test_required_keys_present_in_hints(
        self, cls: type, expected_keys: set[str]
    ) -> None:
        """get_type_hints() reveals the expected required keys."""
        hints = get_type_hints(cls)
        assert set(hints.keys()) == expected_keys


# ---------------------------------------------------------------------------
# Test: SSHTarget total=False allows empty dict
# ---------------------------------------------------------------------------


class TestSSHTargetOptionalFields:
    """SSHTarget uses total=False — all fields are optional."""

    def test_ssh_target_allows_empty_dict(self) -> None:
        """SSHTarget (total=False) accepts an empty dict."""
        target: SSHTarget = {}
        assert isinstance(target, dict)
        assert len(target) == 0

    def test_ssh_target_allows_partial_fields(self) -> None:
        """SSHTarget accepts any subset of its declared fields."""
        target: SSHTarget = {"host": "example.com", "port": 2222}
        assert target["host"] == "example.com"
        assert target["port"] == 2222

    def test_ssh_target_allows_all_fields(self) -> None:
        """SSHTarget accepts all five declared fields."""
        target: SSHTarget = {
            "host": "example.com",
            "port": 22,
            "username": "admin",
            "password": "secret",
            "private_key": "/path/to/key",
        }
        assert target["host"] == "example.com"
        assert target["port"] == 22
        assert target["username"] == "admin"
        assert target["password"] == "secret"
        assert target["private_key"] == "/path/to/key"


# ---------------------------------------------------------------------------
# Test: realistic construction of complex TypedDicts
# ---------------------------------------------------------------------------


class TestTypedDictRealisticConstruction:
    """Construct realistic instances to validate structure coherence."""

    def test_server_list_result_with_nested_server_info(self) -> None:
        """ServerListResult contains a list of ServerInfo dicts."""
        result: ServerListResult = {
            "servers": [
                {
                    "host": "db-primary",
                    "port": 22,
                    "user": "deploy",
                    "description": "Primary database server",
                },
                {
                    "host": "web-01",
                    "port": 22,
                    "user": "www",
                    "description": "Frontend web server",
                },
            ],
        }
        assert len(result["servers"]) == 2
        assert result["servers"][0]["host"] == "db-primary"
        assert result["servers"][1]["description"] == "Frontend web server"

    def test_allowed_commands_result_with_nested_commands(self) -> None:
        """AllowedCommandsResult contains a list of AllowedCommand dicts."""
        result: AllowedCommandsResult = {
            "target_name": "production",
            "commands": [
                {"command": "ls -la", "description": "List files"},
                {"command": "df -h", "description": "Disk usage"},
            ],
        }
        assert result["target_name"] == "production"
        assert len(result["commands"]) == 2
        assert result["commands"][0]["command"] == "ls -la"

    def test_command_result_complete_fields(self) -> None:
        """CommandResult includes stdout, stderr, and exit_code."""
        result: CommandResult = {
            "target_name": "web-01",
            "command": "uptime",
            "stdout": " 09:00:00 up 42 days",
            "stderr": "",
            "exit_code": 0,
        }
        assert result["exit_code"] == 0
        assert result["stdout"].startswith(" 09:00:00")

    def test_command_error_structure(self) -> None:
        """CommandError includes error message, target_name, and command."""
        error: CommandError = {
            "error": "Permission denied",
            "target_name": "db-primary",
            "command": "rm -rf /tmp/data",
        }
        assert error["error"] == "Permission denied"

    def test_file_upload_result_structure(self) -> None:
        """FileUploadResult includes remote_path and bytes_written."""
        result: FileUploadResult = {
            "target_name": "web-01",
            "remote_path": "/tmp/upload.txt",
            "bytes_written": 1024,
        }
        assert result["bytes_written"] == 1024

    def test_health_check_result_structure(self) -> None:
        """HealthCheckResult includes status string and server_count."""
        result: HealthCheckResult = {
            "status": "healthy",
            "server_count": 3,
        }
        assert result["status"] == "healthy"
        assert result["server_count"] == 3

    def test_file_download_result_structure(self) -> None:
        """FileDownloadResult includes filename and content."""
        result: FileDownloadResult = {
            "filename": "report.csv",
            "content": "col1,col2\nval1,val2",
        }
        assert result["filename"] == "report.csv"
        assert "\n" in result["content"]
