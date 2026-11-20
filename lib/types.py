"""TypedDict definitions for MCP tool return values and internal data structures.

Using :class:`~typing.TypedDict` instead of plain ``dict`` provides better
IDE autocompletion, type-checking, and self-documenting code.
"""

from __future__ import annotations

from typing import TypedDict


class ServerInfo(TypedDict):
    """Information about a single configured SSH target server."""

    host: str
    """Hostname or IP address of the target."""

    port: int
    """TCP port for the SSH connection."""

    user: str
    """Username for SSH authentication."""

    description: str
    """Human-readable description of the server."""


class ServerListResult(TypedDict):
    """Return type for the ``ssh_list_servers`` MCP tool."""

    servers: list[ServerInfo]
    """List of configured SSH target servers."""


class AllowedCommand(TypedDict):
    """A single command that the caller is authorized to execute."""

    command: str
    """The command string (e.g. ``"ls -la"`` or ``"*"`` for wildcard)."""

    description: str
    """Human-readable description of what the command does."""


class AllowedCommandsResult(TypedDict):
    """Return type for the ``ssh_list_allowed_commands`` MCP tool."""

    target_name: str
    """The target server for which commands were queried."""

    commands: list[AllowedCommand]
    """Commands the caller is authorised to run on *target_name*."""


class CommandResult(TypedDict):
    """Return type for the ``ssh_execute_command`` MCP tool on success."""

    target_name: str
    """Target server where the command ran."""

    command: str
    """The command that was executed."""

    stdout: str
    """Standard output captured from the command."""

    stderr: str
    """Standard error captured from the command."""

    exit_code: int
    """Process exit code (0 typically means success)."""


class CommandError(TypedDict):
    """Return type for the ``ssh_execute_command`` MCP tool on failure."""

    error: str
    """Human-readable error message."""

    target_name: str
    """Target server where the error occurred."""

    command: str
    """The command that was attempted."""


class FileDownloadResult(TypedDict):
    """Return type for the ``ssh_download_file`` MCP tool."""

    filename: str
    """Base name of the downloaded file."""

    content: str
    """File contents as a UTF-8 string."""


class FileUploadResult(TypedDict):
    """Return type for the ``ssh_upload_file`` MCP tool."""

    target_name: str
    """Target server where the file was uploaded."""

    remote_path: str
    """Absolute path on the remote server where content was written."""

    bytes_written: int
    """Number of bytes written to the remote file."""


class CheckConnectionResult(TypedDict):
    """Return type for the ``ssh_check_connection`` MCP tool."""

    success: bool
    """Whether the SSH check succeeded."""

    output: str
    """Stdout from the check command."""

    error: str | None
    """Error message if the check failed, else None."""

    exit_code: int
    """Process exit code from the check command."""

    checkcommand: str
    """The command that was executed."""


class SudoGrants(TypedDict):
    """Commands a target may run with ``sudo``, collected from the config.

    Returned by :func:`lib.sudoers.collect_sudo_grants`.
    """

    commands: list[str]
    """Sorted, de-duplicated command names that may run with sudo."""

    skipped: list[str]
    """Labels of rules omitted because they grant sudo for every command."""

    invalid: list[str]
    """Configured values that are not plausible command names."""


class SudoersCommand(TypedDict):
    """One command of a generated sudoers file, with its resolved path."""

    command: str
    """The configured command name."""

    path: str
    """Absolute path on the target, or an empty string when unresolved."""


class SudoersDocument(TypedDict):
    """Return type of ``GET /api/config/ssh_targets/{name}/sudoers``."""

    target: str
    """The target identifier."""

    username: str
    """The target's OS user; the only user the file grants to."""

    host: str
    """The target's configured host (header and diagnostics)."""

    filename: str
    """Suggested drop-in file name, safe for ``/etc/sudoers.d``."""

    alias: str
    """The generated ``Cmnd_Alias`` name."""

    content: str
    """The file contents, or an empty string when nothing resolved."""

    resolved: list[SudoersCommand]
    """Commands with a usable path on the target."""

    unresolved: list[str]
    """Configured sudo commands that have no usable path."""

    skipped: list[str]
    """Labels of rules omitted for granting sudo on every command."""

    invalid: list[str]
    """Configured values that are not plausible command names."""

    notes: list[str]
    """Explanations for an empty or partial document.

    Empty when the document is complete.  Otherwise each entry says why
    something is missing — no grants configured, path resolution
    unavailable, or a resolved path sudoers cannot take.
    """


class HealthCheckResult(TypedDict):
    """Return type for the health-check endpoint."""

    status: str
    """Health status string (e.g. ``"healthy"``)."""

    server_count: int
    """Number of configured SSH targets."""


class SSHTarget(TypedDict, total=False):
    """Internal representation of an SSH target read from configuration."""

    host: str
    """Hostname or IP address."""

    port: int
    """TCP port (defaults to 22 when omitted)."""

    username: str
    """SSH username."""

    password: str
    """Optional plain-text password for password authentication."""

    private_key: str
    """Optional path to the private key for key-based authentication."""

    checkcommand: str
    """Optional command executed to verify SSH connectivity."""
