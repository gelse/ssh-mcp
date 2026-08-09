"""Custom exception hierarchy for the SSH MCP server.

All exceptions inherit from :class:`MCPSSHError` so callers can catch a
single base type when they need to handle any application-level error.
"""


class MCPSSHError(Exception):
    """Base exception for all application-level errors in mcp-ssh."""


class ConfigError(MCPSSHError):
    """Raised when a configuration-related operation fails (e.g. file I/O)."""


class ConfigValidationError(MCPSSHError):
    """Raised when configuration data fails schema or business-rule validation.

    Attributes:
        message: Human-readable error summary.
        errors: Optional list of individual validation error strings.
        field: Optional field name (backward-compatible alias for a
            one-element *errors* list).
    """

    def __init__(
        self,
        message: str,
        errors: list[str] | None = None,
        field: str | None = None,
    ) -> None:
        self.message: str = message
        self.errors: list[str] | None = errors
        self.field: str | None = field
        super().__init__(message)


class SSHConnectionError(MCPSSHError):
    """Raised when an SSH connection cannot be established or fails mid-session."""


class SSHAuthenticationError(SSHConnectionError):
    """Raised when SSH authentication fails (bad credentials or key rejection).

    Subclasses :class:`SSHConnectionError` so existing code that catches the
    broader connection error keeps working.
    """


class SSHTimeoutError(SSHConnectionError):
    """Raised when an SSH connection or command times out.

    Subclasses :class:`SSHConnectionError` so existing code that catches the
    broader connection error keeps working.  Operations that raise this error
    are safe to retry.
    """


class AuthorizationError(MCPSSHError):
    """Raised when a command or operation is denied by the authorization layer."""


class FileTransferError(MCPSSHError):
    """Raised when an SFTP file transfer operation fails."""


class PathValidationError(FileTransferError):
    """Raised when a remote path fails validation (e.g. path traversal).

    Subclasses :class:`FileTransferError` so existing code that catches the
    broader transfer error keeps working.
    """


class RateLimitError(MCPSSHError):
    """Raised when a rate-limit threshold is exceeded."""


class ShutdownError(MCPSSHError):
    """Raised during graceful-shutdown failures."""
