"""Custom exception hierarchy for the SSH MCP server.

All exceptions inherit from :class:`MCPSSHError` so callers can catch a
single base type when they need to handle any application-level error.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from lib.constants import HTTP_SERVICE_UNAVAILABLE

if TYPE_CHECKING:
    pass


class MCPSSHError(Exception):
    """Base exception for all application-level errors in mcp-ssh.

    Attributes:
        DEFAULT_USER_MESSAGE: Safe, generic message returned by
            :attr:`user_message` when no explicit user message is provided.
    """

    DEFAULT_USER_MESSAGE: str = "An internal error occurred"

    def __init__(
        self,
        *args: object,
        user_message: str | None = None,
    ) -> None:
        """Initialise the exception.

        Args:
            *args: Positional arguments forwarded to :class:`Exception`.
            user_message: Optional safe message suitable for end-user
                responses.  When ``None``, the class-level
                :attr:`DEFAULT_USER_MESSAGE` is returned by the
                :attr:`user_message` property.
        """
        super().__init__(*args)
        self._user_message: str | None = user_message

    @property
    def user_message(self) -> str:
        """Return a safe, user-facing error message.

        Returns:
            The explicit *user_message* passed at construction time, or the
            class-level :attr:`DEFAULT_USER_MESSAGE` when none was provided.
        """
        return self._user_message if self._user_message is not None else self.DEFAULT_USER_MESSAGE


class ConfigError(MCPSSHError):
    """Raised when a configuration-related operation fails (e.g. file I/O)."""

    DEFAULT_USER_MESSAGE: str = "Configuration error"


class SecretsError(MCPSSHError):
    """Raised when a secrets-related operation fails (e.g. invalid secrets JSON)."""

    DEFAULT_USER_MESSAGE: str = "Secrets configuration error"


class ConfigMigrationError(ConfigError):
    """Raised when a config schema migration cannot be applied."""

    DEFAULT_USER_MESSAGE: str = "Configuration migration error"


class ConfigValidationError(MCPSSHError):
    """Raised when configuration data fails schema or business-rule validation.

    Attributes:
        message: Human-readable error summary.
        errors: Optional list of individual validation error strings.
        field: Optional field name (backward-compatible alias for a
            one-element *errors* list).
    """

    DEFAULT_USER_MESSAGE: str = "Configuration validation failed"

    def __init__(
        self,
        message: str,
        errors: list[str] | None = None,
        field: str | None = None,
        *,
        user_message: str | None = None,
    ) -> None:
        """Initialise a configuration-validation error.

        Args:
            message: Human-readable error summary.
            errors: Optional list of individual validation error strings.
            field: Optional field name (backward-compatible alias).
            user_message: Optional safe message for end-user responses.
        """
        self.message: str = message
        self.errors: list[str] | None = errors
        self.field: str | None = field
        super().__init__(message, user_message=user_message)


class SSHConnectionError(MCPSSHError):
    """Raised when an SSH connection cannot be established or fails mid-session."""

    DEFAULT_USER_MESSAGE: str = "SSH connection failed"


class SSHAuthenticationError(SSHConnectionError):
    """Raised when SSH authentication fails (bad credentials or key rejection).

    Subclasses :class:`SSHConnectionError` so existing code that catches the
    broader connection error keeps working.
    """

    DEFAULT_USER_MESSAGE: str = "SSH authentication failed"


class SSHTimeoutError(SSHConnectionError):
    """Raised when an SSH connection or command times out.

    Subclasses :class:`SSHConnectionError` so existing code that catches the
    broader connection error keeps working.  Operations that raise this error
    are safe to retry.
    """

    DEFAULT_USER_MESSAGE: str = "Operation timed out"


class AuthorizationError(MCPSSHError):
    """Raised when a command or operation is denied by the authorization layer."""

    DEFAULT_USER_MESSAGE: str = "Command not authorized"


class FileTransferError(MCPSSHError):
    """Raised when an SFTP file transfer operation fails."""

    DEFAULT_USER_MESSAGE: str = "File transfer failed"


class PathValidationError(FileTransferError):
    """Raised when a remote path fails validation (e.g. path traversal).

    Subclasses :class:`FileTransferError` so existing code that catches the
    broader transfer error keeps working.
    """

    DEFAULT_USER_MESSAGE: str = "Invalid file path"


class RateLimitError(MCPSSHError):
    """Raised when a rate-limit threshold is exceeded."""

    DEFAULT_USER_MESSAGE: str = "Rate limit exceeded"


class ServiceUnavailableError(MCPSSHError):
    """Raised when the global SSH concurrency limit is reached.

    Carries ``status_code`` (HTTP 503) so the tool layer can reflect a
    Service Unavailable response.  Deliberately NOT an SSHConnectionError:
    this is a server-capacity signal, not a connection failure, and must
    never be counted by the circuit breaker or marked retryable.
    """

    DEFAULT_USER_MESSAGE: str = "Service temporarily unavailable"

    def __init__(
        self,
        message: str,
        status_code: int = HTTP_SERVICE_UNAVAILABLE,
        *,
        user_message: str | None = None,
    ) -> None:
        """Initialise a service-unavailable error.

        Args:
            message: Detailed error description (for logging).
            status_code: HTTP status code to return (default 503).
            user_message: Optional safe message for end-user responses.
        """
        self.status_code: int = status_code
        super().__init__(message, user_message=user_message)


class ShutdownError(MCPSSHError):
    """Raised during graceful-shutdown failures."""

    DEFAULT_USER_MESSAGE: str = "Service shutting down"
