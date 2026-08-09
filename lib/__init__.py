# SSH MCP Server - modular library

from lib.auth import AuthResult, AuthorizationManager
from lib.config import ConfigManager
from lib.command_security import (
    check_dangerous_patterns,
    segment_command,
    split_command_segments as segment_command_chunks,
)
from lib.constants import (
    API_KEY_HASH_PREFIX,
    APP_NAME,
    APP_VERSION,
    BYTES_PER_MB,
    DANGEROUS_UNICODE_PATH_CHARS,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_OUTPUT_LENGTH,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_SFTP_SANDBOX_ROOT,
    DEFAULT_SSH_KEY_FILENAME,
    DEFAULT_SSH_PORT,
    DEFAULT_SSH_TIMEOUT_SECONDS,
    DEFAULT_WATCHER_INTERVAL_SECONDS,
    PBKDF2_ALGO,
    PBKDF2_HASH_FUNC,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
    PEM_HEADER_OPENSSH,
    PEM_HEADER_PKCS8,
    PEM_HEADER_RSA,
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
    SUDO_NO_PASSWORD_FLAG,
    SUDO_PASSWORD_PROMPT_FLAGS,
)
from lib.crypto import hash_api_key, verify_api_key
from lib.exceptions import (
    AuthorizationError,
    ConfigError,
    ConfigValidationError,
    FileTransferError,
    MCPSSHError,
    RateLimitError,
    ShutdownError,
    SSHConnectionError,
)
from lib.file_transfer import FileTransferService
from lib.rate_limiter import RateLimiter, RateLimitMiddleware
from lib.request_context import (
    get_api_key,
    get_client_ip,
    get_current_request,
    RequestContextMiddleware,
)
from lib.ssh_client import SSHClientManager
from lib.sudo import SudoHandler
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

__all__ = [
    # Command security
    "check_dangerous_patterns",
    "segment_command",
    "segment_command_chunks",
    # Rate limiting
    "RateLimiter",
    "RateLimitMiddleware",
    # Services
    "SudoHandler",
    "SSHClientManager",
    "FileTransferService",
    "FileTransferError",
    "MCPSSHError",
    "ConfigError",
    "ConfigValidationError",
    "SSHConnectionError",
    "AuthorizationError",
    "RateLimitError",
    "ShutdownError",
    "ConfigManager",
    "AuthResult",
    "AuthorizationManager",
    # Request context
    "get_api_key",
    "get_client_ip",
    "get_current_request",
    "RequestContextMiddleware",
    # Crypto
    "hash_api_key",
    "verify_api_key",
    # Constants
    "APP_NAME",
    "APP_VERSION",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_CONFIG_FILENAME",
    "DEFAULT_LOG_DIR",
    "DEFAULT_SSH_KEY_FILENAME",
    "API_KEY_HASH_PREFIX",
    "PBKDF2_ALGO",
    "PBKDF2_HASH_FUNC",
    "PBKDF2_ITERATIONS",
    "PBKDF2_SALT_BYTES",
    "PEM_HEADER_OPENSSH",
    "PEM_HEADER_RSA",
    "PEM_HEADER_PKCS8",
    "DEFAULT_WATCHER_INTERVAL_SECONDS",
    "DEFAULT_SSH_PORT",
    "DEFAULT_SSH_TIMEOUT_SECONDS",
    "DEFAULT_COMMAND_TIMEOUT_SECONDS",
    "DEFAULT_MAX_OUTPUT_LENGTH",
    "BYTES_PER_MB",
    "DEFAULT_MAX_FILE_SIZE_BYTES",
    "DEFAULT_SFTP_SANDBOX_ROOT",
    "DANGEROUS_UNICODE_PATH_CHARS",
    "DEFAULT_LOG_MAX_SIZE_MB",
    "DEFAULT_LOG_BACKUP_COUNT",
    "DEFAULT_RATE_LIMIT_REQUESTS",
    "DEFAULT_RATE_LIMIT_WINDOW_SECONDS",
    "RATE_LIMIT_CLEANUP_INTERVAL_SECONDS",
    "SUDO_PASSWORD_PROMPT_FLAGS",
    "SUDO_NO_PASSWORD_FLAG",
    # Types
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
]
