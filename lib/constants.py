"""Named constants for the SSH MCP server.

All magic strings, numbers, and default values are defined here to
eliminate duplication and improve maintainability.
"""

# =============================================================================
# Application Identity
# =============================================================================

APP_NAME: str = "ssh-mcp-server"
"""Name used when creating the FastMCP application instance."""

APP_VERSION: str = "1.0.0"
"""Current semantic version of the application."""

# =============================================================================
# Default Paths
# =============================================================================

DEFAULT_CONFIG_DIR: str = "/config"
"""Default directory for the JSON configuration file."""

DEFAULT_CONFIG_FILENAME: str = "config.json"
"""Default configuration file name inside ``DEFAULT_CONFIG_DIR``."""

DEFAULT_LOG_DIR: str = "/logs"
"""Default directory for JSONL log output."""

DEFAULT_SSH_KEY_FILENAME: str = "ssh_key"
"""Default filename for the private SSH key inside ``DEFAULT_CONFIG_DIR``."""

# =============================================================================
# Auth / Crypto Constants
# =============================================================================

API_KEY_HASH_PREFIX: str = "sha256:"
"""Prefix prepended to hex-encoded SHA-256 API-key hashes.

.. deprecated::
    Newly hashed keys use the PBKDF2 format instead.
    This prefix remains for backward-compatibility verification only.
"""

PBKDF2_ALGO: str = "pbkdf2"
"""Algorithm identifier used in the PBKDF2 hash format prefix."""

PBKDF2_HASH_FUNC: str = "sha256"
"""Hash function name used as the HMAC primitive for PBKDF2."""

PBKDF2_ITERATIONS: int = 100_000
"""Number of PBKDF2 iterations for API-key hashing."""

PBKDF2_SALT_BYTES: int = 16
"""Length of the random per-key salt in bytes."""

# =============================================================================
# PEM Header Strings
# =============================================================================

PEM_HEADER_OPENSSH: str = "BEGIN OPENSSH PRIVATE KEY"
"""PEM header that identifies an Ed25519 OpenSSH-format private key."""

PEM_HEADER_RSA: str = "BEGIN RSA PRIVATE KEY"
"""PEM header that identifies a PKCS#1 RSA private key."""

PEM_HEADER_PKCS8: str = "BEGIN PRIVATE KEY"
"""PEM header that identifies a PKCS#8 generic private key."""

# =============================================================================
# Default Runtime Settings
# =============================================================================

DEFAULT_WATCHER_INTERVAL_SECONDS: float = 15.0
"""Default polling interval (seconds) for the config-file watcher."""

DEFAULT_WATCHER_DEBOUNCE_SECONDS: float = 2.0
"""Minimum delay (seconds) between config reloads triggered by file changes."""

DEFAULT_SSH_PORT: int = 22
"""Fallback TCP port when an SSH target does not specify one."""

DEFAULT_SSH_TIMEOUT_SECONDS: int = 30
"""Default SSH connection timeout in seconds."""

DEFAULT_COMMAND_TIMEOUT_SECONDS: int = 120
"""Default timeout (seconds) for remote command execution."""

DEFAULT_MAX_OUTPUT_LENGTH: int = 50_000
"""Default maximum length (characters) for command output returned to LLMs."""

DEFAULT_RETRY_MAX_ATTEMPTS: int = 3
"""Default maximum number of SSH connection attempts (including the first)."""

DEFAULT_RETRY_BACKOFF_BASE_SECONDS: float = 1.0
"""Default base delay (seconds) for exponential backoff between SSH retries."""

DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = 5
"""Default number of consecutive per-target failures before the circuit opens."""

DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS: float = 60.0
"""Default time (seconds) an open circuit waits before allowing a half-open probe."""

DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET: int = 5
"""Default maximum number of idle connections kept per SSH target."""

DEFAULT_POOL_IDLE_TIMEOUT_SECONDS: float = 300.0
"""Default time (seconds) an idle pooled connection is kept before eviction."""

DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS: float = 60.0
"""Default interval (seconds) between idle-cleanup sweeps of the pool."""

DEFAULT_SSH_EXECUTOR_MAX_WORKERS: int = 8
"""Default maximum worker threads for the SSH operation thread pool."""

# =============================================================================
# File Transfer Limits
# =============================================================================

BYTES_PER_MB: int = 1024 * 1024
"""Number of bytes in one mebibyte."""

DEFAULT_MAX_FILE_SIZE_BYTES: int = 10 * BYTES_PER_MB
"""Default maximum file size (10 MiB) for uploads and downloads."""

DEFAULT_SFTP_SANDBOX_ROOT: str = "/"
"""Default sandbox root for SFTP path validation.

When set to ``"/"`` any absolute path is allowed (full access).
Set to a subdirectory (e.g. ``"/home/app/sftp"``) to restrict
file transfers to that directory tree.
"""

# =============================================================================
# Path-Security Constants
# =============================================================================

# Unicode characters commonly abused for path-traversal attacks:
#   \u2215  DIVISION SLASH         (visually similar to /)
#   \u2024  ONE DOT LEADER         (visually similar to .)
#   \u2025  TWO DOT LEADER         (visually similar to ..)
#   \u2044  FRACTION SLASH         (visually similar to /)
#   \u2216  SET MINUS              (visually similar to \)
#   \uff0f  FULLWIDTH SOLIDUS      (visually similar to /)
#   \uff3c  FULLWIDTH REVERSE SOLIDUS (visually similar to \)
DANGEROUS_UNICODE_PATH_CHARS: str = (
    "\u2215\u2024\u2025\u2044\u2216\uff0f\uff3c"
)
"""Characters that can be used in Unicode normalisation path-traversal attacks."""
# =============================================================================
# Logging Defaults
# =============================================================================

DEFAULT_LOG_MAX_SIZE_MB: int = 10
"""Default per-file maximum size in mebibytes before rotation."""

DEFAULT_LOG_BACKUP_COUNT: int = 5
"""Default number of rotated backup files to keep."""

DEFAULT_MAX_LOG_OUTPUT: int = 4096
"""Default maximum number of characters kept for the ``output`` log field.

Any ``output`` longer than this is truncated at emission time and a
``"... [truncated, full output length: N bytes]"`` marker is appended.
"""

DEFAULT_COMPRESS_ROTATED: bool = True
"""Default for gzip-compressing rotated log backup files."""

DEFAULT_LOG_LEVEL: str = "INFO"
"""Default log level applied to the root logger.

Valid values are the standard Python logging levels listed in
:data:`LOG_LEVELS`.  Configurable via the ``log_level`` settings key.
"""

LOG_LEVELS: tuple[str, ...] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
"""Valid values for the ``log_level`` settings key."""

LOG_FORMAT_VERSION: int = 1
"""Version of the JSONL log entry schema.

Bump this whenever the set or semantics of top-level fields in a log
entry change, so consumers of the log stream can detect format drift.
"""

# =============================================================================
# Sudo Command Prefixes
# =============================================================================

SUDO_PASSWORD_PROMPT_FLAGS: str = "sudo -S -p ''"
"""``sudo`` invocation that reads password from stdin with an empty prompt."""

SUDO_NO_PASSWORD_FLAG: str = "sudo -n"
"""``sudo`` invocation that refuses to run if a password is required."""


# =============================================================================
# Rate-Limiting Defaults
# =============================================================================

DEFAULT_RATE_LIMIT_REQUESTS: int = 60
"""Default maximum requests per client IP within the rate-limit window."""

DEFAULT_RATE_LIMIT_WINDOW_SECONDS: float = 60.0
"""Default sliding-window duration (seconds) for rate limiting."""

RATE_LIMIT_CLEANUP_INTERVAL_SECONDS: float = 300.0
"""Minimum interval (seconds) between expired-entry garbage collections."""
