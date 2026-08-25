"""Named constants for the SSH MCP server.

All magic strings, numbers, and default values are defined here to
eliminate duplication and improve maintainability.
"""

import re

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

DEFAULT_CONFIG_FILENAME: str = "ssh-mcp-config.json"
"""Default configuration file name inside ``DEFAULT_CONFIG_DIR``."""

DEFAULT_SECRETS_FILENAME: str = "secrets.json"
"""Default secrets file name inside ``DEFAULT_CONFIG_DIR``.

Holds sensitive values (SSH target ``password`` and API-key ``key_hash``)
separately from the main config so they can be guarded with stricter
permissions and excluded from VCS.
"""

DEFAULT_LOG_DIR: str = "/logs"
"""Default directory for JSONL log output."""

ACTIVE_LOG_FILENAME: str = "ssh-mcp.log"
"""Filename of the active JSONL log file written inside the log directory."""

DEFAULT_SSH_KEY_FILENAME: str = "ssh_key"
"""Default filename for the private SSH key inside ``DEFAULT_CONFIG_DIR``."""

MCP_SSH_SECRET_PREFIX: str = "MCP_SSH_SECRET_"
"""Prefix for environment variables that supply secrets.

Env vars are mapped as ``MCP_SSH_SECRET_PASSWORD_<TARGET_ID>`` for SSH
target passwords and ``MCP_SSH_SECRET_API_KEY_<KEY_NAME>`` for API-key
hashes.  Identifiers are upper-cased with ``-`` replaced by ``_``.
"""

MCP_SSH_SETTING_PREFIX: str = "MCP_SSH_SETTING_"
"""Prefix for environment variables that override non-secret settings.

Env vars are mapped as ``MCP_SSH_SETTING_<SETTING_KEY>`` where the key is
upper-cased with ``-`` replaced by ``_``, and coerced to the type declared
in :data:`SETTING_KEY_TYPES`.  Precedence is env var > secrets.json >
config.json > defaults.
"""

MCP_SSH_CONFIG_PATH: str = "MCP_SSH_CONFIG_PATH"
"""Environment variable that overrides the path to ``ssh-mcp-config.json``."""

MCP_SSH_LOG_DIR: str = "MCP_SSH_LOG_DIR"
"""Environment variable that overrides the log output directory."""

MCP_SSH_LOG_LEVEL: str = "MCP_SSH_LOG_LEVEL"
"""Environment variable that overrides the default log level.

When set, this value replaces ``DEFAULT_LOG_LEVEL`` for the default
target level.  Per-target ``log_level`` overrides in the config file
take precedence over this env var.
"""

MCP_SSH_SSH_KEY: str = "MCP_SSH_SSH_KEY"
"""Environment variable that overrides the private SSH key path."""

RESTRICTED_FILE_MODE: int = 0o600
"""Permission mode enforced for config and secrets files.

Group/world read or write bits trigger a ``permissions_insecure`` warning
event, and are corrected by the ``--fix-permissions`` CLI flag.
"""

SECRETS_FILE_MODE: int = RESTRICTED_FILE_MODE  # backward-compatible alias
"""Required permission bits for ``secrets.json`` (alias of
``RESTRICTED_FILE_MODE``).

Group/world read or write bits on the secrets file trigger a
``secrets.permissions_insecure`` warning event at load time.
"""

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

MAX_TARGET_NAME_LENGTH: int = 128
"""Maximum length (characters) of an SSH target identifier."""

MAX_TARGETS: int = 1_000
"""Maximum number of SSH targets allowed in a single config file."""

MAX_BLOCK_PATTERNS: int = 500
"""Maximum number of block_patterns entries allowed in a single config file."""

MAX_REGEX_PATTERN_LENGTH: int = 10_000
"""Maximum character length of a single block_patterns regex entry."""

MAX_API_KEY_LENGTH: int = 1024
"""Maximum length (characters) of a raw API key before hashing."""

TARGET_NAME_PATTERN: re.Pattern[str] = re.compile(r"[a-zA-Z0-9._-]+")
"""Regex matching a single valid target-name run (see MAX_TARGET_NAME_LENGTH
for the upper bound; ``sanitize_target_name`` combines both)."""

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
"""Minimum delay (seconds) between config reloads triggered by file changes.

A value of ``0`` disables debouncing entirely, so every file change
triggers an immediate reload.
"""

DEFAULT_SSH_PORT: int = 22
"""Fallback TCP port when an SSH target does not specify one."""

DEFAULT_SSH_TIMEOUT_SECONDS: int = 30
"""Default SSH connection timeout in seconds."""

DEFAULT_CHECK_COMMAND: str = "echo ping"
"""Default command executed to verify SSH connectivity when no
per-target checkcommand is configured."""

DEFAULT_SSH_CHECK_TIMEOUT_MIN: int = 1
"""Minimum allowed timeout (seconds) for the SSH connectivity check."""

DEFAULT_SSH_CHECK_TIMEOUT_MAX: int = 30
"""Maximum allowed timeout (seconds) for the SSH connectivity check."""

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

DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS: int = 20
"""Default global cap on concurrent SSH connections across all targets."""

HTTP_SERVICE_UNAVAILABLE: int = 503
"""HTTP status for Service Unavailable (concurrency-limit rejection)."""

DEFAULT_SSH_EXECUTOR_MAX_WORKERS: int = 8
"""Default maximum worker threads for the SSH operation thread pool."""

DEFAULT_SHUTDOWN_TIMEOUT_SECONDS: int = 30
"""Default time (seconds) to wait for pending SSH work during a graceful shutdown.

On shutdown the server drains in-flight requests for at most this many
seconds before force-cancelling the remaining work and releasing resources.
"""

SETTING_KEY_TYPES: dict[str, str] = {
    "max_output_length": "size",
    "command_timeout_max": "int",
    "retry_max_attempts": "int",
    "retry_backoff_base_seconds": "float",
    "circuit_breaker_failure_threshold": "int",
    "circuit_breaker_timeout_seconds": "float",
    "log_level": "str",
    "logging": "dict",
    "max_log_output": "int",
    "compress_rotated": "bool",
    "pool_max_connections_per_target": "int",
    "pool_idle_timeout_seconds": "float",
    "pool_cleanup_interval_seconds": "float",
    "max_concurrent_ssh_connections": "int",
    "watcher_debounce_seconds": "float",
    "trusted_proxies": "list",
}
"""Maps each ``settings`` key to its expected Python type name.

Used to coerce ``MCP_SSH_SETTING_<KEY>`` environment-variable overrides
before they are merged into the validated config.
"""

# =============================================================================
# Config Schema Version
# =============================================================================

LATEST_CONFIG_VERSION: int = 1
"""The most recent config schema version this release understands."""

CONFIG_BACKUP_SUFFIX: str = ".bak"
"""Suffix appended to the original config path when writing a pre-migration backup."""

MIGRATED_FILE_MODE: int = 0o600
"""File permission applied to migrated/backup config files."""

# =============================================================================
# Block Patterns
# =============================================================================

DEFAULT_BLOCK_PATTERNS: tuple[str, ...] = (
    r"\bsudo\b",
    r"\brm\s+-rf\b",
    r"\bdd\s+if=",
    r"\b>:.*/(dev|proc|sys)/",
    r"\bmkfs\.",
    r"\bwipefs\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bpoweroff\b",
    r"\binit\s+[06]",
    r"\bhalt\b",
)
"""Default dangerous command patterns applied before allow-list authorization.

Each entry is a compiled-able regular expression; if a requested command
matches any pattern it is denied regardless of other authorization layers.
"""

REDIRECT_FD_DUP_RE: str = r"(?<!\S)(?:[0-9]+[12]?>&[0-9-]|[12]?>&[0-9-]|[12]?>&-)"
"""Regex matching shell file-descriptor duplication and closure redirection forms.

Covers forms such as ``2>&1``, ``>&2``, ``3>&1``, ``2>&-``, and ``>&-``.
Used by the redirection stripper to remove fd-dup/fd-close operators before
command segmentation.  Anchored on a non-word-boundary start so an ``&`` or
``>`` embedded inside a quoted argument is not consumed.
"""

REDIRECT_FILE_OP_RE: str = r"(?<!\S)(?:&>>|&>|[12]>>|[12]>|>>|>)"
"""Regex matching shell file-redirection operators.

Covers ``>``, ``>>``, ``1>``, ``1>>``, ``2>``, ``2>>``, ``&>``, and ``&>>``,
optionally prefixed with an fd digit.  Anchored on a non-word-boundary start so
a ``>`` embedded inside a quoted argument or a comparison in ``awk`` (e.g.
``awk '$1 > 5'``) is not treated as a redirector.
"""

PROTECTED_REDIRECT_TARGET_RE: str = r">\s*/?(?:dev|proc|sys)/"
"""Regex matching redirection targets into protected pseudofilesystem paths.

Matches a ``>`` redirect whose target begins with (optionally leading slash)
``dev/``, ``proc/``, or ``sys/`` (e.g. ``>/dev/sda``, ``> /proc/self/fd/0``,
``>/sys/...``).  Used as a defense-in-depth denial so these destructive
redirections are blocked independently of the operator-supplied
``block_patterns`` list.
"""

# =============================================================================
# ReDoS Protection
# =============================================================================

DEFAULT_REDOGS_TIMEOUT_SECONDS: float = 0.5
"""Hard timeout (seconds) for regex matching in block pattern checks.

If a compiled pattern does not complete and return within this window, the
match is treated as a non-match (safe default: the command is **not** blocked
by that pattern).  The operator should repair the offending pattern; the
static analysis in :mod:`lib.redos_protection` catches most dangerous
patterns at config load before they ever reach runtime.
"""

REDOGS_DANGEROUS_PATTERNS: tuple[str, ...] = (
    r"\([^()]*[\*\+][^()]*\)[\*\+]",
    r"\([^()]+\|[^()]+\)[\*\+]",
    r"\([^()]*\.[\*\+][^()]*\)(?:\{[^}]*\}|\+)",
)
"""Detector regexes applied to block-pattern *source* strings to flag known
ReDoS-prone constructs.

These are best-effort heuristics that scan the raw pattern text for nested
quantifiers, overlapping alternations, and quantified dot-star groups.  They
catch obvious unsafe constructs (e.g. ``(a+)+``, ``(a|a)+``, ``(.*a){n}``)
but are not exhaustive — the runtime timeout wrapper is the true safety net.
"""

# =============================================================================
# File Transfer Limits
# =============================================================================

BYTES_PER_KB: int = 1024
"""Number of bytes in one kibibyte."""

BYTES_PER_MB: int = 1024 * 1024
"""Number of bytes in one mebibyte."""

SIZE_UNIT_MULTIPLIERS: dict[str, int] = {
    "b": 1,
    "kb": BYTES_PER_KB,
    "mb": BYTES_PER_MB,
    "gb": BYTES_PER_MB * BYTES_PER_KB,
}
"""Case-insensitive size-suffix to byte multiplier for ``parse_size_bytes``."""

DEFAULT_MAX_FILE_SIZE_BYTES: int = 10 * BYTES_PER_MB
"""Default maximum file size (10 MiB) for uploads and downloads."""

DEFAULT_SFTP_SANDBOX_ROOT: str = "/"
"""Default sandbox root for SFTP path validation.

When set to ``"/"`` any absolute path is allowed (full access).
Set to a subdirectory (e.g. ``"/home/app/sftp"``) to restrict
file transfers to that directory tree.
"""

DEFAULT_MAX_SFTP_PATH_LENGTH: int = 4096
"""Default maximum allowed length for SFTP remote paths (bytes).

Protects against excessively long paths that could trigger filesystem
or SFTP protocol edge cases.  Set to 0 to disable the length check.
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

DEFAULT_RATE_LIMIT_ENABLED: bool = True
"""Whether per-IP rate limiting is enabled by default.

Set ``settings.rate_limit.enabled`` to ``false`` in the config file to
disable rate limiting entirely (e.g. for integration test suites that
issue a high volume of requests from a single client IP).
"""

DEFAULT_RATE_LIMIT_REQUESTS: int = 60
"""Default maximum requests per client IP within the rate-limit window."""

DEFAULT_RATE_LIMIT_WINDOW_SECONDS: float = 60.0
"""Default sliding-window duration (seconds) for rate limiting."""

RATE_LIMIT_CLEANUP_INTERVAL_SECONDS: float = 300.0
"""Minimum interval (seconds) between expired-entry garbage collections."""

# =============================================================================
# Request Context Defaults
# =============================================================================

FALLBACK_CLIENT_IP: str = "127.0.0.1"
"""Fallback client IP used when no request context is active.

Loopback is the safest authorization fallback: it does not accidentally
grant network allow-list access to an external IP, while still being a
well-formed, validatable address.
"""

DEFAULT_REQUEST_ID: str = "unknown"
"""Fallback request correlation ID used outside any request context.

Must be non-empty so callers can always correlate logs and error
responses with a stable, truthy identifier.
"""

DEFAULT_TRUSTED_PROXIES: list[str] = []
"""Trusted reverse proxies honored for ``X-Forwarded-For`` resolution.

When non-empty, the request middleware only accepts the client IP from
the ``X-Forwarded-For`` header when the direct connection peer is in
this list.  An empty list means no proxy is trusted and the header is
ignored entirely, preventing header spoofing by untrusted clients.
"""

# =============================================================================
# Pluggable Log Target Defaults
# =============================================================================

DEFAULT_LOG_TARGETS: list[dict] = [{"target": "stdout"}]
"""Default log targets when ``settings.logging.log_targets`` is absent."""

LOG_TARGET_STDOUT: str = "stdout"
"""Identifier for the stdout log target type."""

LOG_TARGET_JSONFILE: str = "jsonfile"
"""Identifier for the JSONL file log target type."""

LOG_TARGET_TEXTFILE: str = "file"
"""Identifier for the text file log target type."""

SUPPORTED_LOG_TARGETS: tuple[str, ...] = (
    LOG_TARGET_STDOUT,
    LOG_TARGET_JSONFILE,
    LOG_TARGET_TEXTFILE,
)
"""All supported log target type identifiers."""

DEFAULT_TEXT_LOG_FORMAT: str = "{timestamp} {level} {event}: {message}"
"""Default text format string for stdout and text-file targets."""
