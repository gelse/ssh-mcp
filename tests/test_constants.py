"""Unit tests for lib/constants — type and value regression guards."""

from __future__ import annotations

import re

import pytest

from lib.constants import (
    APP_NAME,
    APP_VERSION,
    API_KEY_HASH_PREFIX,
    BYTES_PER_KB,
    BYTES_PER_MB,
    CONFIG_BACKUP_SUFFIX,
    DEFAULT_BLOCK_PATTERNS,
    DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_LOG_DIR,
    DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_LOG_OUTPUT,
    DEFAULT_MAX_OUTPUT_LENGTH,
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
    DEFAULT_RETRY_MAX_ATTEMPTS,
    DEFAULT_SECRETS_FILENAME,
    DEFAULT_SFTP_SANDBOX_ROOT,
    DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
    DEFAULT_SSH_EXECUTOR_MAX_WORKERS,
    DEFAULT_SSH_KEY_FILENAME,
    DEFAULT_SSH_PORT,
    DEFAULT_SSH_TIMEOUT_SECONDS,
    DEFAULT_WATCHER_DEBOUNCE_SECONDS,
    DEFAULT_WATCHER_INTERVAL_SECONDS,
    DANGEROUS_UNICODE_PATH_CHARS,
    FALLBACK_CLIENT_IP,
    HTTP_SERVICE_UNAVAILABLE,
    LATEST_CONFIG_VERSION,
    LOG_FORMAT_VERSION,
    LOG_LEVELS,
    MIGRATED_FILE_MODE,
    MAX_API_KEY_LENGTH,
    MAX_BLOCK_PATTERNS,
    MAX_REGEX_PATTERN_LENGTH,
    MAX_TARGET_NAME_LENGTH,
    MAX_TARGETS,
    MCP_SSH_CONFIG_PATH,
    MCP_SSH_LOG_DIR,
    MCP_SSH_SECRET_PREFIX,
    MCP_SSH_SSH_KEY,
    MCP_SSH_SETTING_PREFIX,
    PBKDF2_ALGO,
    PBKDF2_HASH_FUNC,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
    PEM_HEADER_OPENSSH,
    PEM_HEADER_PKCS8,
    PEM_HEADER_RSA,
    PROTECTED_REDIRECT_TARGET_RE,
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
    REDIRECT_FD_DUP_RE,
    REDIRECT_FILE_OP_RE,
    RESTRICTED_FILE_MODE,
    SECRETS_FILE_MODE,
    TARGET_NAME_PATTERN,
    SETTING_KEY_TYPES,
    SIZE_UNIT_MULTIPLIERS,
    SUDO_NO_PASSWORD_FLAG,
    SUDO_PASSWORD_PROMPT_FLAGS,
)


# ---------------------------------------------------------------------------
# Tests — Type correctness
# ---------------------------------------------------------------------------


class TestConstantTypes:
    """Verify each constant is the expected Python type."""

    @pytest.mark.parametrize(
        "name,value",
        [
            ("APP_NAME", APP_NAME),
            ("APP_VERSION", APP_VERSION),
            ("DEFAULT_CONFIG_DIR", DEFAULT_CONFIG_DIR),
            ("DEFAULT_CONFIG_FILENAME", DEFAULT_CONFIG_FILENAME),
            ("DEFAULT_SECRETS_FILENAME", DEFAULT_SECRETS_FILENAME),
            ("DEFAULT_LOG_DIR", DEFAULT_LOG_DIR),
            ("DEFAULT_SSH_KEY_FILENAME", DEFAULT_SSH_KEY_FILENAME),
            ("DEFAULT_LOG_LEVEL", DEFAULT_LOG_LEVEL),
            ("DEFAULT_SFTP_SANDBOX_ROOT", DEFAULT_SFTP_SANDBOX_ROOT),
            ("API_KEY_HASH_PREFIX", API_KEY_HASH_PREFIX),
            ("PBKDF2_ALGO", PBKDF2_ALGO),
            ("PBKDF2_HASH_FUNC", PBKDF2_HASH_FUNC),
            ("MCP_SSH_SECRET_PREFIX", MCP_SSH_SECRET_PREFIX),
            ("MCP_SSH_SETTING_PREFIX", MCP_SSH_SETTING_PREFIX),
            ("MCP_SSH_CONFIG_PATH", MCP_SSH_CONFIG_PATH),
            ("MCP_SSH_LOG_DIR", MCP_SSH_LOG_DIR),
            ("MCP_SSH_SSH_KEY", MCP_SSH_SSH_KEY),
            ("CONFIG_BACKUP_SUFFIX", CONFIG_BACKUP_SUFFIX),
            ("FALLBACK_CLIENT_IP", FALLBACK_CLIENT_IP),
            ("DEFAULT_REQUEST_ID", "unknown"),
        ],
        ids=[
            "APP_NAME", "APP_VERSION", "DEFAULT_CONFIG_DIR",
            "DEFAULT_CONFIG_FILENAME", "DEFAULT_SECRETS_FILENAME",
            "DEFAULT_LOG_DIR", "DEFAULT_SSH_KEY_FILENAME",
            "DEFAULT_LOG_LEVEL", "DEFAULT_SFTP_SANDBOX_ROOT",
            "API_KEY_HASH_PREFIX", "PBKDF2_ALGO", "PBKDF2_HASH_FUNC",
            "MCP_SSH_SECRET_PREFIX", "MCP_SSH_SETTING_PREFIX",
            "MCP_SSH_CONFIG_PATH", "MCP_SSH_LOG_DIR", "MCP_SSH_SSH_KEY",
            "CONFIG_BACKUP_SUFFIX", "FALLBACK_CLIENT_IP", "DEFAULT_REQUEST_ID",
        ],
    )
    def test_string_constants_are_strings(self, name: str, value: object) -> None:
        assert isinstance(value, str), f"{name} should be str"

    @pytest.mark.parametrize(
        "name,value",
        [
            ("PBKDF2_ITERATIONS", PBKDF2_ITERATIONS),
            ("PBKDF2_SALT_BYTES", PBKDF2_SALT_BYTES),
            ("MAX_TARGET_NAME_LENGTH", MAX_TARGET_NAME_LENGTH),
            ("MAX_API_KEY_LENGTH", MAX_API_KEY_LENGTH),
            ("DEFAULT_SSH_PORT", DEFAULT_SSH_PORT),
            ("DEFAULT_SSH_TIMEOUT_SECONDS", DEFAULT_SSH_TIMEOUT_SECONDS),
            ("DEFAULT_COMMAND_TIMEOUT_SECONDS", DEFAULT_COMMAND_TIMEOUT_SECONDS),
            ("DEFAULT_MAX_OUTPUT_LENGTH", DEFAULT_MAX_OUTPUT_LENGTH),
            ("DEFAULT_RETRY_MAX_ATTEMPTS", DEFAULT_RETRY_MAX_ATTEMPTS),
            (
                "DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            ),
            ("DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET", DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET),
            ("DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS", DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS),
            ("DEFAULT_SSH_EXECUTOR_MAX_WORKERS", DEFAULT_SSH_EXECUTOR_MAX_WORKERS),
            ("DEFAULT_SHUTDOWN_TIMEOUT_SECONDS", DEFAULT_SHUTDOWN_TIMEOUT_SECONDS),
            ("LATEST_CONFIG_VERSION", LATEST_CONFIG_VERSION),
            ("LOG_FORMAT_VERSION", LOG_FORMAT_VERSION),
            ("DEFAULT_LOG_MAX_SIZE_MB", DEFAULT_LOG_MAX_SIZE_MB),
            ("DEFAULT_LOG_BACKUP_COUNT", DEFAULT_LOG_BACKUP_COUNT),
            ("DEFAULT_MAX_LOG_OUTPUT", DEFAULT_MAX_LOG_OUTPUT),
            ("BYTES_PER_KB", BYTES_PER_KB),
            ("BYTES_PER_MB", BYTES_PER_MB),
            ("DEFAULT_MAX_FILE_SIZE_BYTES", DEFAULT_MAX_FILE_SIZE_BYTES),
            ("HTTP_SERVICE_UNAVAILABLE", HTTP_SERVICE_UNAVAILABLE),
            ("DEFAULT_RATE_LIMIT_REQUESTS", DEFAULT_RATE_LIMIT_REQUESTS),
            ("RESTRICTED_FILE_MODE", RESTRICTED_FILE_MODE),
            ("SECRETS_FILE_MODE", SECRETS_FILE_MODE),
            ("MIGRATED_FILE_MODE", MIGRATED_FILE_MODE),
            ("MAX_TARGETS", MAX_TARGETS),
            ("MAX_BLOCK_PATTERNS", MAX_BLOCK_PATTERNS),
            ("MAX_REGEX_PATTERN_LENGTH", MAX_REGEX_PATTERN_LENGTH),
        ],
        ids=[
            "PBKDF2_ITERATIONS", "PBKDF2_SALT_BYTES", "MAX_TARGET_NAME_LENGTH",
            "MAX_API_KEY_LENGTH", "DEFAULT_SSH_PORT", "DEFAULT_SSH_TIMEOUT_SECONDS",
            "DEFAULT_COMMAND_TIMEOUT_SECONDS", "DEFAULT_MAX_OUTPUT_LENGTH",
            "DEFAULT_RETRY_MAX_ATTEMPTS", "DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD",
            "DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET", "DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS",
            "DEFAULT_SSH_EXECUTOR_MAX_WORKERS", "DEFAULT_SHUTDOWN_TIMEOUT_SECONDS",
            "LATEST_CONFIG_VERSION", "LOG_FORMAT_VERSION", "DEFAULT_LOG_MAX_SIZE_MB",
            "DEFAULT_LOG_BACKUP_COUNT", "DEFAULT_MAX_LOG_OUTPUT", "BYTES_PER_KB",
            "BYTES_PER_MB", "DEFAULT_MAX_FILE_SIZE_BYTES", "HTTP_SERVICE_UNAVAILABLE",
            "DEFAULT_RATE_LIMIT_REQUESTS", "RESTRICTED_FILE_MODE", "SECRETS_FILE_MODE",
            "MIGRATED_FILE_MODE", "MAX_TARGETS", "MAX_BLOCK_PATTERNS",
            "MAX_REGEX_PATTERN_LENGTH",
        ],
    )
    def test_int_constants_are_ints(self, name: str, value: object) -> None:
        assert isinstance(value, int), f"{name} should be int"
        assert not isinstance(value, bool), f"{name} should not be bool"

    @pytest.mark.parametrize(
        "name,value",
        [
            ("DEFAULT_WATCHER_INTERVAL_SECONDS", DEFAULT_WATCHER_INTERVAL_SECONDS),
            ("DEFAULT_WATCHER_DEBOUNCE_SECONDS", DEFAULT_WATCHER_DEBOUNCE_SECONDS),
            ("DEFAULT_RETRY_BACKOFF_BASE_SECONDS", DEFAULT_RETRY_BACKOFF_BASE_SECONDS),
            ("DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS", DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS),
            ("DEFAULT_POOL_IDLE_TIMEOUT_SECONDS", DEFAULT_POOL_IDLE_TIMEOUT_SECONDS),
            ("DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS", DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS),
            ("DEFAULT_RATE_LIMIT_WINDOW_SECONDS", DEFAULT_RATE_LIMIT_WINDOW_SECONDS),
            ("RATE_LIMIT_CLEANUP_INTERVAL_SECONDS", RATE_LIMIT_CLEANUP_INTERVAL_SECONDS),
        ],
        ids=[
            "DEFAULT_WATCHER_INTERVAL_SECONDS", "DEFAULT_WATCHER_DEBOUNCE_SECONDS",
            "DEFAULT_RETRY_BACKOFF_BASE_SECONDS", "DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS",
            "DEFAULT_POOL_IDLE_TIMEOUT_SECONDS", "DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS",
            "DEFAULT_RATE_LIMIT_WINDOW_SECONDS", "RATE_LIMIT_CLEANUP_INTERVAL_SECONDS",
        ],
    )
    def test_float_constants_are_floats(self, name: str, value: object) -> None:
        assert isinstance(value, float), f"{name} should be float"

    @pytest.mark.parametrize(
        "name,value",
        [
            ("DEFAULT_BLOCK_PATTERNS", DEFAULT_BLOCK_PATTERNS),
            ("LOG_LEVELS", LOG_LEVELS),
        ],
    )
    def test_tuple_constants_are_tuples(self, name: str, value: object) -> None:
        assert isinstance(value, tuple), f"{name} should be tuple"


# ---------------------------------------------------------------------------
# Tests — Value correctness
# ---------------------------------------------------------------------------


class TestConstantValues:
    """Verify specific values and structural properties of constants."""

    def test_numeric_defaults_are_positive(self) -> None:
        """All numeric default constants are positive."""
        positives = [
            DEFAULT_WATCHER_INTERVAL_SECONDS,
            DEFAULT_WATCHER_DEBOUNCE_SECONDS,
            DEFAULT_SSH_PORT,
            DEFAULT_SSH_TIMEOUT_SECONDS,
            DEFAULT_COMMAND_TIMEOUT_SECONDS,
            DEFAULT_MAX_OUTPUT_LENGTH,
            DEFAULT_RETRY_MAX_ATTEMPTS,
            DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
            DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
            DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
            DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
            DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
            DEFAULT_SSH_EXECUTOR_MAX_WORKERS,
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
            DEFAULT_LOG_MAX_SIZE_MB,
            DEFAULT_LOG_BACKUP_COUNT,
            DEFAULT_MAX_LOG_OUTPUT,
            DEFAULT_MAX_FILE_SIZE_BYTES,
            PBKDF2_ITERATIONS,
            PBKDF2_SALT_BYTES,
            BYTES_PER_KB,
            BYTES_PER_MB,
            DEFAULT_RATE_LIMIT_REQUESTS,
            DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
            MAX_TARGETS,
            MAX_BLOCK_PATTERNS,
            MAX_REGEX_PATTERN_LENGTH,
        ]
        for v in positives:
            assert v > 0, f"Expected positive, got {v}"

    @pytest.mark.parametrize(
        "name,pattern,valid,invalid,fullmatch",
        [
            (
                "TARGET_NAME_PATTERN",
                TARGET_NAME_PATTERN,
                ["my-server", "host01", "db.primary"],
                ["", "has space", "bad!char"],
                True,
            ),
            (
                "REDIRECT_FD_DUP_RE",
                re.compile(rf"^{REDIRECT_FD_DUP_RE}$"),
                ["2>&1", ">&2", ">&-"],
                ["echo hello", "cat file"],
                True,
            ),
            (
                "REDIRECT_FILE_OP_RE",
                re.compile(rf"^{REDIRECT_FILE_OP_RE}$"),
                [">", ">>", "1>", "2>", "&>"],
                ["echo hello", "-rf"],
                True,
            ),
            (
                "PROTECTED_REDIRECT_TARGET_RE",
                re.compile(PROTECTED_REDIRECT_TARGET_RE),
                [">/dev/sda", "> /proc/self/fd", ">sys/class"],
                [">/tmp/out", ">output.log"],
                False,
            ),
        ],
        ids=[
            "TARGET_NAME_PATTERN",
            "REDIRECT_FD_DUP_RE",
            "REDIRECT_FILE_OP_RE",
            "PROTECTED_REDIRECT_TARGET_RE",
        ],
    )
    def test_regex_patterns_compile_and_match(
        self,
        name: str,
        pattern: re.Pattern,
        valid: list,
        invalid: list,
        fullmatch: bool,
    ) -> None:
        """Regex constants compile and match/miss expected strings."""
        match_fn = pattern.fullmatch if fullmatch else pattern.search
        for s in valid:
            assert match_fn(s), f"{name} should match '{s}'"
        for s in invalid:
            assert not match_fn(s), f"{name} should not match '{s}'"

    def test_target_name_pattern_is_compiled(self) -> None:
        """TARGET_NAME_PATTERN is a compiled re.Pattern."""
        assert isinstance(TARGET_NAME_PATTERN, re.Pattern)

    @pytest.mark.parametrize(
        "pattern_str,example",
        [
            (r"\bsudo\b", "sudo rm -rf /"),
            (r"\brm\s+-rf\b", "rm -rf /home"),
            (r"\bdd\s+if=", "dd if=/dev/zero"),
            (r"\bmkfs\.", "mkfs.ext4 /dev/sda"),
            (r"\bwipefs\b", "wipefs --all /dev/sda"),
            (r"\bshutdown\b", "shutdown -h now"),
            (r"\breboot\b", "reboot"),
            (r"\bpoweroff\b", "poweroff"),
            (r"\binit\s+[06]", "init 0"),
            (r"\bhalt\b", "halt"),
        ],
        ids=[
            "sudo", "rm -rf", "dd if=", "mkfs.", "wipefs",
            "shutdown", "reboot", "poweroff", "init 0", "halt",
        ],
    )
    def test_block_patterns_match_dangerous_commands(
        self, pattern_str: str, example: str
    ) -> None:
        """Each default block pattern matches its intended dangerous command."""
        compiled = re.compile(pattern_str)
        assert compiled.search(example), (
            f"Pattern {pattern_str} should match '{example}'"
        )

    def test_size_unit_multipliers_structure(self) -> None:
        """SIZE_UNIT_MULTIPLIERS has the expected keys and power-of-1024 values."""
        assert set(SIZE_UNIT_MULTIPLIERS.keys()) == {"b", "kb", "mb", "gb"}
        assert SIZE_UNIT_MULTIPLIERS["b"] == 1
        assert SIZE_UNIT_MULTIPLIERS["kb"] == 1024
        assert SIZE_UNIT_MULTIPLIERS["mb"] == 1024 * 1024
        assert SIZE_UNIT_MULTIPLIERS["gb"] == 1024 * 1024 * 1024

    def test_setting_key_types_complete(self) -> None:
        """SETTING_KEY_TYPES has 16 keys with valid type names."""
        assert len(SETTING_KEY_TYPES) == 16
        valid_types = {"int", "float", "str", "bool", "size", "list", "dict"}
        for key, type_name in SETTING_KEY_TYPES.items():
            assert isinstance(key, str)
            assert type_name in valid_types, f"{key} has invalid type '{type_name}'"

    def test_log_levels_exact_content(self) -> None:
        """LOG_LEVELS contains exactly the 5 standard Python levels."""
        assert LOG_LEVELS == ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

    def test_file_mode_constants_equal_0o600(self) -> None:
        """File permission constants are all 0o600."""
        assert RESTRICTED_FILE_MODE == 0o600
        assert SECRETS_FILE_MODE == 0o600
        assert MIGRATED_FILE_MODE == 0o600

    def test_pem_headers_present(self) -> None:
        """All three PEM header constants start with 'BEGIN'."""
        assert PEM_HEADER_OPENSSH.startswith("BEGIN")
        assert PEM_HEADER_RSA.startswith("BEGIN")
        assert PEM_HEADER_PKCS8.startswith("BEGIN")

    def test_config_version_is_positive_int(self) -> None:
        """LATEST_CONFIG_VERSION is a positive integer."""
        assert isinstance(LATEST_CONFIG_VERSION, int)
        assert LATEST_CONFIG_VERSION >= 1

    def test_block_patterns_tuple_length(self) -> None:
        """DEFAULT_BLOCK_PATTERNS has 11 entries."""
        assert len(DEFAULT_BLOCK_PATTERNS) == 11

    def test_dangerous_unicode_chars_non_empty(self) -> None:
        """DANGEROUS_UNICODE_PATH_CHARS is a non-empty string."""
        assert isinstance(DANGEROUS_UNICODE_PATH_CHARS, str)
        assert len(DANGEROUS_UNICODE_PATH_CHARS) > 0

    def test_sudo_prefixes_start_with_sudo(self) -> None:
        """SUDO_PASSWORD_PROMPT_FLAGS and SUDO_NO_PASSWORD_FLAG start with 'sudo'."""
        assert SUDO_PASSWORD_PROMPT_FLAGS.startswith("sudo")
        assert SUDO_NO_PASSWORD_FLAG.startswith("sudo")

    def test_http_status_is_503(self) -> None:
        """HTTP_SERVICE_UNAVAILABLE is 503."""
        assert HTTP_SERVICE_UNAVAILABLE == 503

    def test_app_name_and_version_format(self) -> None:
        """APP_NAME is a non-empty string, APP_VERSION looks like semver."""
        assert APP_NAME
        parts = APP_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)
