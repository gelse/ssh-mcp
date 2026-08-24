"""Minimal lib re-exports for the config-api Docker image.

This replaces the full lib/__init__.py to avoid importing heavy
dependencies (paramiko, prometheus_client, fastmcp, watchdog) that
the config-api does not need.

Only re-exports modules whose transitive deps are stdlib-only:
  lib.constants, lib.exceptions, lib.config_migration,
  lib.redos_protection, lib.secrets, lib.size_utils, lib.types, lib.config
"""

from lib.config import build_default_config, ConfigManager
from lib.config_migration import migrate_config
from lib.constants import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_CONFIG_FILENAME,
    LATEST_CONFIG_VERSION,
    RESTRICTED_FILE_MODE,
)
from lib.exceptions import (
    ConfigError,
    ConfigMigrationError,
    ConfigValidationError,
    MCPSSHError,
    SecretsError,
)
from lib.redos_protection import (
    check_redos_risk,
    compile_safe_pattern,
    safe_regex_search,
)
from lib.secrets import SecretsManager
from lib.size_utils import parse_size_bytes
from lib.types import (
    AllowedCommand,
    AllowedCommandsResult,
    SSHTarget,
)

__all__ = [
    "build_default_config",
    "ConfigManager",
    "migrate_config",
    "DEFAULT_CONFIG_DIR",
    "DEFAULT_CONFIG_FILENAME",
    "LATEST_CONFIG_VERSION",
    "RESTRICTED_FILE_MODE",
    "ConfigError",
    "ConfigMigrationError",
    "ConfigValidationError",
    "MCPSSHError",
    "SecretsError",
    "check_redos_risk",
    "compile_safe_pattern",
    "safe_regex_search",
    "SecretsManager",
    "parse_size_bytes",
    "AllowedCommand",
    "AllowedCommandsResult",
    "SSHTarget",
]
