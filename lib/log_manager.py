"""Logging manager — builds and manages log targets from configuration.

Responsible for:
- Parsing ``settings.logging.log_targets`` config into target instances
- Supporting backward-compatible fallback (old flat settings)
- Handling ``MCP_SSH_LOG_LEVEL`` env var override
- Providing the composite logger for injection into the application
"""

from __future__ import annotations

import os

from lib.constants import (
    ACTIVE_LOG_FILENAME,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_MAX_LOG_OUTPUT,
    LOG_TARGET_JSONFILE,
    LOG_TARGET_STDOUT,
    LOG_TARGET_TEXTFILE,
    MCP_SSH_LOG_LEVEL,
    SUPPORTED_LOG_TARGETS,
)
from lib.exceptions import ConfigValidationError
from lib.log_composite import CompositeLogger
from lib.log_target_jsonfile import JsonFileLogger
from lib.log_target_stdout import StdoutLogger
from lib.log_target_textfile import TextFileLogger
from lib.loggers import BaseLogger


class LoggingManager:
    """Builds and manages the logging subsystem from configuration.

    Responsibilities:
    - Parse settings.logging.log_targets config into target instances
    - Support backward-compatible fallback (old flat settings)
    - Handle MCP_SSH_LOG_LEVEL env var override
    - Provide the composite logger for injection into the app
    """

    def __init__(
        self,
        config_settings: dict,
        log_dir: str = DEFAULT_LOG_DIR,
        log_level_env_override: str | None = None,
    ) -> None:
        """Build log targets from config settings.

        Args:
            config_settings: The validated settings dict from ConfigManager.
            log_dir: Default log directory (from CLI arg / MCP_SSH_LOG_DIR).
            log_level_env_override: If set, overrides settings.log_level
                                    for the default target level.  Only
                                    affects the config-file default level,
                                    not per-target overrides.
        """
        # Determine effective default level
        default_level = log_level_env_override or DEFAULT_LOG_LEVEL

        # Build targets
        targets = self._build_targets_from_config(
            config_settings, log_dir, default_level
        )

        self._composite = CompositeLogger(targets)

    @property
    def logger(self) -> CompositeLogger:
        """Return the composite logger for injection into the app."""
        return self._composite

    def close(self) -> None:
        """Close all log targets."""
        self._composite.close()

    def configure(
        self,
        max_log_output: int | None = None,
        compress_rotated: bool | None = None,
    ) -> None:
        """Update runtime settings on all targets."""
        self._composite.configure(
            max_log_output=max_log_output,
            compress_rotated=compress_rotated,
        )

    def _build_targets_from_config(
        self,
        settings: dict,
        log_dir: str,
        default_level: str,
    ) -> list[BaseLogger]:
        """Parse log_targets array and instantiate driver objects.

        Args:
            settings: The settings dict (may contain 'logging' key).
            log_dir: Default log directory for relative file paths.
            default_level: Effective default log level (after env override).

        Returns:
            List of instantiated BaseLogger targets.
        """
        logging_config = settings.get("logging")
        if logging_config is not None:
            return self._parse_log_targets(logging_config, log_dir, default_level)
        return self._build_legacy_target(settings, log_dir, default_level)

    def _parse_log_targets(
        self,
        logging_config: dict,
        log_dir: str,
        default_level: str,
    ) -> list[BaseLogger]:
        """Parse the new-style logging.log_targets config array.

        Args:
            logging_config: The ``logging`` section from settings.
            log_dir: Default log directory for relative file paths.
            default_level: Effective default log level.

        Returns:
            List of instantiated BaseLogger targets.

        Raises:
            ConfigValidationError: On unknown target type or missing
                required fields.
        """
        log_targets = logging_config.get("log_targets", [])
        if not log_targets:
            # No targets configured — fall back to legacy
            return self._build_legacy_target({}, log_dir, default_level)

        targets: list[BaseLogger] = []
        for entry in log_targets:
            target_type = entry.get("target", "")
            if target_type not in SUPPORTED_LOG_TARGETS:
                raise ConfigValidationError(
                    f"Unknown log target type: {target_type!r}. "
                    f"Supported types: {', '.join(SUPPORTED_LOG_TARGETS)}"
                )

            # Per-target level takes precedence over default
            level = entry.get("log_level", default_level)

            if target_type == LOG_TARGET_STDOUT:
                targets.append(StdoutLogger(log_level=level))
            elif target_type == LOG_TARGET_JSONFILE:
                filepath = entry.get("filepath")
                if not filepath:
                    raise ConfigValidationError(
                        "jsonfile target requires a 'filepath' field"
                    )
                resolved = self._resolve_filepath(filepath, log_dir)
                targets.append(
                    JsonFileLogger(
                        filepath=resolved,
                        log_level=level,
                        max_log_output=entry.get(
                            "max_log_output", DEFAULT_MAX_LOG_OUTPUT
                        ),
                        compress_rotated=entry.get(
                            "compress_rotated", DEFAULT_COMPRESS_ROTATED
                        ),
                    )
                )
            elif target_type == LOG_TARGET_TEXTFILE:
                filepath = entry.get("filepath")
                if not filepath:
                    raise ConfigValidationError(
                        "file target requires a 'filepath' field"
                    )
                resolved = self._resolve_filepath(filepath, log_dir)
                targets.append(
                    TextFileLogger(
                        filepath=resolved,
                        log_level=level,
                        compress_rotated=entry.get(
                            "compress_rotated", DEFAULT_COMPRESS_ROTATED
                        ),
                    )
                )

        return targets

    def _build_legacy_target(
        self,
        settings: dict,
        log_dir: str,
        default_level: str,
    ) -> list[BaseLogger]:
        """Build targets from old-style flat settings for backward compat.

        When settings.logging is absent, infer targets from the legacy
        settings (log_level, max_log_output, compress_rotated) and the
        default log directory.  Creates a single jsonfile target.

        Args:
            settings: The settings dict (may contain legacy keys).
            log_dir: Default log directory.
            default_level: Effective default log level.

        Returns:
            List containing a single JsonFileLogger.
        """
        level = settings.get("log_level", default_level)
        max_output = settings.get("max_log_output", DEFAULT_MAX_LOG_OUTPUT)
        compress = settings.get("compress_rotated", DEFAULT_COMPRESS_ROTATED)

        filepath = os.path.join(log_dir, ACTIVE_LOG_FILENAME)
        return [
            JsonFileLogger(
                filepath=filepath,
                log_level=level,
                max_log_output=max_output,
                compress_rotated=compress,
            )
        ]

    @staticmethod
    def _resolve_filepath(filepath: str, log_dir: str) -> str:
        """Resolve a filepath — relative paths are resolved against log_dir.

        Args:
            filepath: The configured filepath (relative or absolute).
            log_dir: Default log directory for relative paths.

        Returns:
            Absolute filepath string.
        """
        if os.path.isabs(filepath):
            return filepath
        return os.path.join(log_dir, filepath)
