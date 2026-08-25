"""JSONL file log target — writes JSON lines to a file.

Implements the :class:`~lib.loggers.BaseLogger` interface.  Delegates
to :class:`~lib.loggers.FileLogger` internally so rotation logic
stays in one place.
"""

from __future__ import annotations

from lib.constants import (
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_MAX_LOG_OUTPUT,
)
from lib.loggers import BaseLogger, FileLogger


class JsonFileLogger(BaseLogger):
    """Log target that writes JSONL entries to a file.

    Functionally equivalent to :class:`~lib.loggers.FileLogger` but
    separated into its own module as part of the pluggable target
    architecture.  Delegates to ``FileLogger`` internally for rotation
    and truncation logic.
    """

    def __init__(
        self,
        filepath: str,
        log_level: str = "INFO",
        max_file_size_mb: int = DEFAULT_LOG_MAX_SIZE_MB,
        backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
        max_log_output: int | None = DEFAULT_MAX_LOG_OUTPUT,
        compress_rotated: bool = DEFAULT_COMPRESS_ROTATED,
    ) -> None:
        """Initialize the JSONL file logger.

        Args:
            filepath: Path to the log file.  The directory is created
                      if it does not exist.
            log_level: Minimum log level for this target.
            max_file_size_mb: Max file size in MiB before rotation.
            backup_count: Number of rotated backups to keep.
            max_log_output: Max characters for the output field.
            compress_rotated: Whether to gzip rotated backups.
        """
        from pathlib import Path

        from lib.sanitize import validate_log_path

        resolved = validate_log_path(filepath)
        log_dir = resolved.parent

        self._log_level = log_level
        self._delegate = FileLogger(
            log_dir=str(log_dir),
            max_file_size_mb=max_file_size_mb,
            backup_count=backup_count,
            max_log_output=max_log_output,
            compress_rotated=compress_rotated,
        )

    # ------------------------------------------------------------------
    # BaseLogger interface
    # ------------------------------------------------------------------

    def log(self, entry: dict) -> None:
        """Append *entry* as a JSON line.  Applies output truncation."""
        self._delegate.log(entry)

    def close(self) -> None:
        """Flush and close the file handle (delegates to FileLogger)."""
        self._delegate.close()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(
        self,
        max_log_output: int | None = None,
        compress_rotated: bool | None = None,
        log_level: str | None = None,
    ) -> None:
        """Update runtime settings.

        Args:
            max_log_output: Max characters for the output field.
            compress_rotated: Whether to gzip rotated backups.
            log_level: New minimum log level.  ``None`` keeps current.
        """
        if max_log_output is not None or compress_rotated is not None:
            kwargs: dict = {}
            if max_log_output is not None:
                kwargs["max_log_output"] = max_log_output
            if compress_rotated is not None:
                kwargs["compress_rotated"] = compress_rotated
            self._delegate.configure(**kwargs)
        if log_level is not None:
            self._log_level = log_level
