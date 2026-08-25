"""Text-file log target — writes human-readable text entries to a file.

Implements the :class:`~lib.loggers.BaseLogger` interface.  Each log
entry is a single human-readable line.  The file rotates when it
exceeds ``max_file_size_mb``, keeping ``backup_count`` rotated backups.
Optionally compresses rotated files with gzip.
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from lib.constants import (
    BYTES_PER_MB,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_TEXT_LOG_FORMAT,
)
from lib.loggers import BaseLogger
from lib.sanitize import validate_log_path


class TextFileLogger(BaseLogger):
    """Log target that writes text-formatted entries to a file.

    Each log entry is a single human-readable line.  The file rotates
    when it exceeds *max_file_size_mb*, keeping *backup_count* rotated
    backups.  Optionally compresses rotated files with gzip.

    Format::

        YYYY-MM-DD HH:MM:SS LEVEL event: message

    Thread safety
    -------------
    All state is guarded by a single ``_lock``.
    """

    ACTIVE_NAME = "ssh-mcp.log"

    def __init__(
        self,
        filepath: str,
        log_level: str = "INFO",
        max_file_size_mb: int = DEFAULT_LOG_MAX_SIZE_MB,
        backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
        compress_rotated: bool = DEFAULT_COMPRESS_ROTATED,
    ) -> None:
        """Initialize the text-file logger.

        Args:
            filepath: Path to the log file.
            log_level: Minimum log level for this target.
            max_file_size_mb: Max file size in MiB before rotation.
            backup_count: Number of rotated backups to keep.
            compress_rotated: Whether to gzip rotated backups.
        """
        resolved = validate_log_path(filepath)
        self._filepath = resolved
        self._log_level = self._parse_level(log_level)
        self._max_bytes = max_file_size_mb * BYTES_PER_MB
        self._backup_count = max(backup_count, 1)
        self._compress_rotated = compress_rotated
        self._lock = threading.Lock()
        self._fp: io.TextIOWrapper | None = None
        self._consecutive_failures = 0

        self._filepath.parent.mkdir(parents=True, exist_ok=True)
        self._open()

    # ------------------------------------------------------------------
    # BaseLogger interface
    # ------------------------------------------------------------------

    def log(self, entry: dict) -> None:
        """Format *entry* as text, rotate if needed, append to file.

        Entries below the configured ``log_level`` are silently dropped.
        """
        level_name = str(entry.get("log_level", "INFO")).upper()
        if self._parse_level(level_name) < self._log_level:
            return

        line = self._format_entry(entry) + "\n"
        with self._lock:
            try:
                self._rotate_if_needed(len(line))
                assert self._fp is not None
                self._fp.write(line)
                self._fp.flush()
            except (OSError, ValueError):
                self._consecutive_failures += 1

    def close(self) -> None:
        """Flush and close the file handle."""
        with self._lock:
            if self._fp is not None:
                self._fp.flush()
                self._fp.close()
                self._fp = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(
        self,
        log_level: str | None = None,
        compress_rotated: bool | None = None,
    ) -> None:
        """Update runtime settings.

        Args:
            log_level: New minimum log level.  ``None`` keeps current.
            compress_rotated: Whether to gzip rotated backups.  ``None``
                              keeps current.
        """
        with self._lock:
            if log_level is not None:
                self._log_level = self._parse_level(log_level)
            if compress_rotated is not None:
                self._compress_rotated = compress_rotated

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_level(level: str) -> int:
        """Convert a level name string to a logging level integer."""
        mapping = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50,
        }
        return mapping.get(level.upper(), 10)

    @staticmethod
    def _format_entry(entry: dict) -> str:
        """Format a structured entry dict as a single text line."""
        ts_raw = entry.get("timestamp", "")
        if isinstance(ts_raw, str) and len(ts_raw) >= 19:
            # Replace 'T' separator with space for human-readable format
            ts_display = ts_raw[:19].replace("T", " ")
        elif isinstance(ts_raw, (int, float)):
            ts_display = datetime.fromtimestamp(
                float(ts_raw), tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_display = datetime.now(tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        level = str(entry.get("log_level", "INFO")).upper()
        event = str(entry.get("event", ""))
        message = str(entry.get("message", ""))

        return DEFAULT_TEXT_LOG_FORMAT.format(
            timestamp=ts_display,
            level=level,
            event=event,
            message=message,
        )

    def _open(self) -> None:
        """Open (or re-open) the active log file for appending."""
        if self._fp is not None:
            self._fp.close()
        self._fp = open(str(self._filepath), "a", encoding="utf-8")

    def _rotate_if_needed(self, pending_bytes: int) -> None:
        """Check file size and rotate if adding *pending_bytes* would exceed the cap."""
        try:
            current_size = os.path.getsize(self._filepath)
        except OSError:
            self._open()
            current_size = 0

        if current_size + pending_bytes <= self._max_bytes:
            return

        # Close the current handle before renaming
        if self._fp is not None:
            self._fp.close()
            self._fp = None

        # Drop the oldest backup
        oldest_plain = self._filepath.with_suffix(f".log.{self._backup_count}")
        oldest_gz = Path(str(oldest_plain) + ".gz")
        for oldest in (oldest_gz, oldest_plain):
            if oldest.exists():
                oldest.unlink()

        # Shift existing backups
        for idx in range(self._backup_count - 1, 0, -1):
            src_plain = self._filepath.with_suffix(f".log.{idx}")
            src_gz = Path(str(src_plain) + ".gz")
            src = src_gz if src_gz.exists() else src_plain
            if src.exists():
                dst_plain = self._filepath.with_suffix(f".log.{idx + 1}")
                dst = (
                    Path(str(dst_plain) + ".gz")
                    if str(src).endswith(".gz")
                    else dst_plain
                )
                src.rename(dst)

        # Rename current active file to .log.1
        backup = self._filepath.with_suffix(".log.1")
        self._filepath.rename(backup)

        # Optionally gzip the freshly rotated backup
        if self._compress_rotated:
            self._gzip_backup(backup)

        # Open a fresh active file
        self._open()

    def _gzip_backup(self, rotated_path: Path) -> None:
        """Compress *rotated_path* in place to ``rotated_path + ".gz"``."""
        try:
            with open(rotated_path, "rb") as f_in:
                with gzip.open(str(rotated_path) + ".gz", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(rotated_path)
        except OSError:
            pass
