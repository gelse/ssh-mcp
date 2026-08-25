"""Stdout log target — writes human-readable text entries to stdout.

Implements the :class:`~lib.loggers.BaseLogger` interface so it can be
used as a pluggable log backend alongside :class:`~lib.loggers.FileLogger`.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime, timezone

from lib.constants import LOG_LEVELS
from lib.loggers import BaseLogger


class StdoutLogger(BaseLogger):
    """Log target that writes text-formatted entries to stdout.

    Each entry is written as a single human-readable line::

        YYYY-MM-DD HH:MM:SS LEVEL event: message

    Entries below the configured ``log_level`` are silently dropped.
    Writes are serialised with a lock so concurrent callers never
    interleave partial lines.
    """

    def __init__(self, log_level: str = "INFO") -> None:
        """Initialize with a minimum log level filter.

        Args:
            log_level: Minimum log level.  Entries below this level are
                       silently dropped.  Valid values: DEBUG, INFO,
                       WARNING, ERROR, CRITICAL.
        """
        self._log_level = self._parse_level(log_level)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # BaseLogger interface
    # ------------------------------------------------------------------

    def log(self, entry: dict) -> None:
        """Format *entry* as text and write to stdout.

        Format: ``YYYY-MM-DD HH:MM:SS LEVEL event: message``

        Respects ``log_level`` filtering.
        """
        level_name = str(entry.get("log_level", "INFO")).upper()
        if self._parse_level(level_name) < self._log_level:
            return
        line = self._format_entry(entry)
        with self._lock:
            print(line, file=sys.stdout, flush=True)

    def close(self) -> None:
        """No-op — stdout is not owned by this logger."""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, log_level: str | None = None) -> None:
        """Update the minimum log level at runtime.

        Args:
            log_level: New minimum level.  ``None`` leaves the current
                       value unchanged.
        """
        if log_level is not None:
            self._log_level = self._parse_level(log_level)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_level(level: str) -> int:
        """Convert a level name string to a logging level integer.

        Unknown names are treated as ``DEBUG`` (accept everything).
        """
        level_upper = level.upper()
        mapping = {
            "DEBUG": 10,
            "INFO": 20,
            "WARNING": 30,
            "ERROR": 40,
            "CRITICAL": 50,
        }
        return mapping.get(level_upper, 10)

    @staticmethod
    def _format_entry(entry: dict) -> str:
        """Format a structured entry dict as a single text line.

        Format: ``YYYY-MM-DD HH:MM:SS LEVEL event: message``

        Missing fields are filled with defaults.
        """
        ts_raw = entry.get("timestamp", "")
        if isinstance(ts_raw, str) and len(ts_raw) >= 19:
            # Strip timezone info for display if present (e.g. "Z" or "+00:00")
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

        return f"{ts_display} {level} {event}: {message}"
