"""Structured logging for the SSH MCP server.

Provides a pluggable logging backend using the strategy pattern:

    BaseLogger (ABC)
    └── FileLogger  (JSONL, thread-safe, size-based rotation)

Only ``FileLogger`` is implemented for now.  Additional backends
(Syslog, Graylog, …) can be added later by implementing ``BaseLogger``.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import shutil
import sys
import threading
from abc import ABC, abstractmethod
from pathlib import Path

from lib.constants import (
    ACTIVE_LOG_FILENAME,
    BYTES_PER_MB,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_MAX_LOG_OUTPUT,
)
from lib.sanitize import validate_log_path


# Fallback logger used for graceful degradation when file writes fail.
# Emits to stderr via the :mod:`logging` module; records still propagate to
# the root logger so they remain capturable (e.g. via caplog in tests).
_FALLBACK_LOGGER = logging.getLogger("ssh_mcp.file_logger.fallback")
if not _FALLBACK_LOGGER.handlers:
    _FALLBACK_LOGGER.addHandler(logging.StreamHandler(sys.stderr))
    # Only WARNING+ entries reach stderr; INFO records (e.g. recovery
    # events) still propagate to the root logger / caplog for capture.
    _FALLBACK_LOGGER.handlers[0].setLevel(logging.WARNING)
_FALLBACK_LOGGER.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseLogger(ABC):
    """Abstract interface for structured-log backends."""

    @abstractmethod
    def log(self, entry: dict) -> None:
        """Append a structured log entry.

        Args:
            entry: A dictionary that will be serialized as a single JSON
                   line.  Must contain at least ``"timestamp"`` and
                   ``"event"`` keys.
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Flush any pending writes and release resources."""
        ...


# ---------------------------------------------------------------------------
# FileLogger – JSONL file logger with size-based rotation
# ---------------------------------------------------------------------------


class FileLogger(BaseLogger):
    """JSONL file logger with size-based rotation.

    Writes one JSON object per line to an active log file.
    When the file exceeds *max_file_size_mb*, the current file is rotated
    (``.log`` → ``.log.1`` → ``.log.2`` → … up to *backup_count*) and a
    new empty file is started.

    Thread safety
    -------------
    All state is guarded by a single ``_lock``: log writes, rotation,
    the ``consecutive_failures`` counter, and ``close()``.  Readers of the
    counter and writers to the file may contend, but a line is never
    interleaved and a rotation never observes a partially-written line.
    ``_rotate_if_needed`` must be called while holding ``_lock``.
    """

    ACTIVE_NAME = ACTIVE_LOG_FILENAME

    def __init__(
        self,
        log_dir: str,
        max_file_size_mb: int = DEFAULT_LOG_MAX_SIZE_MB,
        backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
        max_log_output: int | None = DEFAULT_MAX_LOG_OUTPUT,
        compress_rotated: bool = DEFAULT_COMPRESS_ROTATED,
    ) -> None:
        """
        Args:
            log_dir: Directory where log files are written.
            max_file_size_mb: Maximum size in MiB before rotation.
            backup_count: Number of rotated backup files to keep.
            max_log_output: Maximum number of characters kept for the
                ``output`` field of each entry.  Longer outputs are truncated
                with a marker appended.  ``None`` disables truncation.
            compress_rotated: Whether rotated backup files are gzip-compressed.
        """
        self._log_dir = validate_log_path(log_dir)
        self._max_bytes = max_file_size_mb * BYTES_PER_MB
        self._backup_count = max(backup_count, 1)
        self._max_log_output = max_log_output
        self._compress_rotated = compress_rotated
        self._lock = threading.Lock()
        self._active_path = self._log_dir / self.ACTIVE_NAME
        self._fp: io.TextIOWrapper | None = None
        self._consecutive_failures = 0

        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._open()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, entry: dict) -> None:
        """Append *entry* as a JSON line.  Thread-safe.

        The ``output`` field is truncated at ``max_log_output`` characters,
        appending ``"... [truncated, full output length: N bytes]"`` when it
        was cut.  Metadata fields are never truncated.  The caller's dict is
        left untouched — truncation is applied to a copy.

        When the underlying file cannot be written (disk full, closed
        handle, …), the entry is emitted to stderr via the fallback logger
        instead of raising — graceful degradation.  Consecutive failures are
        tracked and a recovery event is logged once file writes resume.
        """
        if self._max_log_output is not None and isinstance(entry.get("output"), str):
            output = entry["output"]
            if len(output) > self._max_log_output:
                truncated = output[: self._max_log_output]
                truncated += (
                    f"... [truncated, full output length: {len(output)} bytes]"
                )
                entry = {**entry, "output": truncated}
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            try:
                self._rotate_if_needed(len(line))
                assert self._fp is not None
                self._fp.write(line)
                self._fp.flush()
            except (OSError, ValueError) as exc:
                # Graceful degradation: never lose the entry; emit to stderr.
                self._consecutive_failures += 1
                _FALLBACK_LOGGER.warning(
                    "FileLogger write to %s failed (%s); emitting to stderr "
                    "(consecutive failures: %d): %s",
                    self._active_path,
                    exc,
                    self._consecutive_failures,
                    line.rstrip("\n"),
                )
                return

            if self._consecutive_failures > 0:
                self._consecutive_failures = 0
                _FALLBACK_LOGGER.info(
                    "FileLogger file writes to %s resumed", self._active_path
                )

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive write failures since the last success."""
        with self._lock:
            return self._consecutive_failures

    def configure(
        self,
        max_log_output: int | None = DEFAULT_MAX_LOG_OUTPUT,
        compress_rotated: bool = DEFAULT_COMPRESS_ROTATED,
    ) -> None:
        """Apply runtime log settings (truncation + rotation compression).

        Called by :func:`server.create_app` once the validated config is
        available, so the active ``settings.max_log_output`` and
        ``settings.compress_rotated`` values take effect for subsequent
        entries and rotations.
        """
        with self._lock:
            self._max_log_output = max_log_output
            self._compress_rotated = compress_rotated

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        with self._lock:
            if self._fp is not None:
                self._fp.flush()
                self._fp.close()
                self._fp = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open (or re-open) the active log file for appending."""
        if self._fp is not None:
            self._fp.close()
        # pylint: disable=consider-using-with
        self._fp = open(str(self._active_path), "a", encoding="utf-8")

    def _rotate_if_needed(self, pending_bytes: int) -> None:
        """Check file size and rotate if adding *pending_bytes* would exceed the cap.

        Backups are shifted as ``.log.(N-1)`` → ``.log.N`` (preserving gzip
        state) and the freshly rotated file is compressed when
        ``compress_rotated`` is enabled.  Must be called while holding
        ``self._lock``.
        """
        try:
            current_size = os.path.getsize(self._active_path)
        except OSError:
            # File was deleted or is otherwise inaccessible — re-open now.
            self._open()
            current_size = 0

        if current_size + pending_bytes <= self._max_bytes:
            return

        # Close the current handle before renaming
        if self._fp is not None:
            self._fp.close()
            self._fp = None

        # Drop the oldest backup (plain or gzip-compressed)
        oldest_plain = self._active_path.with_suffix(f".log.{self._backup_count}")
        oldest_gz = Path(str(oldest_plain) + ".gz")
        for oldest in (oldest_gz, oldest_plain):
            if oldest.exists():
                oldest.unlink()

        # Shift existing backups: .log.(N-1) → .log.N, keeping each file's
        # compression state (a .log.N.gz stays compressed as .log.(N+1).gz).
        for idx in range(self._backup_count - 1, 0, -1):
            src_plain = self._active_path.with_suffix(f".log.{idx}")
            src_gz = Path(str(src_plain) + ".gz")
            src = src_gz if src_gz.exists() else src_plain
            if src.exists():
                dst_plain = self._active_path.with_suffix(f".log.{idx + 1}")
                dst = (
                    Path(str(dst_plain) + ".gz")
                    if str(src).endswith(".gz")
                    else dst_plain
                )
                src.rename(dst)

        # Rename current active file to .log.1
        backup = self._active_path.with_suffix(".log.1")
        self._active_path.rename(backup)

        # Optionally gzip the freshly rotated backup
        if self._compress_rotated:
            self._gzip_backup(backup)

        # Open a fresh active file
        self._open()

    def _gzip_backup(self, rotated_path: Path) -> None:
        """Compress *rotated_path* in place to ``rotated_path + ".gz"``.

        On failure the plain backup is kept so no log data is lost.
        """
        try:
            with open(rotated_path, "rb") as f_in:
                with gzip.open(str(rotated_path) + ".gz", "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(rotated_path)
        except OSError:
            _FALLBACK_LOGGER.warning(
                "FileLogger failed to gzip rotated backup %s; keeping plain file",
                rotated_path,
            )
