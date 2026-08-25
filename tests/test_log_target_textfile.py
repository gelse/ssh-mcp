"""Unit tests for lib/log_target_textfile.py — TextFileLogger."""

from __future__ import annotations

import gzip
import os
from pathlib import Path

import pytest

from lib.exceptions import ConfigValidationError
from lib.log_target_textfile import TextFileLogger
from lib.loggers import BaseLogger


class TestTextFileLoggerInterface:
    """Ensure TextFileLogger implements the full BaseLogger interface."""

    def test_is_subclass_of_base_logger(self):
        """TextFileLogger is a subclass of BaseLogger."""
        assert issubclass(TextFileLogger, BaseLogger)

    def test_instantiation(self, tmp_path: Path):
        """TextFileLogger can be instantiated with valid filepath."""
        filepath = str(tmp_path / "logs" / "test.log")
        logger = TextFileLogger(filepath)
        try:
            assert os.path.exists(filepath)
        finally:
            logger.close()

    def test_creates_parent_directories(self, tmp_path: Path):
        """TextFileLogger creates parent directories if needed."""
        filepath = str(tmp_path / "a" / "b" / "c" / "test.log")
        logger = TextFileLogger(filepath)
        try:
            assert os.path.exists(filepath)
        finally:
            logger.close()


class TestTextFileLoggerFormatting:
    """Tests for text format output to file."""

    def test_writes_text_line(self, tmp_path: Path):
        """log() writes a human-readable text line."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "ssh_execute_command",
                "message": "Command executed on server1",
            })
        finally:
            logger.close()

        content = Path(filepath).read_text().strip()
        assert "2025-01-15 10:30:00" in content
        assert "INFO" in content
        assert "ssh_execute_command" in content
        assert "Command executed on server1" in content

    def test_multiple_entries(self, tmp_path: Path):
        """Each log() call appends a new text line."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        try:
            for i in range(5):
                logger.log({
                    "timestamp": f"2025-01-15T10:00:0{i}Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"entry {i}",
                })
        finally:
            logger.close()

        lines = Path(filepath).read_text().strip().split("\n")
        assert len(lines) == 5
        for i, line in enumerate(lines):
            assert f"entry {i}" in line


class TestTextFileLoggerLevelFiltering:
    """Tests for log level filtering."""

    def test_filters_below_level(self, tmp_path: Path):
        """Entries below configured log level are dropped."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath, log_level="WARNING")
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test",
                "message": "dropped",
            })
        finally:
            logger.close()

        content = Path(filepath).read_text().strip()
        assert content == ""  # no entries written

    def test_emits_at_or_above_level(self, tmp_path: Path):
        """Entries at or above configured log level are emitted."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath, log_level="WARNING")
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "ERROR",
                "event": "test",
                "message": "should appear",
            })
        finally:
            logger.close()

        content = Path(filepath).read_text().strip()
        assert "should appear" in content


class TestTextFileLoggerRotation:
    """Tests for file rotation."""

    def test_rotation_when_exceeds_max_size(self, tmp_path: Path):
        """File rotates when it exceeds max_file_size_mb."""
        filepath = str(tmp_path / "test.log")
        # Use tiny max size to force rotation
        logger = TextFileLogger(
            filepath,
            max_file_size_mb=0,  # 0 bytes → rotation on every write
            backup_count=3,
            compress_rotated=False,
        )
        try:
            for i in range(5):
                logger.log({
                    "timestamp": "2025-01-15T10:30:00Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"entry {i}",
                })
        finally:
            logger.close()

        # Should have a backup file
        backup = Path(filepath + ".1")
        assert backup.exists()

    def test_rotation_with_gzip_compression(self, tmp_path: Path):
        """Rotated files are gzip-compressed when compress_rotated=True."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(
            filepath,
            max_file_size_mb=0,
            backup_count=3,
            compress_rotated=True,
        )
        try:
            for i in range(5):
                logger.log({
                    "timestamp": "2025-01-15T10:30:00Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"entry {i}",
                })
        finally:
            logger.close()

        gz_backup = Path(filepath + ".1.gz")
        assert gz_backup.exists()
        # Verify the gz file is valid gzip
        with gzip.open(str(gz_backup), "rt") as f:
            content = f.read()
            assert "entry" in content

    def test_respects_backup_count(self, tmp_path: Path):
        """Oldest backups are dropped when backup_count is exceeded."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(
            filepath,
            max_file_size_mb=0,
            backup_count=2,
            compress_rotated=False,
        )
        try:
            for i in range(10):
                logger.log({
                    "timestamp": "2025-01-15T10:30:00Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"entry {i}",
                })
        finally:
            logger.close()

        # Only .log.1 and .log.2 should exist (backup_count=2)
        assert Path(filepath + ".1").exists()
        assert Path(filepath + ".2").exists()
        assert not Path(filepath + ".3").exists()


class TestTextFileLoggerConfigure:
    """Tests for configure() method."""

    def test_configure_updates_log_level(self, tmp_path: Path):
        """configure() changes the minimum log level."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath, log_level="ERROR")
        try:
            # Before: WARNING is filtered
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "WARNING",
                "event": "test",
                "message": "dropped",
            })
            content = Path(filepath).read_text().strip()
            assert content == ""

            # Update level
            logger.configure(log_level="WARNING")
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "WARNING",
                "event": "test",
                "message": "now visible",
            })
        finally:
            logger.close()

        content = Path(filepath).read_text().strip()
        assert "now visible" in content

    def test_configure_updates_compress_rotated(self, tmp_path: Path):
        """configure() changes compress_rotated setting."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(
            filepath,
            max_file_size_mb=0,
            backup_count=2,
            compress_rotated=False,
        )
        try:
            logger.configure(compress_rotated=True)
            for i in range(5):
                logger.log({
                    "timestamp": "2025-01-15T10:30:00Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"entry {i}",
                })
        finally:
            logger.close()

        gz_backup = Path(filepath + ".1.gz")
        assert gz_backup.exists()


class TestTextFileLoggerClose:
    """Tests for close() method."""

    def test_close_flushes_and_closes(self, tmp_path: Path):
        """close() flushes and closes the file handle."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        logger.close()

        # Verify the logger's internal file handle is closed
        assert logger._fp is None

    def test_close_is_idempotent(self, tmp_path: Path):
        """close() can be called multiple times without error."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        logger.close()
        logger.close()  # should not raise


class TestTextFileLoggerPathValidation:
    """Tests for filepath validation."""

    def test_rejects_empty_path(self):
        """Empty filepath raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError):
            TextFileLogger("")

    def test_rejects_null_bytes(self):
        """Filepath with null bytes raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError):
            TextFileLogger("/tmp/test\x00.log")


class TestTextFileLoggerParseLevel:
    """Tests for _parse_level helper."""

    def test_parse_known_levels(self):
        """Known level strings map to correct integers."""
        assert TextFileLogger._parse_level("DEBUG") == 10
        assert TextFileLogger._parse_level("INFO") == 20
        assert TextFileLogger._parse_level("WARNING") == 30
        assert TextFileLogger._parse_level("ERROR") == 40
        assert TextFileLogger._parse_level("CRITICAL") == 50

    def test_parse_case_insensitive(self):
        """Level parsing is case-insensitive."""
        assert TextFileLogger._parse_level("info") == 20
        assert TextFileLogger._parse_level("Warning") == 30

    def test_parse_unknown_defaults_to_debug(self):
        """Unknown levels default to DEBUG (10)."""
        assert TextFileLogger._parse_level("UNKNOWN") == 10


class TestTextFileLoggerAdditional:
    """Additional tests for text format, compression, and concurrency."""

    def test_text_format_in_file(self, tmp_path: Path):
        """Written entry matches the human-readable text format."""
        import re

        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "ssh_execute_command",
                "message": "Hello world message",
            })
        finally:
            logger.close()

        content = Path(filepath).read_text().strip()
        # Full line matches: YYYY-MM-DD HH:MM:SS LEVEL event: message
        assert re.search(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO ssh_execute_command: Hello world message$",
            content,
        )
        # Assert specific substrings
        assert "2025-01-15 10:30:00" in content
        assert "INFO" in content
        assert "ssh_execute_command" in content
        assert "Hello world message" in content

    def test_gzip_compression(self, tmp_path: Path):
        """Rotated backup is valid gzip and contains expected text."""
        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(
            filepath,
            max_file_size_mb=0,
            backup_count=3,
            compress_rotated=True,
        )
        try:
            for i in range(5):
                logger.log({
                    "timestamp": f"2025-01-15T10:30:0{i}Z",
                    "log_level": "INFO",
                    "event": "test",
                    "message": f"gzip-entry-{i}",
                })
        finally:
            logger.close()

        gz_path = Path(filepath + ".1.gz")
        assert gz_path.exists()
        # Must be valid gzip
        with gzip.open(str(gz_path), "rt", encoding="utf-8") as f:
            content = f.read()
        assert "gzip-entry-" in content
        assert "test" in content

    def test_concurrent_writes(self, tmp_path: Path):
        """Multiple threads writing concurrently produce complete, non-interleaved lines."""
        import threading

        filepath = str(tmp_path / "test.log")
        logger = TextFileLogger(filepath)
        try:
            num_threads = 4
            writes_per_thread = 10
            threads = []

            def writer(thread_id: int):
                for j in range(writes_per_thread):
                    logger.log({
                        "timestamp": "2025-01-15T10:30:00Z",
                        "log_level": "INFO",
                        "event": "concurrent_test",
                        "message": f"thread-{thread_id}-entry-{j}",
                    })

            for tid in range(num_threads):
                t = threading.Thread(target=writer, args=(tid,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()
        finally:
            logger.close()

        lines = Path(filepath).read_text().strip().split("\n")
        # Every thread × writes_per_thread line must be present
        assert len(lines) == num_threads * writes_per_thread

        # Each line is a complete, non-interleaved entry
        expected = {
            f"thread-{tid}-entry-{j}"
            for tid in range(num_threads)
            for j in range(writes_per_thread)
        }
        found = set()
        for line in lines:
            # Each line must match the expected format — no partial writes
            assert line.startswith("2025-01-15 10:30:00 INFO concurrent_test: thread-")
            # Extract the message portion after the prefix
            msg = line.split("concurrent_test: ", 1)[1]
            found.add(msg)

        assert found == expected
