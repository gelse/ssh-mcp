"""Unit tests for lib/log_target_jsonfile.py — JsonFileLogger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lib.exceptions import ConfigValidationError
from lib.log_target_jsonfile import JsonFileLogger
from lib.loggers import BaseLogger, FileLogger


class TestJsonFileLoggerInterface:
    """Ensure JsonFileLogger implements the full BaseLogger interface."""

    def test_is_subclass_of_base_logger(self):
        """JsonFileLogger is a subclass of BaseLogger."""
        assert issubclass(JsonFileLogger, BaseLogger)

    def test_instantiation(self, tmp_path: Path):
        """JsonFileLogger can be instantiated with valid filepath."""
        filepath = str(tmp_path / "logs" / "test.log")
        logger = JsonFileLogger(filepath)
        try:
            assert logger._delegate is not None
        finally:
            logger.close()

    def test_creates_parent_directories(self, tmp_path: Path):
        """JsonFileLogger creates parent directories via FileLogger."""
        filepath = str(tmp_path / "a" / "b" / "test.log")
        logger = JsonFileLogger(filepath)
        try:
            assert logger._delegate._log_dir.exists()
        finally:
            logger.close()


class TestJsonFileLoggerDelegation:
    """Tests for delegation to FileLogger."""

    def test_delegates_log_to_file_logger(self, tmp_path: Path):
        """log() delegates to FileLogger, producing JSONL output."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath)
        try:
            logger.log({
                "event": "test_event",
                "message": "hello world",
            })
        finally:
            logger.close()

        # FileLogger writes to ssh-mcp.log in the parent directory
        log_dir = Path(filepath).parent
        log_file = log_dir / "ssh-mcp.log"
        assert log_file.exists()

        content = log_file.read_text().strip()
        parsed = json.loads(content)
        assert parsed["event"] == "test_event"
        assert parsed["message"] == "hello world"

    def test_output_truncation_via_delegate(self, tmp_path: Path):
        """Output field is truncated by the delegate FileLogger."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath, max_log_output=10)
        try:
            long_output = "x" * 100
            logger.log({
                "event": "test",
                "output": long_output,
            })
        finally:
            logger.close()

        log_dir = Path(filepath).parent
        log_file = log_dir / "ssh-mcp.log"
        content = log_file.read_text().strip()
        parsed = json.loads(content)
        assert len(parsed["output"]) < 100
        assert "truncated" in parsed["output"]

    def test_multiple_entries(self, tmp_path: Path):
        """Each log() call appends a new JSON line."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath)
        try:
            for i in range(3):
                logger.log({"event": "test", "n": i})
        finally:
            logger.close()

        log_dir = Path(filepath).parent
        log_file = log_dir / "ssh-mcp.log"
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 3


class TestJsonFileLoggerConfigure:
    """Tests for configure() method."""

    def test_configure_updates_max_log_output(self, tmp_path: Path):
        """configure(max_log_output=...) updates truncation in delegate."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath, max_log_output=100)
        try:
            logger.configure(max_log_output=5)
            long_output = "y" * 100
            logger.log({"event": "test", "output": long_output})
        finally:
            logger.close()

        log_dir = Path(filepath).parent
        log_file = log_dir / "ssh-mcp.log"
        parsed = json.loads(log_file.read_text().strip())
        assert len(parsed["output"]) < 100

    def test_configure_updates_compress_rotated(self, tmp_path: Path):
        """configure(compress_rotated=...) updates delegate setting."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(
            filepath,
            max_file_size_mb=0,
            backup_count=2,
            compress_rotated=False,
        )
        try:
            logger.configure(compress_rotated=True)
            for i in range(5):
                logger.log({"event": "test", "n": i})
        finally:
            logger.close()

        log_dir = Path(filepath).parent
        log_file = log_dir / "ssh-mcp.log"
        gz_backup = log_file.parent / (log_file.name + ".1.gz")
        assert gz_backup.exists()

    def test_configure_updates_log_level(self, tmp_path: Path):
        """configure(log_level=...) updates the stored log level."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath)
        try:
            logger.configure(log_level="DEBUG")
            assert logger._log_level == "DEBUG"
        finally:
            logger.close()

    def test_configure_none_values_keep_current(self, tmp_path: Path):
        """configure() with all None keeps current settings."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath, max_log_output=50)
        try:
            original_output = logger._delegate._max_log_output
            logger.configure(max_log_output=None, compress_rotated=None, log_level=None)
            assert logger._delegate._max_log_output == original_output
        finally:
            logger.close()


class TestJsonFileLoggerClose:
    """Tests for close() method."""

    def test_close_delegates_to_file_logger(self, tmp_path: Path):
        """close() delegates to FileLogger.close()."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath)
        logger.close()

        # Verify the delegate's file handle is closed
        assert logger._delegate._fp is None

    def test_close_is_idempotent(self, tmp_path: Path):
        """close() can be called multiple times without error."""
        filepath = str(tmp_path / "test.log")
        logger = JsonFileLogger(filepath)
        logger.close()
        logger.close()  # should not raise


class TestJsonFileLoggerPathValidation:
    """Tests for filepath validation."""

    def test_rejects_empty_path(self):
        """Empty filepath raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError):
            JsonFileLogger("")

    def test_rejects_null_bytes(self):
        """Filepath with null bytes raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError):
            JsonFileLogger("/tmp/test\x00.log")
