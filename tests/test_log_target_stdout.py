"""Unit tests for lib/log_target_stdout.py — StdoutLogger."""

from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from lib.log_target_stdout import StdoutLogger
from lib.loggers import BaseLogger


class TestStdoutLoggerInterface:
    """Ensure StdoutLogger implements the full BaseLogger interface."""

    def test_is_subclass_of_base_logger(self):
        """StdoutLogger is a subclass of BaseLogger."""
        assert issubclass(StdoutLogger, BaseLogger)

    def test_instantiation(self):
        """StdoutLogger can be instantiated with defaults."""
        logger = StdoutLogger()
        logger.close()

    def test_instantiation_with_custom_level(self):
        """StdoutLogger accepts a custom log_level."""
        logger = StdoutLogger(log_level="DEBUG")
        logger.close()


class TestStdoutLoggerFormatting:
    """Tests for text format output."""

    def test_format_entry_with_all_fields(self):
        """_format_entry produces the expected text format."""
        entry = {
            "timestamp": "2025-01-15T10:30:00Z",
            "log_level": "INFO",
            "event": "ssh_execute_command",
            "message": "Command executed on server1",
        }
        result = StdoutLogger._format_entry(entry)
        assert result == "2025-01-15 10:30:00 INFO ssh_execute_command: Command executed on server1"

    def test_format_entry_missing_fields(self):
        """_format_entry fills missing fields with defaults."""
        result = StdoutLogger._format_entry({})
        # Should produce a line with defaults
        assert "INFO" in result
        assert ": " in result

    def test_format_entry_timestamp_truncation(self):
        """Timestamps longer than 19 chars are truncated."""
        entry = {
            "timestamp": "2025-01-15T10:30:00.123456Z",
            "log_level": "WARNING",
            "event": "test_event",
            "message": "test message",
        }
        result = StdoutLogger._format_entry(entry)
        assert "2025-01-15 10:30:00 WARNING" in result

    def test_format_entry_numeric_timestamp(self):
        """Numeric timestamps are converted to human-readable format."""
        entry = {
            "timestamp": 1705312200,
            "log_level": "ERROR",
            "event": "test_event",
            "message": "test message",
        }
        result = StdoutLogger._format_entry(entry)
        assert "ERROR" in result
        assert "test_event" in result


class TestStdoutLoggerLogMethod:
    """Tests for the log() method."""

    def test_log_writes_to_stdout(self, capsys):
        """log() writes a formatted line to stdout."""
        logger = StdoutLogger()
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test_event",
                "message": "hello world",
            })
            captured = capsys.readouterr()
            assert "hello world" in captured.out
            assert "INFO" in captured.out
        finally:
            logger.close()

    def test_log_level_filtering_below_level(self, capsys):
        """Entries below the configured log level are dropped."""
        logger = StdoutLogger(log_level="WARNING")
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test_event",
                "message": "should be dropped",
            })
            captured = capsys.readouterr()
            assert "should be dropped" not in captured.out
        finally:
            logger.close()

    def test_log_level_filtering_at_level(self, capsys):
        """Entries at or above the configured log level are emitted."""
        logger = StdoutLogger(log_level="WARNING")
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "WARNING",
                "event": "test_event",
                "message": "should appear",
            })
            captured = capsys.readouterr()
            assert "should appear" in captured.out
        finally:
            logger.close()

    def test_log_level_allows_above(self, capsys):
        """Entries above the configured log level are emitted."""
        logger = StdoutLogger(log_level="WARNING")
        try:
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "ERROR",
                "event": "test_event",
                "message": "error message",
            })
            captured = capsys.readouterr()
            assert "error message" in captured.out
        finally:
            logger.close()


class TestStdoutLoggerConfigure:
    """Tests for configure() method."""

    def test_configure_updates_log_level(self, capsys):
        """configure() changes the minimum log level."""
        logger = StdoutLogger(log_level="WARNING")
        try:
            # Before: INFO is filtered
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test",
                "message": "dropped",
            })
            captured = capsys.readouterr()
            assert "dropped" not in captured.out

            # Update level
            logger.configure(log_level="DEBUG")
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test",
                "message": "now visible",
            })
            captured = capsys.readouterr()
            assert "now visible" in captured.out
        finally:
            logger.close()

    def test_configure_none_keeps_current(self, capsys):
        """configure(log_level=None) leaves the current level unchanged."""
        logger = StdoutLogger(log_level="ERROR")
        try:
            logger.configure(log_level=None)
            logger.log({
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "WARNING",
                "event": "test",
                "message": "still dropped",
            })
            captured = capsys.readouterr()
            assert "still dropped" not in captured.out
        finally:
            logger.close()


class TestStdoutLoggerClose:
    """Tests for close() method."""

    def test_close_is_noop(self):
        """close() does not raise and is idempotent."""
        logger = StdoutLogger()
        logger.close()
        logger.close()  # should not raise


class TestStdoutLoggerParseLevel:
    """Tests for _parse_level helper."""

    def test_parse_known_levels(self):
        """Known level strings map to correct integers."""
        assert StdoutLogger._parse_level("DEBUG") == 10
        assert StdoutLogger._parse_level("INFO") == 20
        assert StdoutLogger._parse_level("WARNING") == 30
        assert StdoutLogger._parse_level("ERROR") == 40
        assert StdoutLogger._parse_level("CRITICAL") == 50

    def test_parse_case_insensitive(self):
        """Level parsing is case-insensitive."""
        assert StdoutLogger._parse_level("info") == 20
        assert StdoutLogger._parse_level("Warning") == 30

    def test_parse_unknown_defaults_to_debug(self):
        """Unknown levels default to DEBUG (10)."""
        assert StdoutLogger._parse_level("UNKNOWN") == 10


class TestStdoutLoggerConcurrency:
    """Tests for thread safety."""

    def test_concurrent_writes(self, capsys):
        """Concurrent log() calls produce non-interleaved lines."""
        logger = StdoutLogger()
        try:
            entry = {
                "timestamp": "2025-01-15T10:30:00Z",
                "log_level": "INFO",
                "event": "test",
                "message": "x",
            }

            def write_entries():
                for _ in range(10):
                    logger.log(entry)

            threads = [threading.Thread(target=write_entries) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            captured = capsys.readouterr()
            lines = [line for line in captured.out.strip().split("\n") if line]
            assert len(lines) == 40
        finally:
            logger.close()
