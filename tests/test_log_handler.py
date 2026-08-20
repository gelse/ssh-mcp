"""Unit tests for lib/log_handler — JSONLHandler."""

from __future__ import annotations

import datetime
import logging
from unittest.mock import MagicMock, patch

import pytest

from lib.constants import LOG_FORMAT_VERSION
from lib.log_handler import JSONLHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class RecordingFileLogger:
    """Duck-typed BaseLogger that captures log entries."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, entry: dict) -> None:
        self.entries.append(entry)

    def close(self) -> None:
        pass


def _make_record(
    name: str = "test_logger",
    level: int = logging.INFO,
    msg: str = "hello %s",
    args: tuple = ("world",),
    extra: dict | None = None,
    created: float | None = None,
) -> logging.LogRecord:
    """Build a LogRecord with known attributes for testing."""
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname="test_module.py",
        lineno=42,
        msg=msg,
        args=args,
        exc_info=None,
    )
    if extra:
        for k, v in extra.items():
            setattr(record, k, v)
    if created is not None:
        record.created = created
    return record


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildEntry:
    """Tests for JSONLHandler._build_entry static method."""

    def test_entry_has_all_expected_keys(self) -> None:
        """Built entry contains all 10 expected keys."""
        record = _make_record()
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        expected_keys = {
            "timestamp",
            "event",
            "level",
            "logger_name",
            "module",
            "funcName",
            "message",
            "request_id",
            "log_level",
            "log_format_version",
        }
        assert set(entry.keys()) == expected_keys

    def test_event_falls_back_to_logger_name(self) -> None:
        """Without extra event, the record name is used as the event."""
        record = _make_record(name="uvicorn.access")
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["event"] == "uvicorn.access"

    def test_event_from_extra(self) -> None:
        """extra={'event': 'custom'} overrides the logger name."""
        record = _make_record(name="stdlib", extra={"event": "custom_event"})
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["event"] == "custom_event"

    @pytest.mark.parametrize(
        "bad_event",
        [42, [], True, None],
        ids=["int", "list", "bool", "None"],
    )
    def test_non_string_event_falls_back(self, bad_event: object) -> None:
        """Non-string or empty event extra falls back to record.name."""
        record = _make_record(name="fallback_logger", extra={"event": bad_event})
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["event"] == "fallback_logger"

    def test_empty_string_event_falls_back(self) -> None:
        """An empty-string event extra falls back to record.name."""
        record = _make_record(name="fallback_logger", extra={"event": ""})
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["event"] == "fallback_logger"

    def test_timestamp_is_iso8601_utc(self) -> None:
        """Timestamp is a valid ISO 8601 string with UTC offset."""
        fixed_ts = 1700000000.0
        record = _make_record(created=fixed_ts)
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        ts = entry["timestamp"]
        # Should parse as ISO 8601
        dt = datetime.datetime.fromisoformat(ts)
        assert dt.tzinfo == datetime.timezone.utc

    def test_log_format_version_matches_constant(self) -> None:
        """log_format_version equals the module-level constant."""
        record = _make_record()
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["log_format_version"] == LOG_FORMAT_VERSION

    def test_request_id_populated(self) -> None:
        """request_id is the value returned by get_request_id()."""
        record = _make_record()
        with patch("lib.log_handler.get_request_id", return_value="test-id-xyz"):
            entry = JSONLHandler._build_entry(record)
        assert entry["request_id"] == "test-id-xyz"

    def test_level_matches_record_level(self) -> None:
        """level and log_level match the record's levelname."""
        record = _make_record(level=logging.WARNING)
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["level"] == "WARNING"
        assert entry["log_level"] == "WARNING"

    def test_message_formatting(self) -> None:
        """message field contains the fully formatted message."""
        record = _make_record(msg="count=%d", args=(42,))
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            entry = JSONLHandler._build_entry(record)
        assert entry["message"] == "count=42"


class TestEmit:
    """Tests for JSONLHandler.emit method."""

    def test_normal_record_forwarded_to_file_logger(self) -> None:
        """A normal record is converted and forwarded to file_logger.log()."""
        fl = RecordingFileLogger()
        handler = JSONLHandler(fl)
        record = _make_record(name="mylogger", level=logging.INFO)
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            handler.emit(record)
        assert len(fl.entries) == 1
        entry = fl.entries[0]
        assert entry["event"] == "mylogger"
        assert entry["level"] == "INFO"

    @pytest.mark.parametrize(
        "fallback_name",
        [
            "ssh_mcp.file_logger",
            "ssh_mcp.file_logger.graceful",
            "ssh_mcp.file_logger.anything",
        ],
        ids=["exact", "with-dot-suffix", "with-another-suffix"],
    )
    def test_fallback_logger_records_skipped(self, fallback_name: str) -> None:
        """Records from the fallback logger prefix are silently skipped."""
        fl = RecordingFileLogger()
        handler = JSONLHandler(fl)
        record = _make_record(name=fallback_name)
        handler.emit(record)
        assert len(fl.entries) == 0

    def test_file_logger_exception_does_not_propagate(self) -> None:
        """If file_logger.log() raises, emit() returns without exception."""
        fl = RecordingFileLogger()
        fl.log = MagicMock(side_effect=OSError("disk full"))
        handler = JSONLHandler(fl)
        record = _make_record()
        # handleError is called — patch it to avoid stderr noise
        handler.handleError = MagicMock()
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            handler.emit(record)
        handler.handleError.assert_called_once_with(record)

    def test_emit_does_not_mutate_record(self) -> None:
        """emit() must not modify the original LogRecord."""
        fl = RecordingFileLogger()
        handler = JSONLHandler(fl)
        record = _make_record(name="mutability_test")
        original_name = record.name
        original_level = record.levelno
        with patch("lib.log_handler.get_request_id", return_value="req-1"):
            handler.emit(record)
        assert record.name == original_name
        assert record.levelno == original_level
