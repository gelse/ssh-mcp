"""Unit tests for lib/loggers.py — BaseLogger and FileLogger."""

import gzip
import json
import logging
import os
import threading
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from lib.loggers import BaseLogger, FileLogger


# ---------------------------------------------------------------------------
# BaseLogger contract tests
# ---------------------------------------------------------------------------


class TestBaseLogger:
    """Ensure BaseLogger cannot be instantiated directly and defines the contract."""

    def test_cannot_instantiate_abc(self):
        """BaseLogger is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseLogger()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_log(self):
        """A subclass missing log() raises TypeError."""

        class Incomplete(BaseLogger):
            def close(self) -> None:
                pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_close(self):
        """A subclass missing close() raises TypeError."""

        class Incomplete(BaseLogger):
            def log(self, entry: dict) -> None:
                pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_full_implementation_works(self):
        """A subclass implementing both methods instantiates without error."""

        class Complete(BaseLogger):
            def log(self, entry: dict) -> None:
                pass

            def close(self) -> None:
                pass

        instance = Complete()
        assert isinstance(instance, BaseLogger)


# ---------------------------------------------------------------------------
# FileLogger — JSONL writing & correctness
# ---------------------------------------------------------------------------


class TestFileLoggerBasics:
    """Tests for basic FileLogger write / read / JSONL correctness."""

    def test_writes_jsonl_line(self, tmp_path: Path):
        """A single log entry produces one line of valid JSON."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=10, backup_count=3)
        try:
            fl.log({"event": "test", "msg": "hello"})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event"] == "test"
        assert parsed["msg"] == "hello"

    def test_multiple_entries_produce_multiple_lines(self, tmp_path: Path):
        """Each log() call appends a new JSON line."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=10, backup_count=3)
        try:
            for i in range(5):
                fl.log({"n": i})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert len(lines) == 5
        values = [json.loads(line)["n"] for line in lines]
        assert values == list(range(5))

    def test_creates_log_directory(self, tmp_path: Path):
        """FileLogger creates the log directory if it doesn't exist."""
        log_dir = tmp_path / "nested" / "deep" / "logs"
        fl = FileLogger(str(log_dir))
        try:
            assert log_dir.is_dir()
            assert (log_dir / "ssh-mcp.log").exists()
        finally:
            fl.close()

    def test_non_serializable_values_use_default_str(self, tmp_path: Path):
        """Non-serializable objects like datetime are coerced via default=str."""
        from datetime import datetime

        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            fl.log({"ts": datetime(2026, 8, 7, 12, 0, 0)})
        finally:
            fl.close()

        parsed = json.loads((log_dir / "ssh-mcp.log").read_text().strip())
        assert "2026" in parsed["ts"]  # str representation

    def test_unicode_characters_preserved(self, tmp_path: Path):
        """Non-ASCII content is written correctly (ensure_ascii=False)."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            fl.log({"msg": "café 北京 🚀"})
        finally:
            fl.close()

        parsed = json.loads((log_dir / "ssh-mcp.log").read_text().strip())
        assert parsed["msg"] == "café 北京 🚀"


# ---------------------------------------------------------------------------
# FileLogger — rotation
# ---------------------------------------------------------------------------


class TestFileLoggerRotation:
    """Tests for size-based rotation logic."""

    def test_no_rotation_when_under_size_limit(self, tmp_path: Path):
        """No backup files are created when size stays under the limit."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=10, backup_count=3)
        try:
            for _ in range(100):
                fl.log({"x": "y"})
        finally:
            fl.close()

        assert not (log_dir / "ssh-mcp.log.1").exists()
        assert not (log_dir / "ssh-mcp.log.1.gz").exists()
        assert (log_dir / "ssh-mcp.log").exists()

    def test_rotation_creates_backup_when_exceeding_limit(self, tmp_path: Path):
        """When size exceeds max_file_size_mb, the active file rotates."""
        log_dir = tmp_path / "logs"
        # Use a tiny 1-byte limit to force rotation on every write
        fl = FileLogger(str(log_dir), max_file_size_mb=1, backup_count=3)
        try:
            # First write creates the file and triggers rotation because
            # even a small entry exceeds 1 MB? No — 1 MB is still large.
            # Force rotation by writing a payload that exceeds the limit.
            # Actually the limit is in MB, so 1 byte = 1/1M MB → won't trigger.
            # Write a large payload instead.
            big = "x" * (2 * 1024 * 1024)  # 2 MB
            fl.log({"data": big})
        finally:
            fl.close()

        backup = log_dir / "ssh-mcp.log.1.gz"
        assert backup.exists()
        assert not (log_dir / "ssh-mcp.log.1").exists()
        # The rotated backup must be a valid gzip stream.
        with gzip.open(backup, "rt", encoding="utf-8") as fh:
            fh.read()

    def test_backup_count_enforced(self, tmp_path: Path):
        """Only backup_count rotated files are kept; oldest is dropped."""
        log_dir = tmp_path / "logs"
        backup_count = 2
        fl = FileLogger(
            str(log_dir), max_file_size_mb=1, backup_count=backup_count
        )
        try:
            big = "x" * (2 * 1024 * 1024)  # 2 MB per entry
            for i in range(6):
                fl.log({"i": i, "data": big})
        finally:
            fl.close()

        # Only .log.1.gz and .log.2.gz should exist — no .log.3(.gz) or beyond
        for idx in range(1, backup_count + 1):
            assert (log_dir / f"ssh-mcp.log.{idx}.gz").exists(), \
                f"Expected ssh-mcp.log.{idx}.gz to exist"
            assert not (log_dir / f"ssh-mcp.log.{idx}").exists()
        assert not (log_dir / f"ssh-mcp.log.{backup_count + 1}").exists()
        assert not (log_dir / f"ssh-mcp.log.{backup_count + 1}.gz").exists()

    def test_active_file_always_exists_after_rotation(self, tmp_path: Path):
        """After rotation, ssh-mcp.log exists and is writable."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=1, backup_count=2)
        try:
            big = "y" * (2 * 1024 * 1024)
            for _ in range(4):
                fl.log({"data": big})
            # Write one more small entry to the active file
            fl.log({"final": True})
        finally:
            fl.close()

        active = log_dir / "ssh-mcp.log"
        assert active.exists()
        lines = active.read_text().strip().split("\n")
        last = json.loads(lines[-1])
        assert last["final"] is True

    def test_rotation_with_compression_disabled_keeps_plain_backup(
        self, tmp_path: Path
    ):
        """compress_rotated=False leaves the rotated backup uncompressed."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(
            str(log_dir),
            max_file_size_mb=1,
            backup_count=2,
            compress_rotated=False,
        )
        try:
            fl.log({"data": "x" * (2 * 1024 * 1024)})
        finally:
            fl.close()

        assert (log_dir / "ssh-mcp.log.1").exists()
        assert not (log_dir / "ssh-mcp.log.1.gz").exists()


class TestFileLoggerTruncation:
    """Tests for the max_log_output truncation behaviour."""

    def test_output_kept_when_within_limit(self, tmp_path: Path):
        """Short outputs pass through unchanged."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_log_output=100)
        try:
            fl.log({"output": "short"})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert json.loads(lines[0])["output"] == "short"

    def test_output_truncated_with_marker(self, tmp_path: Path):
        """Long outputs are cut at max_log_output with the marker appended."""
        log_dir = tmp_path / "logs"
        max_output = 20
        fl = FileLogger(str(log_dir), max_log_output=max_output)
        try:
            output = "x" * 500
            fl.log({"output": output})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        stored = json.loads(lines[0])["output"]
        marker = f"... [truncated, full output length: {len(output)} bytes]"
        assert stored == output[:max_output] + marker

    def test_metadata_fields_never_truncated(self, tmp_path: Path):
        """Only the output field is truncated; metadata stays intact."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_log_output=10)
        try:
            long_key = "k" * 200
            fl.log({"output": "x" * 100, long_key: "value"})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        stored = json.loads(lines[0])
        assert stored[long_key] == "value"

    def test_truncation_disabled_with_none(self, tmp_path: Path):
        """max_log_output=None keeps the full output."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_log_output=None)
        try:
            output = "y" * 5000
            fl.log({"output": output})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert json.loads(lines[0])["output"] == output

    def test_caller_dict_not_mutated(self, tmp_path: Path):
        """Truncation works on a copy; the caller's entry is untouched."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_log_output=10)
        try:
            entry = {"output": "z" * 100}
            fl.log(entry)
        finally:
            fl.close()

        assert entry["output"] == "z" * 100

    def test_configure_applies_runtime_settings(self, tmp_path: Path):
        """configure() updates truncation behaviour after construction."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_log_output=None)
        try:
            fl.configure(max_log_output=10)
            fl.log({"output": "a" * 100})
        finally:
            fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        stored = json.loads(lines[0])["output"]
        assert stored == "a" * 10 + "... [truncated, full output length: 100 bytes]"


# ---------------------------------------------------------------------------
# FileLogger — thread safety
# ---------------------------------------------------------------------------


class TestFileLoggerThreadSafety:
    """Verify concurrent writes produce complete, non-interleaved JSON lines."""

    def test_concurrent_writes_no_interleaving(self, tmp_path: Path):
        """Threads writing concurrently must not interleave JSON lines."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=10, backup_count=5)

        errors: list[Exception] = []

        def writer(thread_id: int, count: int):
            try:
                for i in range(count):
                    fl.log({"thread": thread_id, "seq": i})
            except Exception as exc:
                errors.append(exc)

        threads = []
        num_threads = 8
        writes_per_thread = 500
        for tid in range(num_threads):
            t = threading.Thread(target=writer, args=(tid, writes_per_thread))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        fl.close()

        # No exceptions during writes
        assert len(errors) == 0, f"Exceptions during concurrent writes: {errors}"

        # All lines must be valid JSON
        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert len(lines) == num_threads * writes_per_thread

        for line in lines:
            parsed = json.loads(line)
            assert "thread" in parsed
            assert "seq" in parsed

    def test_rotate_during_concurrent_writes_is_safe(self, tmp_path: Path):
        """Concurrent writes while rotation happens must not corrupt data."""
        log_dir = tmp_path / "logs"
        # Small limit to trigger rotation under concurrent load
        fl = FileLogger(str(log_dir), max_file_size_mb=1, backup_count=3)

        errors: list[Exception] = []

        def writer(thread_id: int, count: int):
            try:
                big = "z" * 1024  # 1 KB per entry
                for i in range(count):
                    fl.log({"thread": thread_id, "seq": i, "data": big})
            except Exception as exc:
                errors.append(exc)

        threads = []
        num_threads = 4
        writes_per_thread = 200
        for tid in range(num_threads):
            t = threading.Thread(
                target=writer, args=(tid, writes_per_thread)
            )
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        fl.close()

        assert len(errors) == 0, f"Exceptions during concurrent rotate: {errors}"

        # Collect all lines from active + (gzip) backup files
        all_lines: list[str] = []
        for entry in sorted(log_dir.iterdir()):
            if entry.suffix == ".log":
                all_lines.extend(entry.read_text().strip().split("\n"))
            elif entry.suffix == ".gz":
                with gzip.open(entry, "rt", encoding="utf-8") as fh:
                    content = fh.read().strip()
                    if content:
                        all_lines.extend(content.split("\n"))

        assert len(all_lines) == num_threads * writes_per_thread

        for line in all_lines:
            parsed = json.loads(line)
            assert "thread" in parsed
            assert "seq" in parsed


# ---------------------------------------------------------------------------
# FileLogger — close / cleanup
# ---------------------------------------------------------------------------


class TestFileLoggerClose:
    """Tests for close() behaviour."""

    def test_close_flushes_and_closes(self, tmp_path: Path):
        """After close(), the file exists and further writes raise ValueError."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        fl.log({"hello": "world"})
        fl.close()

        # File should exist with the entry
        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["hello"] == "world"

        # Writing after close should raise (fp is None → assertion fails)
        with pytest.raises(AssertionError):
            fl.log({"after": "close"})

    def test_close_is_idempotent(self, tmp_path: Path):
        """Calling close() multiple times does not raise."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        fl.close()
        fl.close()  # should not raise
        fl.close()  # still safe

    def test_writes_after_reopen(self, tmp_path: Path):
        """A new FileLogger on the same directory appends to existing log."""
        log_dir = tmp_path / "logs"
        fl1 = FileLogger(str(log_dir))
        fl1.log({"seq": 1})
        fl1.close()

        fl2 = FileLogger(str(log_dir))
        fl2.log({"seq": 2})
        fl2.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["seq"] == 1
        assert json.loads(lines[1])["seq"] == 2


# ---------------------------------------------------------------------------
# FileLogger — rotation edge cases
# ---------------------------------------------------------------------------


class TestFileLoggerEdgeCases:
    """Edge case tests for rotation and file handling."""

    def test_rotate_with_zero_backup_count_clamped_to_one(self, tmp_path: Path):
        """backup_count=0 is clamped to 1 so at least one backup is kept."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir), max_file_size_mb=1, backup_count=0)
        try:
            big = "x" * (2 * 1024 * 1024)
            fl.log({"data": big})
        finally:
            fl.close()

        # With backup_count=0 (clamped to 1), .log.1.gz should exist
        assert (log_dir / "ssh-mcp.log.1.gz").exists()
        assert not (log_dir / "ssh-mcp.log.1").exists()

    def test_rotate_when_file_does_not_exist_yet(self, tmp_path: Path):
        """Rotation logic handles missing active file gracefully (OSError)."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        # Delete the file behind the logger's back
        (log_dir / "ssh-mcp.log").unlink()
        # Writing should still work — _rotate_if_needed catches OSError
        fl.log({"recovered": True})
        fl.close()

        lines = (log_dir / "ssh-mcp.log").read_text().strip().split("\n")
        assert json.loads(lines[0])["recovered"] is True

    def test_default_file_naming(self, tmp_path: Path):
        """Active log is always named ssh-mcp.log."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            assert fl.ACTIVE_NAME == "ssh-mcp.log"
            assert (log_dir / "ssh-mcp.log").exists()
        finally:
            fl.close()


# ---------------------------------------------------------------------------
# FileLogger — graceful degradation on write failure
# ---------------------------------------------------------------------------


class TestFileLoggerGracefulDegradation:
    """On write failure, entries fall back to stderr via the logging module."""

    def test_write_failure_falls_back_to_stderr(self, tmp_path: Path, caplog):
        """A failing file write emits the entry via the fallback logger."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            # Simulate a disk failure on the file handle.
            with patch.object(fl, "_fp") as mock_fp:
                mock_fp.write.side_effect = OSError("disk full")
                with caplog.at_level(logging.WARNING):
                    fl.log({"event": "startup", "n": 1})

            assert fl.consecutive_failures == 1

            # The entry was emitted via the fallback logger.
            records = [r for r in caplog.records if r.name == "ssh_mcp.file_logger.fallback"]
            assert len(records) == 1
            assert records[0].levelno == logging.WARNING
            assert "disk full" in records[0].getMessage()
            assert "startup" in records[0].getMessage()
        finally:
            fl.close()

    def test_consecutive_failures_accumulate(self, tmp_path: Path, caplog):
        """Multiple failures increment the consecutive-failure counter."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            with patch.object(fl, "_fp") as mock_fp:
                mock_fp.write.side_effect = OSError("disk full")
                with caplog.at_level(logging.WARNING):
                    fl.log({"event": "a"})
                    fl.log({"event": "b"})
                    fl.log({"event": "c"})

            assert fl.consecutive_failures == 3
            records = [r for r in caplog.records if r.name == "ssh_mcp.file_logger.fallback"]
            assert len(records) == 3
            assert all("consecutive failures: %d" % i in r.getMessage() for i, r in
                       zip((1, 2, 3), records))
        finally:
            fl.close()

    def test_success_resets_failures_and_logs_recovery(self, tmp_path: Path, caplog):
        """A successful write resets the counter and logs a recovery event."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            with patch.object(fl, "_fp") as mock_fp:
                mock_fp.write.side_effect = OSError("disk full")
                with caplog.at_level(logging.INFO):
                    fl.log({"event": "a"})
                assert fl.consecutive_failures == 1

            # Now the real handle works again — recovery is logged.
            with caplog.at_level(logging.INFO):
                fl.log({"event": "b"})

            assert fl.consecutive_failures == 0
            assert (log_dir / "ssh-mcp.log").exists()
            recovery = [
                r for r in caplog.records
                if r.name == "ssh_mcp.file_logger.fallback"
                and r.levelno == logging.INFO
                and "resumed" in r.getMessage()
            ]
            assert len(recovery) == 1
        finally:
            fl.close()

    def test_value_error_also_falls_back(self, tmp_path: Path, caplog):
        """ValueError (e.g. closed stream) also triggers graceful fallback."""
        log_dir = tmp_path / "logs"
        fl = FileLogger(str(log_dir))
        try:
            with patch.object(fl, "_fp") as mock_fp:
                mock_fp.write.side_effect = ValueError("I/O operation on closed file")
                with caplog.at_level(logging.WARNING):
                    fl.log({"event": "startup"})

            assert fl.consecutive_failures == 1
        finally:
            fl.close()
