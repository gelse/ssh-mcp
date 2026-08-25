"""Unit tests for lib/log_composite.py — CompositeLogger."""

from __future__ import annotations

import sys
from io import StringIO

import pytest

from lib.log_composite import CompositeLogger
from lib.loggers import BaseLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class StubLogger(BaseLogger):
    """Minimal BaseLogger stub that records calls."""

    def __init__(self, name: str = "stub") -> None:
        self.name = name
        self.log_calls: list[dict] = []
        self.close_calls: int = 0
        self.configure_calls: list[dict] = []

    def log(self, entry: dict) -> None:
        self.log_calls.append(entry)

    def close(self) -> None:
        self.close_calls += 1

    def configure(
        self,
        max_log_output: int | None = None,
        compress_rotated: bool | None = None,
    ) -> None:
        self.configure_calls.append(
            {
                "max_log_output": max_log_output,
                "compress_rotated": compress_rotated,
            }
        )


class FailingLogger(BaseLogger):
    """A BaseLogger whose log() raises an exception."""

    def __init__(
        self,
        exc: Exception | None = None,
        close_exc: Exception | None = None,
    ) -> None:
        self._exc = exc or RuntimeError("target failure")
        self._close_exc = close_exc
        self.close_called = False

    def log(self, entry: dict) -> None:
        raise self._exc

    def close(self) -> None:
        if self._close_exc is not None:
            raise self._close_exc
        self.close_called = True


class NoConfigureLogger(BaseLogger):
    """A BaseLogger that does NOT have a configure() method."""

    def log(self, entry: dict) -> None:
        pass

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCompositeLoggerLog:
    """Tests for CompositeLogger.log() delegation."""

    def test_delegates_log_to_all_targets(self):
        """log() forwards the entry to every child target."""
        t1 = StubLogger("t1")
        t2 = StubLogger("t2")
        composite = CompositeLogger([t1, t2])

        entry = {"event": "test", "message": "hello"}
        composite.log(entry)

        assert len(t1.log_calls) == 1
        assert t1.log_calls[0] is entry
        assert len(t2.log_calls) == 1
        assert t2.log_calls[0] is entry

    def test_entry_dict_not_modified(self):
        """The original entry dict is not mutated by the composite."""
        t1 = StubLogger()
        composite = CompositeLogger([t1])

        entry = {"event": "test"}
        composite.log(entry)

        # The same object reference is passed through
        assert t1.log_calls[0] is entry

    def test_handles_target_exception_gracefully(self):
        """Other targets still receive the entry when one target raises."""
        failing = FailingLogger(RuntimeError("boom"))
        good = StubLogger("good")
        composite = CompositeLogger([failing, good])

        entry = {"event": "test"}
        composite.log(entry)

        # The good target still received the entry
        assert len(good.log_calls) == 1
        assert good.log_calls[0] is entry

    def test_exception_emitted_to_stderr(self, capsys):
        """Target exceptions are printed to stderr as fallback."""
        failing = FailingLogger(RuntimeError("oops"))
        composite = CompositeLogger([failing])

        composite.log({"event": "test"})

        captured = capsys.readouterr()
        assert "CompositeLogger" in captured.err
        assert "RuntimeError" in captured.err

    def test_multiple_failures_all_others_called(self):
        """Multiple failing targets don't prevent remaining targets."""
        f1 = FailingLogger(RuntimeError("a"))
        f2 = FailingLogger(RuntimeError("b"))
        good = StubLogger("good")
        composite = CompositeLogger([f1, f2, good])

        composite.log({"event": "test"})

        assert len(good.log_calls) == 1


class TestCompositeLoggerClose:
    """Tests for CompositeLogger.close() in reverse order."""

    def test_close_calls_all_targets(self):
        """close() is called on every child target."""
        t1 = StubLogger("t1")
        t2 = StubLogger("t2")
        composite = CompositeLogger([t1, t2])

        composite.close()

        assert t1.close_calls == 1
        assert t2.close_calls == 1

    def test_close_reverse_order(self):
        """Targets are closed in reverse creation order."""
        close_order: list[str] = []

        class RecordingLogger(BaseLogger):
            def __init__(self, name: str) -> None:
                self._name = name

            def log(self, entry: dict) -> None:
                pass

            def close(self) -> None:
                close_order.append(self._name)

        t1 = RecordingLogger("first")
        t2 = RecordingLogger("second")
        t3 = RecordingLogger("third")
        composite = CompositeLogger([t1, t2, t3])

        composite.close()

        assert close_order == ["third", "second", "first"]

    def test_close_exception_does_not_block_others(self):
        """An exception in one target's close() doesn't prevent others."""
        failing = FailingLogger(RuntimeError("close-fail"))
        good = StubLogger("good")
        composite = CompositeLogger([failing, good])

        composite.close()

        assert good.close_calls == 1

    def test_close_exception_emitted_to_stderr(self, capsys):
        """close() exceptions are printed to stderr."""
        failing = FailingLogger(
            close_exc=RuntimeError("close-err"),
        )
        composite = CompositeLogger([failing])

        composite.close()

        captured = capsys.readouterr()
        assert "close()" in captured.err


class TestCompositeLoggerConfigure:
    """Tests for CompositeLogger.configure() forwarding."""

    def test_configure_forwards_to_all_targets(self):
        """configure() is called on every child target that supports it."""
        t1 = StubLogger("t1")
        t2 = StubLogger("t2")
        composite = CompositeLogger([t1, t2])

        composite.configure(max_log_output=100, compress_rotated=True)

        assert len(t1.configure_calls) == 1
        assert t1.configure_calls[0] == {
            "max_log_output": 100,
            "compress_rotated": True,
        }
        assert len(t2.configure_calls) == 1

    def test_configure_skips_targets_without_method(self):
        """Targets without configure() are silently skipped."""
        no_configure = NoConfigureLogger()
        stub = StubLogger("stub")
        composite = CompositeLogger([no_configure, stub])

        composite.configure(max_log_output=50)

        assert len(stub.configure_calls) == 1
        assert stub.configure_calls[0]["max_log_output"] == 50

    def test_configure_exception_does_not_block_others(self):
        """A configure() failure in one target doesn't prevent others."""
        # Use a stub that has configure() but raises
        class ConfigureFailingLogger(BaseLogger):
            def log(self, entry: dict) -> None:
                pass

            def close(self) -> None:
                pass

            def configure(self, **kwargs: object) -> None:
                raise RuntimeError("config fail")

        failing_target = ConfigureFailingLogger()
        good = StubLogger("good")
        composite = CompositeLogger([failing_target, good])

        # Should not raise
        composite.configure(max_log_output=10)

        assert len(good.configure_calls) == 1


class TestCompositeLoggerEmpty:
    """Tests for CompositeLogger with an empty targets list."""

    def test_empty_targets_log_noop(self):
        """log() on an empty composite is a no-op."""
        composite = CompositeLogger([])
        # Should not raise
        composite.log({"event": "test"})

    def test_empty_targets_close_noop(self):
        """close() on an empty composite is a no-op."""
        composite = CompositeLogger([])
        composite.close()

    def test_empty_targets_configure_noop(self):
        """configure() on an empty composite is a no-op."""
        composite = CompositeLogger([])
        composite.configure(max_log_output=100)


class TestCompositeLoggerTargetsProperty:
    """Tests for the targets property."""

    def test_targets_returns_copy(self):
        """targets property returns a copy, not the internal list."""
        t1 = StubLogger("t1")
        composite = CompositeLogger([t1])

        targets_copy = composite.targets
        targets_copy.append(StubLogger("extra"))

        # Internal list is unchanged
        assert len(composite.targets) == 1

    def test_targets_matches_init(self):
        """targets property returns the same targets passed to __init__."""
        t1 = StubLogger("t1")
        t2 = StubLogger("t2")
        composite = CompositeLogger([t1, t2])

        targets = composite.targets
        assert len(targets) == 2
        assert targets[0] is t1
        assert targets[1] is t2


class TestCompositeLoggerThreadSafety:
    """Tests for CompositeLogger thread safety under concurrent log() calls."""

    def test_thread_safety(self):
        """Concurrent log() calls deliver all entries to all targets."""
        import threading

        num_threads = 4
        calls_per_thread = 10
        total_calls = num_threads * calls_per_thread

        t1 = StubLogger("t1")
        t2 = StubLogger("t2")
        composite = CompositeLogger([t1, t2])

        barrier = threading.Barrier(num_threads)
        expected_messages: list[str] = []

        def worker(thread_idx: int) -> None:
            barrier.wait()
            for call_idx in range(calls_per_thread):
                msg = f"thread_{thread_idx}_msg_{call_idx}"
                expected_messages.append(msg)
                composite.log({"event": "threaded", "message": msg})

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each target must have received exactly total_calls entries
        assert len(t1.log_calls) == total_calls
        assert len(t2.log_calls) == total_calls

        # Every unique message must appear in each target's log_calls
        t1_messages = [entry["message"] for entry in t1.log_calls]
        t2_messages = [entry["message"] for entry in t2.log_calls]

        for msg in expected_messages:
            assert msg in t1_messages, f"{msg!r} missing from t1"
            assert msg in t2_messages, f"{msg!r} missing from t2"
