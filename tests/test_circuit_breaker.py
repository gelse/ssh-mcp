"""Unit tests for :mod:`lib.circuit_breaker` — CircuitBreaker.

The breaker is a pure, thread-safe state machine, so these tests run
without any network or filesystem interaction.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lib.circuit_breaker import CircuitBreaker
from lib.constants import (
    DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
)


# ---------------------------------------------------------------------------
# Construction & defaults
# ---------------------------------------------------------------------------


class TestCircuitBreakerDefaults:
    """The breaker instantiates with sensible defaults and validates args."""

    def test_default_threshold_and_timeout(self):
        """Defaults come from lib.constants (5 failures / 60 seconds)."""
        cb = CircuitBreaker()
        assert cb._failure_threshold == DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD
        assert cb._timeout_seconds == DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS

    def test_initial_state_is_closed(self):
        """An untouched target starts CLOSED with zero failures."""
        cb = CircuitBreaker()
        assert cb.state("host:22") == CircuitBreaker.CLOSED
        assert cb.failure_count("host:22") == 0

    def test_closed_circuit_allows_request(self):
        """__call__ returns True while the circuit is CLOSED."""
        cb = CircuitBreaker()
        assert cb("host:22") is True

    def test_rejects_threshold_below_one(self):
        """failure_threshold < 1 is rejected."""
        with pytest.raises(ValueError, match="failure_threshold"):
            CircuitBreaker(failure_threshold=0)

    def test_rejects_non_positive_timeout(self):
        """timeout_seconds <= 0 is rejected."""
        with pytest.raises(ValueError, match="timeout_seconds"):
            CircuitBreaker(timeout_seconds=0)
        with pytest.raises(ValueError, match="timeout_seconds"):
            CircuitBreaker(timeout_seconds=-5)


# ---------------------------------------------------------------------------
# Failure accumulation & opening
# ---------------------------------------------------------------------------


class TestCircuitOpening:
    """The circuit opens after the failure threshold is reached."""

    def test_opens_after_threshold_failures(self):
        """N consecutive failures transition CLOSED -> OPEN."""
        cb = CircuitBreaker(failure_threshold=3)
        assert cb.state("host:22") == CircuitBreaker.CLOSED

        cb.record_failure("host:22")
        cb.record_failure("host:22")
        assert cb.state("host:22") == CircuitBreaker.CLOSED
        assert cb.failure_count("host:22") == 2

        cb.record_failure("host:22")
        assert cb.state("host:22") == CircuitBreaker.OPEN
        assert cb.failure_count("host:22") == 3

    def test_open_circuit_rejects_requests(self):
        """An OPEN circuit fails fast until the timeout elapses."""
        cb = CircuitBreaker(failure_threshold=2, timeout_seconds=60)
        cb.record_failure("host:22")
        cb.record_failure("host:22")
        assert cb("host:22") is False

    def test_success_resets_failure_count(self):
        """A success resets failures and keeps the circuit CLOSED."""
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure("host:22")
        cb.record_failure("host:22")
        cb.record_success("host:22")
        assert cb.state("host:22") == CircuitBreaker.CLOSED
        assert cb.failure_count("host:22") == 0

        # Failures start counting again from zero.
        cb.record_failure("host:22")
        cb.record_failure("host:22")
        assert cb.state("host:22") == CircuitBreaker.CLOSED
        cb.record_failure("host:22")
        assert cb.state("host:22") == CircuitBreaker.OPEN

    def test_per_target_isolation(self):
        """Failure counts are tracked independently per target."""
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure("host-a:22")
        assert cb.state("host-a:22") == CircuitBreaker.CLOSED
        assert cb.state("host-b:22") == CircuitBreaker.CLOSED

        cb.record_failure("host-a:22")
        assert cb.state("host-a:22") == CircuitBreaker.OPEN
        assert cb.state("host-b:22") == CircuitBreaker.CLOSED
        assert cb("host-b:22") is True
        assert cb("host-a:22") is False


# ---------------------------------------------------------------------------
# Half-open probing
# ---------------------------------------------------------------------------


class TestHalfOpenProbe:
    """OPEN -> HALF_OPEN transition and single-probe semantics."""

    def test_timeout_allows_single_probe(self):
        """After the cooldown, one half-open probe is let through."""
        cb = CircuitBreaker(failure_threshold=2, timeout_seconds=60)
        cb.record_failure("host:22")
        cb.record_failure("host:22")
        assert cb("host:22") is False

        with patch(
            "lib.circuit_breaker.time.monotonic", return_value=100.0
        ) as mock_monotonic:
            # Simulate the circuit opening at t=40 and the probe at t=100.
            mock_monotonic.return_value = 40.0
            cb.record_failure("host:22")  # re-open (already open, refreshes)
            mock_monotonic.return_value = 100.0
            # Only __call__ performs the OPEN -> HALF_OPEN transition.
            assert cb("host:22") is True
            assert cb.state("host:22") == CircuitBreaker.HALF_OPEN

    def test_probe_success_closes_circuit(self):
        """A successful half-open probe returns the circuit to CLOSED."""
        with patch(
            "lib.circuit_breaker.time.monotonic", return_value=100.0
        ) as mock_monotonic:
            cb = CircuitBreaker(failure_threshold=1, timeout_seconds=0.001)
            cb.record_failure("host:22")  # circuit opens at t=100
            assert cb.state("host:22") == CircuitBreaker.OPEN

            mock_monotonic.return_value = 200.0  # cooldown elapsed
            assert cb("host:22") is True  # probe allowed through
            assert cb.state("host:22") == CircuitBreaker.HALF_OPEN

            cb.record_success("host:22")
            assert cb.state("host:22") == CircuitBreaker.CLOSED
            assert cb.failure_count("host:22") == 0
            assert cb("host:22") is True

    def test_probe_failure_reopens_circuit(self):
        """A failed half-open probe re-opens the circuit immediately."""
        with patch(
            "lib.circuit_breaker.time.monotonic", return_value=100.0
        ) as mock_monotonic:
            cb = CircuitBreaker(failure_threshold=2, timeout_seconds=0.001)
            cb.record_failure("host:22")
            cb.record_failure("host:22")  # circuit opens at t=100
            assert cb.state("host:22") == CircuitBreaker.OPEN

            mock_monotonic.return_value = 200.0  # cooldown elapsed
            assert cb("host:22") is True  # probe goes through...
            assert cb.state("host:22") == CircuitBreaker.HALF_OPEN

            # ...and its failure re-opens the circuit at t=200.
            cb.record_failure("host:22")
            assert cb.state("host:22") == CircuitBreaker.OPEN
            assert cb("host:22") is False

    def test_only_one_probe_in_flight(self):
        """While a half-open probe is in flight, other requests are rejected."""
        with patch(
            "lib.circuit_breaker.time.monotonic", return_value=100.0
        ) as mock_monotonic:
            cb = CircuitBreaker(failure_threshold=1, timeout_seconds=0.001)
            cb.record_failure("host:22")  # circuit opens at t=100

            mock_monotonic.return_value = 200.0  # cooldown elapsed
            assert cb("host:22") is True  # probe allowed
            assert cb.state("host:22") == CircuitBreaker.HALF_OPEN

            # Second request while probe is still in flight is rejected.
            assert cb("host:22") is False


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Concurrent callers never corrupt per-target state."""

    def test_concurrent_failures_are_counted_atomically(self):
        """Threads hammering record_failure together trip the circuit."""
        cb = CircuitBreaker(failure_threshold=5)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                for _ in range(20):
                    cb.record_failure("host:22")
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(exc)

        import threading

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert cb.failure_count("host:22") == 80
        assert cb.state("host:22") == CircuitBreaker.OPEN
