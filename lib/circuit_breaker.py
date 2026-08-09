"""Circuit breaker for per-target SSH connection resilience.

Tracks consecutive failures for each SSH target and opens a circuit once a
configurable failure threshold is reached.  While a circuit is open, new
connection attempts for that target are rejected immediately (fail fast)
until a cooldown timeout elapses, at which point a single half-open probe is
allowed through to test whether the target has recovered.
"""

import threading
import time
from typing import Any, Dict

from lib.constants import (
    DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
)


class CircuitBreaker:
    """Per-target circuit breaker with CLOSED / OPEN / HALF_OPEN states.

    Thread-safe: all state mutations happen under an internal lock so the
    breaker can be shared across concurrent request handlers.

    State transitions:
        CLOSED   --(failure_threshold consecutive failures)--> OPEN
        OPEN     --(timeout_seconds elapsed)--> HALF_OPEN (single probe)
        HALF_OPEN--(probe succeeds)--> CLOSED
        HALF_OPEN--(probe fails)--> OPEN
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        timeout_seconds: float = DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    ):
        """Initialize the circuit breaker.

        Args:
            failure_threshold: Consecutive failures per target that trip the
                circuit (must be >= 1).
            timeout_seconds: Seconds an open circuit stays open before a
                half-open probe is permitted.
        """
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        self._failure_threshold = failure_threshold
        self._timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._targets: Dict[str, Dict[str, Any]] = {}

    def _state_for(self, target_name: str) -> Dict[str, Any]:
        """Return (creating if needed) the mutable state dict for a target.

        Must be called while holding ``self._lock``.
        """
        if target_name not in self._targets:
            self._targets[target_name] = {
                "state": self.CLOSED,
                "failures": 0,
                "opened_at": None,
                "probe_in_flight": False,
            }
        return self._targets[target_name]

    def __call__(self, target_name: str) -> bool:
        """Return True if a request for *target_name* should proceed.

        Closed circuits always allow requests.  Open circuits reject requests
        until the timeout elapses, then transition to HALF_OPEN and allow a
        single in-flight probe through.

        Args:
            target_name: Stable identifier for the target (e.g. ``host:port``).

        Returns:
            True if the caller should proceed, False to fail fast.
        """
        with self._lock:
            state = self._state_for(target_name)

            if state["state"] == self.CLOSED:
                return True

            if state["state"] == self.OPEN:
                if (
                    state["opened_at"] is not None
                    and time.monotonic() - state["opened_at"] >= self._timeout_seconds
                ):
                    state["state"] = self.HALF_OPEN
                    state["probe_in_flight"] = True
                    return True
                return False

            # HALF_OPEN: allow a single probe; reject everything else while
            # the probe is still in flight.
            if state["probe_in_flight"]:
                return False
            state["probe_in_flight"] = True
            return True

    def record_success(self, target_name: str) -> None:
        """Record a successful operation for *target_name*.

        Resets the failure count and returns the circuit to CLOSED.
        """
        with self._lock:
            state = self._state_for(target_name)
            state["failures"] = 0
            state["state"] = self.CLOSED
            state["opened_at"] = None
            state["probe_in_flight"] = False

    def record_failure(self, target_name: str) -> None:
        """Record a failed operation for *target_name*.

        Increments the consecutive failure count and opens the circuit once
        the threshold is reached.  A half-open probe failure re-opens the
        circuit immediately.
        """
        with self._lock:
            state = self._state_for(target_name)
            state["failures"] += 1
            state["probe_in_flight"] = False
            if state["failures"] >= self._failure_threshold:
                state["state"] = self.OPEN
                state["opened_at"] = time.monotonic()

    def state(self, target_name: str) -> str:
        """Return the current state (``closed``/``open``/``half_open``)."""
        with self._lock:
            return self._state_for(target_name)["state"]

    def failure_count(self, target_name: str) -> int:
        """Return the current consecutive failure count for *target_name*."""
        with self._lock:
            return self._state_for(target_name)["failures"]
