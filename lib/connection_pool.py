"""Per-target SSH connection pooling.

Reuses established paramiko connections across requests to avoid the
dominant per-request latency of a full TCP + SSH handshake.  Connections
are pooled per target (``host:port``), health-checked before reuse, and
evicted once they have been idle for longer than ``idle_timeout_seconds``.

Thread safety
-------------
Each target has its own :class:`threading.Lock` guarding its idle deque
and per-target counters.  A background daemon thread periodically runs
idle-eviction.  Locks are never nested: helpers that touch multiple
targets (stats aggregation, gauge refresh) acquire per-target locks one
at a time and release them before touching the next.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Deque, Dict, List

from lib.constants import (
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
)
from lib.metrics import (
    SSH_POOL_ACTIVE_CONNECTIONS,
    SSH_POOL_CREATED_TOTAL,
    SSH_POOL_IDLE_CONNECTIONS,
)

if TYPE_CHECKING:
    from lib.ssh_client import SSHClientManager


@dataclass
class PooledConnection:
    """A connection sitting in a target's idle pool.

    Attributes:
        client: The connected :class:`paramiko.SSHClient` instance.
        created_at: ``time.monotonic()`` timestamp of pool creation.
        last_used_at: ``time.monotonic()`` timestamp of the last
            checkout or return.  Used for idle eviction.
    """

    client: Any
    created_at: float
    last_used_at: float


class SSHConnectionPool:
    """Pool of reusable SSH connections, organised per target.

    A target is identified by ``host:port`` (see
    :meth:`SSHClientManager._target_name`).  Each target has an idle
    ``deque`` of :class:`PooledConnection` entries and a per-target
    :class:`threading.Lock` guarding that deque plus the per-target
    counters (``active`` / ``created``).

    The pool is opt-in: :class:`~lib.ssh_client.SSHClientManager` only
    consults it when one is attached via
    :meth:`~lib.ssh_client.SSHClientManager.set_connection_pool`.
    """

    def __init__(
        self,
        ssh_client_manager: "SSHClientManager",
        max_connections_per_target: int = DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
        idle_timeout_seconds: float = DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
        cleanup_interval_seconds: float = DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    ):
        """Initialise the pool.

        Args:
            ssh_client_manager: Manager used to create new connections
                when the idle pool has no usable entry.
            max_connections_per_target: Maximum number of idle
                connections kept per target.  Connections returned
                beyond this limit are closed immediately.
            idle_timeout_seconds: Idle connections are evicted (closed)
                once they have been unused for this many seconds.
            cleanup_interval_seconds: Interval between idle-cleanup
                sweeps of the background thread.
        """
        self._manager = ssh_client_manager
        self._max_connections_per_target = max(1, max_connections_per_target)
        self._idle_timeout_seconds = max(0.0, idle_timeout_seconds)
        self._cleanup_interval_seconds = max(1.0, cleanup_interval_seconds)

        self._idle_by_target: Dict[str, Deque[PooledConnection]] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._active_by_target: Dict[str, int] = {}
        self._created_by_target: Dict[str, int] = {}
        self._targets: Dict[str, Dict[str, Any]] = {}

        self._stop_event = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background idle-cleanup thread (idempotent)."""
        if self._cleanup_thread is not None and self._cleanup_thread.is_alive():
            return
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="ssh-pool-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background cleanup thread and close all pooled clients.

        Safe to call more than once and before :meth:`start`.
        """
        self._stop_event.set()
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=timeout)
            self._cleanup_thread = None
        self.close_all()

    def register_target(self, target_name: str, target: Dict[str, Any]) -> None:
        """Ensure a per-target lock, deque, and counters exist.

        Called by :meth:`SSHClientManager.connect` so the pool can lazily
        create new connections for targets that were never seen before.
        Safe to call concurrently from multiple threads.
        """
        if target_name in self._locks:
            return
        with self._locks_guard:
            if target_name not in self._locks:
                self._locks[target_name] = threading.Lock()
                self._idle_by_target[target_name] = deque()
                self._active_by_target[target_name] = 0
                self._created_by_target[target_name] = 0
                self._targets[target_name] = target
                SSH_POOL_ACTIVE_CONNECTIONS.labels(target=target_name).set(0)
                SSH_POOL_IDLE_CONNECTIONS.labels(target=target_name).set(0)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def get_connection(self, target_name: str) -> Any:
        """Return a reusable connection for *target_name*.

        Pops the most-recently-returned idle entry (LIFO), health-checks
        it, and returns it immediately when healthy.  Unhealthy entries
        are closed and skipped.  When the idle pool is empty, a fresh
        connection is created via the manager.

        Args:
            target_name: Stable target identifier (``host:port``).

        Returns:
            A connected :class:`paramiko.SSHClient` instance.
        """
        lock = self._lock_for(target_name)
        with lock:
            idle = self._idle_by_target[target_name]
            while idle:
                entry = idle.pop()
                if self._health_check(entry.client):
                    self._active_by_target[target_name] += 1
                    self._update_idle_gauge(target_name)
                    self._update_active_gauge(target_name)
                    return entry.client
                # Unhealthy: drop the stale connection and keep looking.
                self._safe_close(entry.client)

        client = self._manager.get_client(self._targets[target_name])
        with lock:
            self._active_by_target[target_name] += 1
            self._created_by_target[target_name] += 1
            self._update_active_gauge(target_name)
            SSH_POOL_CREATED_TOTAL.labels(target=target_name).inc()
        return client

    def return_connection(self, target_name: str, client: Any) -> None:
        """Return *client* to the pool (when healthy) or close it.

        The client is only pooled when it is healthy and the target's
        idle deque is below ``max_connections_per_target``.  Otherwise
        it is closed immediately.

        Args:
            target_name: Stable target identifier (``host:port``).
            client: The connection being returned.
        """
        lock = self._lock_for(target_name)
        with lock:
            self._active_by_target[target_name] = max(
                0, self._active_by_target[target_name] - 1
            )
            if self._health_check(client) and len(
                self._idle_by_target[target_name]
            ) < self._max_connections_per_target:
                self._idle_by_target[target_name].append(
                    PooledConnection(
                        client=client,
                        created_at=time.monotonic(),
                        last_used_at=time.monotonic(),
                    )
                )
            else:
                self._safe_close(client)
            self._update_idle_gauge(target_name)
            self._update_active_gauge(target_name)

    def close_all(self) -> None:
        """Close every idle connection in the pool and reset counters."""
        for target_name, lock in list(self._locks.items()):
            with lock:
                idle = self._idle_by_target[target_name]
                while idle:
                    self._safe_close(idle.pop().client)
                self._active_by_target[target_name] = 0
                self._created_by_target[target_name] = 0
                self._update_idle_gauge(target_name)
                self._update_active_gauge(target_name)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return aggregate pool statistics.

        Returns:
            A dict with ``active_connections``, ``idle_connections``,
            ``total_created``, ``max_connections_per_target``, and
            ``idle_timeout_seconds`` keys.
        """
        active = 0
        idle = 0
        created = 0
        for target_name, lock in list(self._locks.items()):
            with lock:
                active += self._active_by_target.get(target_name, 0)
                idle += len(self._idle_by_target.get(target_name, ()))
                created += self._created_by_target.get(target_name, 0)
        return {
            "active_connections": active,
            "idle_connections": idle,
            "total_created": created,
            "max_connections_per_target": self._max_connections_per_target,
            "idle_timeout_seconds": self._idle_timeout_seconds,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lock_for(self, target_name: str) -> threading.Lock:
        """Return the per-target lock, creating state on first use."""
        lock = self._locks.get(target_name)
        if lock is None:
            with self._locks_guard:
                lock = self._locks.get(target_name)
                if lock is None:
                    lock = threading.Lock()
                    self._locks[target_name] = lock
                    self._idle_by_target[target_name] = deque()
                    self._active_by_target[target_name] = 0
                    self._created_by_target[target_name] = 0
                    SSH_POOL_ACTIVE_CONNECTIONS.labels(target=target_name).set(0)
                    SSH_POOL_IDLE_CONNECTIONS.labels(target=target_name).set(0)
        return lock

    def _health_check(self, client: Any) -> bool:
        """Return True when *client* is still usable.

        A client is healthy when its transport is active and responds to
        an SSH2 keepalive (``send_ignore``).  No remote command is run,
        keeping the check lightweight.
        """
        try:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                return False
            transport.send_ignore()
            return True
        except Exception:
            return False

    def _safe_close(self, client: Any) -> None:
        """Close *client*, swallowing any errors."""
        try:
            client.close()
        except Exception:
            pass

    def _cleanup_idle(self) -> None:
        """Close idle connections that exceed the idle timeout.

        The idle deque is kept sorted by ``last_used_at`` ascending:
        checkouts pop from the right and returns append to the right, so
        eviction scans from the left (oldest) and stops at the first
        entry younger than the timeout.
        """
        cutoff = time.monotonic() - self._idle_timeout_seconds
        for target_name, lock in list(self._locks.items()):
            with lock:
                idle = self._idle_by_target[target_name]
                while idle and idle[0].last_used_at < cutoff:
                    self._safe_close(idle.popleft().client)
                self._update_idle_gauge(target_name)

    def _cleanup_loop(self) -> None:
        """Background loop that runs idle eviction periodically."""
        while not self._stop_event.wait(self._cleanup_interval_seconds):
            try:
                self._cleanup_idle()
            except Exception:
                # The cleanup thread must never die from a transient error.
                continue

    # ------------------------------------------------------------------
    # Gauge helpers (never called while holding a per-target lock)
    # ------------------------------------------------------------------

    def _update_idle_gauge(self, target_name: str) -> None:
        """Refresh the idle gauge for *target_name*.

        Callers MUST hold the target's lock before invoking this.
        """
        SSH_POOL_IDLE_CONNECTIONS.labels(target=target_name).set(
            len(self._idle_by_target.get(target_name, ()))
        )

    def _update_active_gauge(self, target_name: str) -> None:
        """Refresh the active gauge for *target_name*.

        Callers MUST hold the target's lock before invoking this.
        """
        SSH_POOL_ACTIVE_CONNECTIONS.labels(target=target_name).set(
            self._active_by_target.get(target_name, 0)
        )
