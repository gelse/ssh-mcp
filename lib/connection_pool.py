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
    DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
)
from lib.exceptions import ServiceUnavailableError
from lib.metrics import (
    SSH_POOL_ACTIVE_CONNECTIONS,
    SSH_POOL_CREATED_TOTAL,
    SSH_POOL_IDLE_CONNECTIONS,
)

if TYPE_CHECKING:
    from lib.config import ConfigManager
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

    Additional concurrency state: ``_locks_guard`` protects the
    ``_locks`` map (double-checked in ``_lock_for``), and the global
    ``threading.Semaphore`` (``_semaphore``) enforces the process-wide
    concurrent-checkout cap, raising :class:`ServiceUnavailableError`
    (HTTP 503) when exhausted.  ``PooledConnection.created_at`` and
    ``.last_used_at`` are mutated under the owning target's lock only.
    """

    def __init__(
        self,
        ssh_client_manager: "SSHClientManager",
        max_connections_per_target: int = DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
        max_concurrent_ssh_connections: int = DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
        idle_timeout_seconds: float = DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
        cleanup_interval_seconds: float = DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
        config_manager: "ConfigManager | None" = None,
    ):
        """Initialise the pool.

        Args:
            ssh_client_manager: Manager used to create new connections
                when the idle pool has no usable entry.
            max_connections_per_target: Maximum number of idle
                connections kept per target.  Connections returned
                beyond this limit are closed immediately.
            max_concurrent_ssh_connections: Global maximum number of
                concurrently checked-out SSH connections across all
                targets.  Excess acquisitions are rejected with a
                :class:`ServiceUnavailableError` (HTTP 503) rather than
                queued.  This is a process-wide back-pressure cap.
            idle_timeout_seconds: Idle connections are evicted (closed)
                once they have been unused for this many seconds.
            cleanup_interval_seconds: Interval between idle-cleanup
                sweeps of the background thread.
            config_manager: Optional :class:`~lib.config.ConfigManager`
                whose config changes invalidate pooled connections for
                removed/reconfigured targets.  When provided, the pool
                subscribes to its ``on_config_change`` notifications.
        """
        self._manager = ssh_client_manager
        self._max_connections_per_target = max(1, max_connections_per_target)
        self._max_concurrent_ssh_connections = max(
            1, max_concurrent_ssh_connections
        )
        self._semaphore = threading.Semaphore(
            self._max_concurrent_ssh_connections
        )
        self._idle_timeout_seconds = max(0.0, idle_timeout_seconds)
        self._cleanup_interval_seconds = max(1.0, cleanup_interval_seconds)
        self._config_manager = config_manager

        self._idle_by_target: Dict[str, Deque[PooledConnection]] = {}
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._active_by_target: Dict[str, int] = {}
        self._active_clients_by_target: Dict[str, set] = {}
        self._created_by_target: Dict[str, int] = {}
        self._targets: Dict[str, Dict[str, Any]] = {}

        self._stop_event = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

        if self._config_manager is not None:
            self._config_manager.on_config_change(self.on_config_change)

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

        Closes idle connections and any currently checked-out (active)
        clients, so the pool fully releases its SSH handles on shutdown.
        Safe to call more than once and before :meth:`start`.
        """
        self._stop_event.set()
        if self._cleanup_thread is not None:
            self._cleanup_thread.join(timeout=timeout)
            self._cleanup_thread = None
        self.close_all(include_active=True)

    def on_config_change(self) -> None:
        """React to a config hot-reload by invalidating stale pooled state.

        Invoked by the :class:`~lib.config.ConfigManager` after it has
        atomically swapped in new config data.  Targets that no longer
        exist have their idle connections closed.  Targets whose
        configuration changed are invalidated and re-registered with a
        fresh copy so that future connections use the new settings.
        Active (checked-out) connections are left untouched.  Safe to
        call whenever a config manager is attached; otherwise a no-op.
        """
        if self._config_manager is None:
            return
        # Refresh the process-wide concurrency cap when the config changed
        # it.  The semaphore is rebuilt at full capacity, so any permits
        # still held by force-closed leases (see close_all) are not leaked.
        settings = self._config_manager.data.get("settings", {})
        new_limit = max(
            1,
            int(settings.get(
                "max_concurrent_ssh_connections",
                DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
            )),
        )
        if new_limit != self._max_concurrent_ssh_connections:
            self._max_concurrent_ssh_connections = new_limit
            self.close_all(include_active=True)
        current_targets = self._config_manager.data.get("ssh_targets", {})
        # Map each configured target to its pool key -- the same key space
        # that connect() uses (host:port#<digest>) -- because the pool is
        # keyed by that value, not by the config's plain target name.
        current_pool_keys = {
            self._manager._target_name(target)
            for target in current_targets.values()
        }
        # Drop targets that vanished from the config.
        for pool_key in list(self._locks.keys()):
            if pool_key not in current_pool_keys:
                self._invalidate_target(pool_key)
        # Refresh targets whose configuration changed.
        for target in current_targets.values():
            pool_key = self._manager._target_name(target)
            if self._targets.get(pool_key) != target:
                self._invalidate_target(pool_key)
                self._targets[pool_key] = dict(target)

    def register_target(self, target_name: str, target: Dict[str, Any]) -> None:
        """Ensure a per-target lock, deque, and counters exist.

        Called by :meth:`SSHClientManager.connect` so the pool can lazily
        create new connections for targets that were never seen before.
        Safe to call concurrently from multiple threads.

        The ``_targets`` mapping is always (re)populated with the latest
        *target*, not only on first registration: a config change may have
        invalidated it (see :meth:`on_config_change`), and every tracked
        dict must stay keyed consistently for :meth:`get_connection` to
        find a target.
        """
        with self._locks_guard:
            if target_name not in self._locks:
                self._locks[target_name] = threading.Lock()
                self._idle_by_target[target_name] = deque()
                self._active_by_target[target_name] = 0
                self._active_clients_by_target[target_name] = set()
                self._created_by_target[target_name] = 0
                SSH_POOL_ACTIVE_CONNECTIONS.labels(target=target_name).set(0)
                SSH_POOL_IDLE_CONNECTIONS.labels(target=target_name).set(0)
            self._targets[target_name] = target

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def get_connection(self, target_name: str) -> Any:
        """Return a reusable connection for *target_name*.

        Pops the most-recently-returned idle entry (LIFO), health-checks
        it, and returns it immediately when healthy.  Unhealthy entries
        are closed and skipped.  When the idle pool is empty, a fresh
        connection is created via the manager.

        A global semaphore (:attr:`_semaphore`) gates concurrent checkouts
        across all targets.  When the limit is reached the semaphore is
        acquired non-blocking and this method raises
        :class:`ServiceUnavailableError` (HTTP 503) instead of queuing.
        The permit is released again on any failure *after* a successful
        acquire so a failed checkout never leaks a permit.

        Args:
            target_name: Stable target identifier (``host:port``).

        Raises:
            ServiceUnavailableError: When the global concurrency limit for
                concurrently checked-out connections has been reached.

        Returns:
            A connected :class:`paramiko.SSHClient` instance.
        """
        if not self._semaphore.acquire(blocking=False):
            raise ServiceUnavailableError(
                "Concurrent SSH connection limit reached "
                f"({self._max_concurrent_ssh_connections}); try again later"
            )
        try:
            return self._get_connection_unlocked(target_name)
        except BaseException:
            # A checkout that fails after acquiring the permit must give it
            # back, otherwise the pool leaks capacity until a full reset.
            self._semaphore.release()
            raise

    def _get_connection_unlocked(self, target_name: str) -> Any:
        """Check out a connection, assuming the concurrency permit is held."""
        lock = self._lock_for(target_name)
        with lock:
            idle = self._idle_by_target[target_name]
            while idle:
                entry = idle.pop()
                if self._health_check(entry.client):
                    self._active_by_target[target_name] += 1
                    self._active_clients_by_target[target_name].add(entry.client)
                    self._update_idle_gauge(target_name)
                    self._update_active_gauge(target_name)
                    return entry.client
                # Unhealthy: drop the stale connection and keep looking.
                self._safe_close(entry.client)

        client = self._manager.get_client(self._targets[target_name])
        with lock:
            self._active_by_target[target_name] += 1
            self._active_clients_by_target[target_name].add(client)
            self._created_by_target[target_name] += 1
            self._update_active_gauge(target_name)
            SSH_POOL_CREATED_TOTAL.labels(target=target_name).inc()
        return client

    def return_connection(self, target_name: str, client: Any) -> None:
        """Return *client* to the pool (when healthy) or close it.

        The client is only pooled when it is healthy and the target's
        idle deque is below ``max_connections_per_target``.  Otherwise
        it is closed immediately.

        Releases the global concurrency permit so another checkout can
        proceed.

        Args:
            target_name: Stable target identifier (``host:port``).
            client: The connection being returned.
        """
        lock = self._lock_for(target_name)
        with lock:
            self._active_by_target[target_name] = max(
                0, self._active_by_target[target_name] - 1
            )
            active_clients = self._active_clients_by_target.get(target_name)
            if active_clients is not None:
                active_clients.discard(client)
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
        self._semaphore.release()

    def close_all(self, include_active: bool = False) -> None:
        """Close every pooled connection and reset counters.

        By default only idle connections are closed; checked-out (active)
        clients are left alone so in-flight operations are not interrupted.

        When ``include_active`` is True every checked-out client is forced
        closed, so the global concurrency semaphore is rebuilt at full
        capacity: the permits for the force-closed leases would otherwise
        be released later by their callers' ``return_connection``, over
        -releasing the semaphore.

        Args:
            include_active: When True, also close and clear currently
                checked-out clients for every target.

        Safe to call more than once.
        """
        for target_name, lock in list(self._locks.items()):
            with lock:
                idle = self._idle_by_target[target_name]
                while idle:
                    self._safe_close(idle.pop().client)
                if include_active:
                    active_clients = self._active_clients_by_target.get(
                        target_name
                    )
                    if active_clients is not None:
                        for client in list(active_clients):
                            self._safe_close(client)
                        active_clients.clear()
                self._active_by_target[target_name] = 0
                self._created_by_target[target_name] = 0
                self._update_idle_gauge(target_name)
                self._update_active_gauge(target_name)
        if include_active:
            self._semaphore = threading.Semaphore(
                self._max_concurrent_ssh_connections
            )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        """Return aggregate pool statistics.

        Returns:
            A dict with ``active_connections``, ``idle_connections``,
            ``total_created``, ``max_connections_per_target``,
            ``max_concurrent_ssh_connections``, and
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
            "max_concurrent_ssh_connections": self._max_concurrent_ssh_connections,
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
                    self._active_clients_by_target[target_name] = set()
                    self._created_by_target[target_name] = 0
                    SSH_POOL_ACTIVE_CONNECTIONS.labels(target=target_name).set(0)
                    SSH_POOL_IDLE_CONNECTIONS.labels(target=target_name).set(0)
        return lock

    def _invalidate_target(self, target_name: str) -> None:
        """Close idle connections and drop the cached config for a target.

        Called when a config change removes or reconfigures a target.
        Idle connections for the target are closed and removed from the
        pool, and its cached ``_targets`` entry is dropped so future
        lookups treat it as unregistered.  Active (checked-out)
        connections are left open so in-flight operations are not
        interrupted.
        """
        lock = self._lock_for(target_name)
        with lock:
            idle = self._idle_by_target.get(target_name)
            if idle is not None:
                while idle:
                    self._safe_close(idle.pop().client)
            self._update_idle_gauge(target_name)
            self._targets.pop(target_name, None)

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
