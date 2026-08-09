"""Unit tests for :mod:`lib.connection_pool` — SSHConnectionPool.

The pool is exercised with fake managers and clients (no network), covering
per-target reuse, health-checked checkouts, idle eviction, pool-size limits,
thread safety, stats, and lifecycle (start/stop/close_all).
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from lib.connection_pool import PooledConnection, SSHConnectionPool
from lib.constants import (
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
)
from lib.metrics import REGISTRY

TARGET = "unit-test-pool-target"
TARGET_DICT = {"host": "unit-test-host", "port": 22}


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeTransport:
    """Minimal transport stand-in with is_active() and send_ignore()."""

    def __init__(self, active: bool = True):
        self._active = active
        self.ignore_calls = 0

    def is_active(self) -> bool:
        return self._active

    def send_ignore(self) -> None:
        self.ignore_calls += 1


class FakeClient:
    """Minimal SSHClient stand-in recording close() and transport state."""

    def __init__(self, active: bool = True, close_raises: bool = False):
        self.transport = FakeTransport(active=active)
        self.closed = False
        self.close_raises = close_raises

    def get_transport(self) -> FakeTransport:
        return self.transport

    def close(self) -> None:
        if self.close_raises:
            raise RuntimeError("close failed")
        self.closed = True


class FakeManager:
    """Records get_client() calls and hands out fresh fake clients."""

    def __init__(self):
        self.clients: list[FakeClient] = []
        self.calls: list[dict] = []

    def get_client(self, target: dict) -> FakeClient:
        self.calls.append(target)
        client = FakeClient()
        self.clients.append(client)
        return client


@pytest.fixture
def manager() -> FakeManager:
    return FakeManager()


@pytest.fixture
def pool(manager: FakeManager) -> SSHConnectionPool:
    p = SSHConnectionPool(manager)  # type: ignore[arg-type]
    p.register_target(TARGET, TARGET_DICT)
    return p


# ---------------------------------------------------------------------------
# Construction & defaults
# ---------------------------------------------------------------------------


class TestConstruction:
    """The pool instantiates with defaults from lib.constants."""

    def test_defaults_match_constants(self, manager: FakeManager):
        p = SSHConnectionPool(manager)  # type: ignore[arg-type]
        assert p._max_connections_per_target == DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET
        assert p._idle_timeout_seconds == DEFAULT_POOL_IDLE_TIMEOUT_SECONDS
        assert p._cleanup_interval_seconds == DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS

    def test_negative_values_clamped(self, manager: FakeManager):
        p = SSHConnectionPool(manager, max_connections_per_target=0, idle_timeout_seconds=-5)  # type: ignore[arg-type]
        assert p._max_connections_per_target == 1
        assert p._idle_timeout_seconds == 0.0

    def test_register_target_initialises_state(self, pool: SSHConnectionPool):
        assert TARGET in pool._locks
        assert len(pool._idle_by_target[TARGET]) == 0
        assert pool._active_by_target[TARGET] == 0
        assert pool._created_by_target[TARGET] == 0
        assert pool._targets[TARGET] == TARGET_DICT

    def test_register_target_is_idempotent(self, pool: SSHConnectionPool, manager: FakeManager):
        pool.register_target(TARGET, TARGET_DICT)
        assert pool._targets[TARGET] == TARGET_DICT


# ---------------------------------------------------------------------------
# Checkout (get_connection)
# ---------------------------------------------------------------------------


class TestGetConnection:
    """get_connection creates or reuses per-target connections."""

    def test_creates_new_connection_when_idle_empty(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        assert client is manager.clients[0]
        assert manager.calls == [TARGET_DICT]
        assert pool._active_by_target[TARGET] == 1
        assert pool._created_by_target[TARGET] == 1

    def test_reuses_healthy_idle_connection(self, pool: SSHConnectionPool, manager: FakeManager):
        first = pool.get_connection(TARGET)
        pool.return_connection(TARGET, first)
        assert pool._idle_by_target[TARGET]

        second = pool.get_connection(TARGET)
        assert second is first
        # No new connection was created by the manager.
        assert len(manager.clients) == 1
        assert pool._active_by_target[TARGET] == 1
        assert len(pool._idle_by_target[TARGET]) == 0

    def test_health_check_runs_before_reuse(self, pool: SSHConnectionPool, manager: FakeManager):
        first = pool.get_connection(TARGET)
        pool.return_connection(TARGET, first)
        second = pool.get_connection(TARGET)
        assert second is first
        assert first.transport.ignore_calls >= 1

    def test_unhealthy_idle_connection_closed_and_skipped(self, pool: SSHConnectionPool, manager: FakeManager):
        first = pool.get_connection(TARGET)
        pool.return_connection(TARGET, first)
        # Kill the pooled client's transport so the health check fails.
        first.transport._active = False

        second = pool.get_connection(TARGET)
        assert second is not first
        assert first.closed is True
        assert len(manager.clients) == 2
        assert pool._created_by_target[TARGET] == 2

    def test_all_unhealthy_idle_connections_dropped(self, pool: SSHConnectionPool, manager: FakeManager):
        first = pool.get_connection(TARGET)
        pool.return_connection(TARGET, first)
        first.transport._active = False
        second = pool.get_connection(TARGET)
        # First was closed and skipped; second (fresh) is returned.
        assert second is not first
        assert first.closed is True
        assert len(pool._idle_by_target[TARGET]) == 0

    def test_creates_fresh_connection_after_closing_stale(self, pool: SSHConnectionPool, manager: FakeManager):
        first = pool.get_connection(TARGET)
        pool.return_connection(TARGET, first)
        first.transport._active = False
        second = pool.get_connection(TARGET)
        assert second is manager.clients[1]
        assert second.closed is False


# ---------------------------------------------------------------------------
# Return (return_connection)
# ---------------------------------------------------------------------------


class TestReturnConnection:
    """return_connection pools healthy clients and closes the rest."""

    def test_returns_healthy_connection_to_idle(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        pool.return_connection(TARGET, client)
        assert pool._active_by_target[TARGET] == 0
        assert len(pool._idle_by_target[TARGET]) == 1
        assert client.closed is False

    def test_closes_unhealthy_connection(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        client.transport._active = False
        pool.return_connection(TARGET, client)
        assert client.closed is True
        assert len(pool._idle_by_target[TARGET]) == 0
        assert pool._active_by_target[TARGET] == 0

    def test_closes_when_idle_pool_at_max(self, manager: FakeManager):
        p = SSHConnectionPool(manager, max_connections_per_target=1)  # type: ignore[arg-type]
        p.register_target(TARGET, TARGET_DICT)
        # Check out two healthy connections before returning either, so the
        # idle deque is still empty when both are active.
        first = p.get_connection(TARGET)
        second = p.get_connection(TARGET)
        # Returning the first fills the idle deque to its max of one.
        p.return_connection(TARGET, first)
        # The idle deque is full, so the second healthy client is closed.
        p.return_connection(TARGET, second)
        assert second.closed is True
        assert len(p._idle_by_target[TARGET]) == 1
        assert p._idle_by_target[TARGET][0].client is first

    def test_active_count_never_goes_negative(self, pool: SSHConnectionPool, manager: FakeManager):
        pool.return_connection(TARGET, FakeClient())
        assert pool._active_by_target[TARGET] == 0

    def test_close_errors_swallowed(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        client.close_raises = True
        client.transport._active = False
        # Must not raise even though close() raises.
        pool.return_connection(TARGET, client)


# ---------------------------------------------------------------------------
# Idle cleanup
# ---------------------------------------------------------------------------


class TestIdleCleanup:
    """_cleanup_idle evicts connections idle past the timeout."""

    def test_evicts_idle_past_timeout(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        pool.return_connection(TARGET, client)
        entry = pool._idle_by_target[TARGET][0]
        # Age the entry beyond the idle timeout.
        with patch("lib.connection_pool.time.monotonic", return_value=entry.last_used_at + pool._idle_timeout_seconds + 1):
            pool._cleanup_idle()
        assert len(pool._idle_by_target[TARGET]) == 0
        assert client.closed is True

    def test_keeps_recent_idle_connection(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        pool.return_connection(TARGET, client)
        entry = pool._idle_by_target[TARGET][0]
        with patch("lib.connection_pool.time.monotonic", return_value=entry.last_used_at + pool._idle_timeout_seconds - 1):
            pool._cleanup_idle()
        assert len(pool._idle_by_target[TARGET]) == 1
        assert client.closed is False

    def test_cleanup_loop_stops_on_stop_event(self, pool: SSHConnectionPool):
        pool._stop_event.set()
        pool._cleanup_loop()
        # No exception and the loop exits immediately.


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    """stats() aggregates counters across targets."""

    def test_initial_stats(self, pool: SSHConnectionPool):
        assert pool.stats() == {
            "active_connections": 0,
            "idle_connections": 0,
            "total_created": 0,
            "max_connections_per_target": DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
            "idle_timeout_seconds": DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
        }

    def test_stats_reflect_active_and_idle(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        stats = pool.stats()
        assert stats["active_connections"] == 1
        assert stats["total_created"] == 1
        pool.return_connection(TARGET, client)
        stats = pool.stats()
        assert stats["active_connections"] == 0
        assert stats["idle_connections"] == 1
        assert stats["total_created"] == 1

    def test_stats_aggregate_across_targets(self, manager: FakeManager):
        p = SSHConnectionPool(manager)  # type: ignore[arg-type]
        other = {"host": "other-host", "port": 22}
        p.register_target(TARGET, TARGET_DICT)
        p.register_target("other:22", other)
        p.get_connection(TARGET)
        p.get_connection("other:22")
        p.get_connection("other:22")
        stats = p.stats()
        assert stats["active_connections"] == 3
        assert stats["total_created"] == 3


# ---------------------------------------------------------------------------
# close_all & lifecycle
# ---------------------------------------------------------------------------


class TestCloseAllAndLifecycle:
    """close_all, start and stop are safe and idempotent."""

    def test_close_all_closes_idle_and_resets(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        pool.return_connection(TARGET, client)
        pool.close_all()
        assert client.closed is True
        assert len(pool._idle_by_target[TARGET]) == 0
        assert pool._active_by_target[TARGET] == 0
        assert pool._created_by_target[TARGET] == 0

    def test_start_then_stop(self, pool: SSHConnectionPool):
        pool.start()
        assert pool._cleanup_thread is not None
        assert pool._cleanup_thread.is_alive()
        pool.stop()
        assert pool._cleanup_thread is None
        assert pool._stop_event.is_set()

    def test_stop_safe_before_start(self, pool: SSHConnectionPool):
        pool.stop()
        pool.stop()  # second call must not raise

    def test_start_is_idempotent(self, pool: SSHConnectionPool):
        pool.start()
        thread = pool._cleanup_thread
        pool.start()
        assert pool._cleanup_thread is thread

    def test_stop_closes_idle_connections(self, pool: SSHConnectionPool, manager: FakeManager):
        client = pool.get_connection(TARGET)
        pool.return_connection(TARGET, client)
        pool.stop()
        assert client.closed is True


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Concurrent get/return must not corrupt per-target state."""

    def test_concurrent_get_and_return(self, manager: FakeManager):
        p = SSHConnectionPool(manager, max_connections_per_target=8)  # type: ignore[arg-type]
        p.register_target(TARGET, TARGET_DICT)

        errors: list[Exception] = []

        def worker(_: int) -> None:
            try:
                for _ in range(20):
                    client = p.get_connection(TARGET)
                    p.return_connection(TARGET, client)
            except Exception as exc:  # pragma: no cover - only on failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == []
        stats = p.stats()
        assert stats["active_connections"] == 0
        assert stats["idle_connections"] <= 8
        assert stats["total_created"] >= 1


# ---------------------------------------------------------------------------
# Metrics integration
# ---------------------------------------------------------------------------


class TestPoolMetrics:
    """Pool operations update the mcpssh_pool_* Prometheus metrics.

    Each test registers a fresh pool against its own unique target label so
    assertions are isolated from other tests sharing the module-level
    registry (same convention as tests/test_metrics.py).
    """

    def test_created_counter_increments(self, manager: FakeManager):
        target = "unit-test-pool-metric-created"
        p = SSHConnectionPool(manager)  # type: ignore[arg-type]
        p.register_target(target, TARGET_DICT)
        p.get_connection(target)
        value = REGISTRY.get_sample_value(
            "mcpssh_pool_created_total", {"target": target}
        )
        assert value == 1.0

    def test_idle_gauge_tracks_idle_connections(self, manager: FakeManager):
        target = "unit-test-pool-metric-idle"
        p = SSHConnectionPool(manager)  # type: ignore[arg-type]
        p.register_target(target, TARGET_DICT)
        client = p.get_connection(target)
        p.return_connection(target, client)
        idle = REGISTRY.get_sample_value(
            "mcpssh_pool_idle_connections", {"target": target}
        )
        active = REGISTRY.get_sample_value(
            "mcpssh_pool_active_connections", {"target": target}
        )
        assert idle == 1.0
        assert active == 0.0


# ---------------------------------------------------------------------------
# PooledConnection dataclass
# ---------------------------------------------------------------------------


class TestPooledConnection:
    """PooledConnection carries client and timing metadata."""

    def test_dataclass_fields(self):
        client = FakeClient()
        entry = PooledConnection(client=client, created_at=1.0, last_used_at=2.0)
        assert entry.client is client
        assert entry.created_at == 1.0
        assert entry.last_used_at == 2.0
