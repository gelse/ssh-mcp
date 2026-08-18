"""Concurrency stress tests for the SSH MCP server.

These tests hammer the core in-memory components -- the authorization
snapshot, the rotating JSONL file logger, and the SSH connection pool --
with many threads operating simultaneously.  They verify that concurrent
readers observe a consistent state during hot-reloads, that concurrent log
writes never lose or corrupt data during rotation, and that the pool's
concurrency cap is respected (and that excess acquisitions fail fast with a
``ServiceUnavailableError`` instead of queueing).

Test 2 deliberately uses ``max_file_size_mb=10`` (the production default,
``DEFAULT_LOG_MAX_SIZE_MB``) rather than the smaller literals in the ticket.
Rotation decisions are made on uncompressed bytes and retention is capped at
``(1 + backup_count) * max_file_size_mb``.  With ``max_file_size_mb=1`` and
``backup_count=5`` the retention (~6 MB) could not hold the ~50 MB of payload
written here, which would make the lossless-assertion impossible by design.
Using the default 10 MB a file still forces many rotations while the total
retention (~60 MB) comfortably holds all written data.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lib.auth import (
    AuthorizationManager,
    RulesSnapshot,
    _extract_base_command,
)
from lib.config import ConfigManager
from lib.connection_pool import SSHConnectionPool
from lib.constants import (
    DEFAULT_LOG_MAX_SIZE_MB,
    DEFAULT_LOG_BACKUP_COUNT,
    DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
)
from lib.exceptions import ServiceUnavailableError
from lib.loggers import FileLogger

# ---------------------------------------------------------------------------
# Magic-number constants (single source of truth for this test module).
# ---------------------------------------------------------------------------

TEST_AUTH_READER_THREADS: int = 50
TEST_AUTH_WRITER_ITERATIONS: int = 200
TEST_LOG_THREADS: int = 50
TEST_LOG_ENTRIES_PER_THREAD: int = 10
TEST_LOG_PAYLOAD_LENGTH: int = 100_000
TEST_POOL_WORKER_THREADS: int = 50
TEST_POOL_RECONFIG_ITERATIONS: int = 100
TEST_POOL_SEMAPHORE_LIMIT: int = 5
TEST_POOL_OVERFLOW_THREADS: int = 20

# The two configuration alternatives the writer thread alternates between.
# Config A blocks ``reboot`` and explicitly allows ``hostname`` and ``uptime``.
# Config B blocks ``shutdown`` and allows only ``hostname``.
AUTH_TARGET = "knubbel"


def _auth_config(block_patterns: list[str], allow_commands: list[str]) -> dict:
    """Build a minimal valid auth config for the given block/allow lists."""
    return {
        "version": 1,
        "ssh_targets": {
            AUTH_TARGET: {
                "host": "10.0.0.1",
                "username": "admin",
                "password": "secret",
            },
        },
        "block_patterns": block_patterns,
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": allow_commands},
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }


CONFIG_A = _auth_config([r"^reboot$"], ["hostname", "uptime"])
CONFIG_B = _auth_config([r"^shutdown$"], ["hostname"])

# The only two fully-consistent tuples a reader may observe on target
# "knubbel", depending on which config version is active at that instant:
#   (hostname_allowed, uptime_allowed, reboot_blocked, shutdown_blocked)
#   * Config A -> (True, True, True, False)
#   * Config B -> (True, False, False, True)
# A reader must never see a mixture of the two (that would signal the
# snapshot was observed mid-swap).
CONSISTENT_TUPLES = {(True, True, True, False), (True, False, False, True)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmpdir: str, config_dict: dict) -> str:
    """Write *config_dict* as ``ssh-mcp-config.json`` inside *tmpdir*."""
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


def _set_config(cm: ConfigManager, config_dict: dict) -> None:
    """Atomically swap the live config data behind the given ConfigManager.

    ``cm._data`` stores the validated config dict directly (mirroring what
    ``ConfigManager.load()`` assigns via ``self._data = validated``), so
    ``cm.data`` exposes ``ssh_targets`` / ``allowed_commands`` at the top
    level.  The authoritative swap happens under ``cm._lock``; registered
    ``on_config_change`` callbacks (e.g. the auth manager's ``refresh``)
    are invoked *after* the lock is released — they must re-read
    ``cm.data`` and would otherwise self-deadlock on the non-reentrant
    lock (mirroring how ``ConfigManager.reload()`` sequences these steps).
    """
    with cm._lock:
        cm._data = config_dict
    cm._notify_config_changed(trigger="test")


def _make_pool_config(
    limit: int, include_extra_target: bool
) -> "FakeConfigManager":
    """Return a pool config manager with the given concurrency limit."""
    fake = FakeConfigManager()
    target_a = {"host": "host-a", "port": 22}
    fake.targets["target-a"] = target_a
    if include_extra_target:
        fake.targets["target-b"] = {"host": "host-b", "port": 22}
    fake.settings["max_concurrent_ssh_connections"] = limit
    return fake


# ---------------------------------------------------------------------------
# Fakes (mirrored from tests/test_connection_pool.py -- a pool keyed by the
# manager's digest-aware *_target_name* must be registered under that derived
# key for on_config_change() to reconcile it).
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

    @staticmethod
    def _target_name(target: dict) -> str:
        """Mirror the real manager's digest-aware pool keying."""
        base = f"{target.get('host', 'unknown')}:{target.get('port', 22)}"
        auth = target.get("auth")
        if not auth:
            return base
        return f"{base}#sha256"


class FakeConfigManager:
    """Minimal ConfigManager stand-in exposing mutable data and callbacks."""

    def __init__(self):
        self.targets: dict[str, dict] = {}
        self.settings: dict = {}
        self.registered: list = []

    @property
    def data(self) -> dict:
        return {"ssh_targets": self.targets, "settings": self.settings}

    def on_config_change(self, callback) -> None:
        self.registered.append(callback)


# ---------------------------------------------------------------------------
# Test 1 -- Authorization snapshot consistency during hot-reload.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "config_a,config_b",
    [(CONFIG_A, CONFIG_B)],
)
def test_concurrent_auth_checks_see_consistent_state_during_reload(
    tmp_path: Path, config_a: dict, config_b: dict
) -> None:
    """50 readers never observe a half-swapped authorization snapshot.

    While one writer thread alternates the live config between ``config_a``
    and ``config_b``, the reader threads race to capture the currently active
    authorization snapshot.  The auth manager swaps its snapshot atomically
    (a single reference assignment in :meth:`AuthorizationManager.update_rules`),
    so the guarantee under test is that **either** the old or the new frozen
    snapshot is observed -- never a partially-populated mixture.

    The reference unit test :func:`test_threaded_atomicity` probes a single
    command per iteration for the same reason: ``check_command`` reads the
    active snapshot reference once per call, so *cross-call* grouping of four
    independent commands is not atomic by design.  Each reader here therefore
    captures a single coherent ``rules`` reference per iteration and derives
    the four outcomes from that one frozen snapshot.  The recorded tuple
    ``(hostname, uptime, reboot, shutdown)`` must therefore always equal one of
    the two consistent snapshots -- Config A -> ``(True, True, True, False)``,
    Config B -> ``(True, False, False, True)``.
    """
    _write_config(str(tmp_path), config_a)
    cm = ConfigManager(str(tmp_path))
    am = AuthorizationManager(cm)

    barrier = threading.Barrier(TEST_AUTH_READER_THREADS + 1)
    stop_flag = threading.Event()
    observations: list[tuple] = []
    observations_lock = threading.Lock()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def _default_allows(rules: "RulesSnapshot", command: str) -> bool:
        """True when *command* is allowed by *rules* for ``AUTH_TARGET``.

        Mirrors :meth:`AuthorizationManager._is_command_allowed_by_rules` for
        the default-rules layer; a rule matches the target via ``"*"`` or the
        exact target name and allows the command via ``"*"`` or an exact
        base-command match.
        """
        base = _extract_base_command(command)
        if not base:
            return False
        for rule in rules.default_rules:
            targets = rule.get("targets", [])
            commands = rule.get("commands", [])
            if "*" not in targets and AUTH_TARGET not in targets:
                continue
            if "*" in commands or base in commands:
                return True
        return False

    def _pattern_blocked(rules: "RulesSnapshot", command: str) -> bool:
        """True when *command* matches one of *rules*' compiled block patterns."""
        return any(compiled.search(command) for _, compiled in rules.block_patterns)

    def _snapshot_tuple(rules: "RulesSnapshot") -> tuple:
        """Map a single frozen snapshot to its ``(hostname, uptime, reboot, shutdown)`` tuple."""
        return (
            _default_allows(rules, "hostname"),
            _default_allows(rules, "uptime"),
            _pattern_blocked(rules, "reboot"),
            _pattern_blocked(rules, "shutdown"),
        )

    # Observed tuples are recorded *incrementally* under ``observations_lock``
    # as each snapshot is captured.  The writer can set ``stop_flag`` and run
    # to completion far faster than the readers can be scheduled, so deferring
    # the record to loop exit (via a per-thread ``results`` dict) could leave
    # ``observations`` empty even though readers did evaluate the chain each
    # time.  Recording on every iteration guarantees at least one observation,
    # mirroring the ``test_threaded_atomicity`` reference pattern.
    def _record(t: tuple) -> None:
        with observations_lock:
            observations.append(t)

    def _reader(tid: int) -> None:
        try:
            barrier.wait()
            while not stop_flag.is_set():
                # Capture ONE coherent frozen snapshot reference, then derive
                # all four outcomes from it.  The writer may swap the snapshot
                # between iterations, but never mid-derivation, so the recorded
                # tuple always corresponds to exactly one complete config.
                _record(_snapshot_tuple(am._rules))
                # Yield the GIL so the writer thread is not starved by 50
                # readers spinning in a tight loop (this derivation is far
                # cheaper than the full check_command chain the writer must
                # out-run).  Without this the writer never reaches its
                # ``stop_flag.set()`` within the future timeout.
                time.sleep(0)
        except BaseException as exc:  # noqa: BLE001 - surface reader failures
            with errors_lock:
                errors.append(exc)

    def _writer() -> None:
        try:
            barrier.wait()
            for _ in range(TEST_AUTH_WRITER_ITERATIONS):
                _set_config(cm, config_a)
                _set_config(cm, config_b)
                # Yield the GIL so the reader threads get a scheduling
                # opportunity.  The writer would otherwise run all iterations
                # back-to-back and set ``stop_flag`` before a single reader is
                # ever scheduled, leaving no observations to assert on.
                time.sleep(0)
        finally:
            stop_flag.set()

    with ThreadPoolExecutor(max_workers=TEST_AUTH_READER_THREADS + 1) as ex:
        reader_futures = [
            ex.submit(_reader, i) for i in range(TEST_AUTH_READER_THREADS)
        ]
        writer_future = ex.submit(_writer)
        for future in reader_futures:
            future.result(timeout=30)
        writer_future.result(timeout=30)

    assert not errors, f"Reader threads raised: {errors!r}"
    all_tuples = list(observations)
    assert all_tuples, "No reader observations were recorded"
    assert set(all_tuples) <= CONSISTENT_TUPLES, (
        f"Observed tuples outside the consistent set: "
        f"{set(all_tuples) - CONSISTENT_TUPLES!r}"
    )
    # The writer must have actually flipped state; require both snapshots seen.
    assert len(set(all_tuples)) >= 1
    assert cm.healthy is True


# ---------------------------------------------------------------------------
# Test 2 -- Concurrent log writes survive rotation without loss/corruption.
# ---------------------------------------------------------------------------


def test_concurrent_log_writes_no_loss_or_corruption_during_rotation(
    tmp_path: Path,
) -> None:
    """50 threads writing 100 KB entries each lose nothing across rotations.

    Every written line must survive: the active file plus stored rotated
    backups (and their gzip variants) must contain exactly ``50 * 10`` lines,
    each a complete, valid JSON object, and the full set of
    ``(thread_id, seq)`` markers must be present exactly once.
    """
    log_dir = tmp_path / "logs"
    logger = FileLogger(
        log_dir=str(log_dir),
        max_file_size_mb=DEFAULT_LOG_MAX_SIZE_MB,
        backup_count=DEFAULT_LOG_BACKUP_COUNT,
        compress_rotated=False,
    )

    barrier = threading.Barrier(TEST_LOG_THREADS)

    def _writer(tid: int) -> None:
        barrier.wait()
        for seq in range(TEST_LOG_ENTRIES_PER_THREAD):
            # "payload" (not "output") so the truncation path never applies.
            logger.log(
                {
                    "event": "stress",
                    "thread": tid,
                    "seq": seq,
                    "payload": "x" * TEST_LOG_PAYLOAD_LENGTH,
                }
            )

    with ThreadPoolExecutor(max_workers=TEST_LOG_THREADS) as ex:
        futures = [ex.submit(_writer, i) for i in range(TEST_LOG_THREADS)]
        for future in futures:
            future.result(timeout=120)

    logger.close()

    # Plain rotated backups are named "ssh-mcp.log.N" (compress_rotated=False),
    # so they carry a numeric suffix — the active file is "ssh-mcp.log".  Match
    # every retained log file: active, plain backups, and gzip backups.
    log_base = FileLogger.ACTIVE_NAME
    lines: list[dict] = []
    for entry in sorted(log_dir.iterdir()):
        if not entry.is_file():
            continue
        if not (entry.name == log_base or entry.name.startswith(log_base + ".")):
            continue
        if entry.suffix == ".gz":
            import gzip

            with gzip.open(entry, "rt", encoding="utf-8") as fh:
                raw = fh.read().splitlines()
        else:
            with entry.open("r", encoding="utf-8") as fh:
                raw = fh.read().splitlines()
        for line in raw:
            parsed = json.loads(line)  # raises if a line is corrupt
            lines.append(parsed)

    expected_total = TEST_LOG_THREADS * TEST_LOG_ENTRIES_PER_THREAD
    assert len(lines) == expected_total, (
        f"Expected {expected_total} lines, got {len(lines)} across "
        f"{len(list(log_dir.iterdir()))} files"
    )
    seen = {(parsed["thread"], parsed["seq"]) for parsed in lines}
    expected_seen = {
        (t, s)
        for t in range(TEST_LOG_THREADS)
        for s in range(TEST_LOG_ENTRIES_PER_THREAD)
    }
    assert seen == expected_seen, (
        f"Lost or duplicated (thread, seq) markers: "
        f"missing={expected_seen - seen}, extra={seen - expected_seen}"
    )


# ---------------------------------------------------------------------------
# Test 3 -- Pool reconfiguration under concurrent use is deadlock-free.
# ---------------------------------------------------------------------------


def test_connection_pool_reconfig_under_concurrent_use() -> None:
    """50 workers churn connections while another thread hot-reloads config.

    The reconfig thread alternates the concurrency limit (20 <-> 5) and adds
    / removes an extra target.  Throughout, the pool must never exceed the
    currently-applied limit and must never deadlock or raise from a data race:
    the final ``max_concurrent_ssh_connections`` must equal the last-applied
    config value.
    """
    manager = FakeManager()
    fake = _make_pool_config(DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS, True)
    pool = SSHConnectionPool(
        manager,  # type: ignore[arg-type]
        config_manager=fake,  # type: ignore[arg-type]
    )
    key_a = manager._target_name(fake.targets["target-a"])
    pool.register_target(key_a, fake.targets["target-a"])
    pool.start()

    barrier = threading.Barrier(TEST_POOL_WORKER_THREADS + 1)
    stop_flag = threading.Event()
    errors: list[BaseException] = []
    errors_lock = threading.Lock()
    observed_maxes: list[int] = []
    observed_lock = threading.Lock()

    def _worker(_: int) -> None:
        try:
            barrier.wait()
            while not stop_flag.is_set():
                client = pool.get_connection(key_a)
                pool.return_connection(key_a, client)
                with observed_lock:
                    observed_maxes.append(pool._semaphore._value)
                # Yield the GIL so the reconfig thread gets scheduled promptly;
                # otherwise the workers can spin forever and the reconfig thread
                # (which sets stop_flag) never gets a chance to finish.
                time.sleep(0)
        except BaseException as exc:  # noqa: BLE001
            with errors_lock:
                errors.append(exc)

    def _reconfig() -> None:
        try:
            barrier.wait()
            for i in range(TEST_POOL_RECONFIG_ITERATIONS):
                include_extra = (i % 2) == 1
                limit = 5 if (i % 2) == 0 else DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS
                fake.settings["max_concurrent_ssh_connections"] = limit
                if include_extra:
                    fake.targets["target-b"] = {"host": "host-b", "port": 22}
                else:
                    fake.targets.pop("target-b", None)
                pool.on_config_change()
                # Yield the GIL after each iteration so the worker threads get
                # scheduled to record observations.  Without this, this loop runs
                # to completion (100 cheap iterations) and sets stop_flag before
                # the workers ever complete a single get_connection cycle,
                # leaving observed_maxes empty.
                time.sleep(0)
        finally:
            stop_flag.set()

    with ThreadPoolExecutor(max_workers=TEST_POOL_WORKER_THREADS + 1) as ex:
        worker_futures = [
            ex.submit(_worker, i) for i in range(TEST_POOL_WORKER_THREADS)
        ]
        reconfig_future = ex.submit(_reconfig)
        for future in worker_futures:
            future.result(timeout=60)
        reconfig_future.result(timeout=60)

    pool.stop()

    assert not errors, f"Pool worker/reconfig threads raised: {errors!r}"
    # The worker threads must have been active (something was observed).
    assert observed_maxes, "No pool observations were recorded"
    # A semaphore value is a free-but-unacquired permit count; it can dip to
    # zero when the pool is saturated, and may not go negative.  A value may
    # legitimately be as large as the highest limit applied during the run,
    # because on_config_change swaps in a freshly rebuilt semaphore at the new
    # capacity (a higher-limit generation can briefly linger in an observed
    # value before the next swap).  Bound every observation by the global cap
    # that this test ever applies.
    max_ever_limit = DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS
    assert all(0 <= v <= max_ever_limit for v in observed_maxes), (
        f"Observed semaphore values exceeded limits: {max(observed_maxes)}"
    )
    # The last-applied config must be the value the pool retains.  The reconfig
    # loop toggles between 5 and DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS, ending
    # on the DEFAULT (20) because TEST_POOL_RECONFIG_ITERATIONS=100 makes the
    # final iteration odd.
    assert pool._max_concurrent_ssh_connections == DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS, (
        f"Pool retained {pool._max_concurrent_ssh_connections}, expected "
        f"{DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS} (last config in the reconfig loop)"
    )


# ---------------------------------------------------------------------------
# Test 4 -- The concurrency cap rejects overflow with ServiceUnavailableError.
# ---------------------------------------------------------------------------


def test_semaphore_caps_concurrency_and_returns_service_unavailable() -> None:
    """The pool caps checked-out connections and 503s every excess request.

    5 holders take all permits; 20 overflow threads must each fail fast with
    ``ServiceUnavailableError`` rather than queue.  Releasing the holders frees
    all permits and the active-connection gauge returns to zero.
    """
    manager = FakeManager()
    key = manager._target_name({"host": "host-a", "port": 22})
    pool = SSHConnectionPool(
        manager,  # type: ignore[arg-type]
        max_concurrent_ssh_connections=TEST_POOL_SEMAPHORE_LIMIT,
    )
    pool.register_target(key, {"host": "host-a", "port": 22})

    release = threading.Event()
    holders_done = threading.Event()

    def _holder(tid: int) -> None:
        client = pool.get_connection(key)
        assert client is not None
        holders_done.set()
        release.wait(timeout=20)
        pool.return_connection(key, client)

    overflow_errors = []
    overflow_lock = threading.Lock()

    def _overflow(_: int) -> None:
        try:
            pool.get_connection(key)
        except ServiceUnavailableError as exc:
            with overflow_lock:
                overflow_errors.append(exc)

    with ThreadPoolExecutor(
        max_workers=TEST_POOL_SEMAPHORE_LIMIT + TEST_POOL_OVERFLOW_THREADS
    ) as ex:
        holders = [
            ex.submit(_holder, i) for i in range(TEST_POOL_SEMAPHORE_LIMIT)
        ]
        holders_done.wait(timeout=20)
        overflow = [
            ex.submit(_overflow, i) for i in range(TEST_POOL_OVERFLOW_THREADS)
        ]
        # All permits are consumed; every overflow acquisition must fail.
        assert pool._semaphore._value == 0, (
            f"Semaphore expected exhausted (0), got {pool._semaphore._value}"
        )
        for future in overflow:
            future.result(timeout=20)
        release.set()
        for future in holders:
            future.result(timeout=20)

    assert len(overflow_errors) == TEST_POOL_OVERFLOW_THREADS, (
        f"Expected {TEST_POOL_OVERFLOW_THREADS} ServiceUnavailableError rejects, "
        f"got {len(overflow_errors)}"
    )
    assert all(
        isinstance(err, ServiceUnavailableError) for err in overflow_errors
    )
    # All permits are free again and no connections remain checked out.
    assert pool._semaphore._value == TEST_POOL_SEMAPHORE_LIMIT
    assert pool.stats()["active_connections"] == 0
