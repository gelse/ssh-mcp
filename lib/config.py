"""ConfigManager: loading, validation, and default creation for SSH MCP config.

Provides a thread-safe ConfigManager that loads a JSON config file,
validates it against a strict schema, applies defaults, and exposes
query methods for SSH targets.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Callable

from lib.config_migration import (
    backup_config_file,
    migrate_config,
    write_migrated_config,
)
from lib.constants import (
    DEFAULT_BLOCK_PATTERNS,
    DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_LOG_OUTPUT,
    DEFAULT_MAX_OUTPUT_LENGTH,
    DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
    DEFAULT_RATE_LIMIT_ENABLED,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
    DEFAULT_RETRY_MAX_ATTEMPTS,
    DEFAULT_SSH_PORT,
    DEFAULT_TRUSTED_PROXIES,
    DEFAULT_MAX_SFTP_PATH_LENGTH,
    DEFAULT_SFTP_SANDBOX_ROOT,
    DEFAULT_WATCHER_DEBOUNCE_SECONDS,
    DEFAULT_WATCHER_INTERVAL_SECONDS,
    LATEST_CONFIG_VERSION,
    LOG_FORMAT_VERSION,
    LOG_LEVELS,
    MAX_BLOCK_PATTERNS,
    MAX_REGEX_PATTERN_LENGTH,
    MAX_TARGET_NAME_LENGTH,
    MAX_TARGETS,
    MCP_SSH_SETTING_PREFIX,
    RESTRICTED_FILE_MODE,
    TARGET_NAME_PATTERN,
    SETTING_KEY_TYPES,
)
from lib.exceptions import (
    ConfigMigrationError,
    ConfigValidationError,
    SecretsError,
)
from lib.redos_protection import check_redos_risk, compile_safe_pattern
from lib.secrets import SecretsManager
from lib.size_utils import parse_size_bytes
from lib.types import SSHTarget

logger = logging.getLogger(__name__)


def build_default_config() -> dict:
    """Return a minimal-but-valid default configuration as a plain dict.

    The emitted config is intended to illustrate the config schema and to be
    dumped via the ``--print-default-config`` CLI flag.  It deliberately ships a
    single placeholder SSH target and a single default command-allowance rule so
    it passes :meth:`ConfigManager._validate` (which requires both to be
    non-empty); operators are expected to replace the placeholder with their own
    targets and rules before use.

    Returns:
        A JSON-serializable dict matching the validated config shape, with all
        magic values drawn from :mod:`lib.constants`.
    """
    return {
        "version": LATEST_CONFIG_VERSION,
        "ssh_targets": {
            "example-server": {
                "host": "example.com",
                "port": DEFAULT_SSH_PORT,
                "username": "ubuntu",
                "password": "CHANGE_ME",
            }
        },
        "block_patterns": list(DEFAULT_BLOCK_PATTERNS),
        "allowed_commands": {
            "default": [
                {
                    "targets": ["*"],
                    "commands": ["echo", "whoami", "hostname"],
                }
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": DEFAULT_MAX_OUTPUT_LENGTH,
            "command_timeout_max": DEFAULT_COMMAND_TIMEOUT_SECONDS,
            "max_concurrent_ssh_connections": DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
        },
    }


class ConfigManager:
    """Loads, validates, and provides access to the SSH MCP configuration.

    The config file is expected at ``<config_dir>/ssh-mcp-config.json``.
    If the file does not exist on first load, a default is copied from
    the project root's ``default-config.json``.

    All public reads return shallow copies so callers cannot mutate
    internal state.

    Thread safety
    -------------
    ``ConfigManager`` guards its mutable state with two ``threading.Lock``
    objects, never both held at once:

    * ``_lock`` serialises the authoritative snapshot swap (``self._data``,
      ``self._targets_by_name``) and the health-state fields
      (``_last_error``, ``_last_reload_timestamp``, ``_last_mtime``,
      ``_last_reload_monotonic``).
    * ``_callbacks_lock`` guards the ``_callbacks`` registry during
      add/remove/iteration.

    Reads use the single-reference-read pattern: ``self._data`` is replaced
    atomically (a CPython reference assignment) under ``_lock``, so readers
    that hold the reference observe one fully-validated configuration and
    never a half-mutated dict.  The ``data`` property returns a **shallow**
    copy; callers must treat the nested ``ssh_targets`` / ``allowed_commands``
    / ``settings`` structures as read-only (do not mutate them in place).
    Lock-free reads: ``config_path`` and ``secrets_path`` (immutable
    ``Path`` values set in ``__init__``).
    """

    def __init__(self, config_dir: str, logger=None, fix_permissions: bool = False):
        """
        Args:
            config_dir: Directory containing ``ssh-mcp-config.json``.
            logger: Optional :class:`~lib.loggers.BaseLogger` instance for
                    structured config-reload events.  When ``None``,
                    structured events are silently skipped.
            fix_permissions: When ``True``, chmod the config and secrets
                    files to ``RESTRICTED_FILE_MODE`` after loading if they
                    are group/world readable.
        """
        self._config_dir = Path(config_dir)
        self._config_path = self._config_dir / DEFAULT_CONFIG_FILENAME
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[], None]] = []
        self._callbacks_lock = threading.Lock()
        self.secrets_manager = SecretsManager(config_dir, logger=logger)
        self._data: dict = {}
        self._targets_by_name: dict[str, SSHTarget] = {}
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop_event = threading.Event()
        self._watcher_is_observer: bool = False
        self._last_mtime: float = 0.0
        self._last_reload_monotonic: float = float("-inf")
        self._logger = logger
        self._last_reload_timestamp: str | None = None
        self._last_error: str | None = None
        self.load()
        if fix_permissions:
            self.fix_permissions()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        """Path to the active configuration file."""
        return self._config_path

    @property
    def secrets_path(self) -> Path:
        """Path to the active secrets file."""
        return self.secrets_manager.secrets_path

    @property
    def data(self) -> dict:
        """Shallow copy of the validated, normalized configuration."""
        with self._lock:
            return self._data.copy()

    @property
    def last_reload_timestamp(self) -> str | None:
        """ISO-8601 timestamp of the last successful config load/reload."""
        with self._lock:
            return self._last_reload_timestamp

    @property
    def last_error(self) -> str | None:
        """Message of the most recent failed load/reload, or None."""
        with self._lock:
            return self._last_error

    @property
    def healthy(self) -> bool:
        """True when the last config load/reload succeeded.

        ``healthy`` is False after a failed reload (the previous config is
        preserved) and True again once a reload succeeds.
        """
        with self._lock:
            return self._last_error is None

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def load(self) -> dict:
        """Load config from disk, validate, and store internally.

        Precedence for merged values is env vars > secrets.json >
        config.json > defaults.  Returns the validated dict.
        """
        if not self._config_path.exists():
            self._ensure_default_config()
            if not self._config_path.exists():
                raise RuntimeError(
                    "Default config creation failed — "
                    f"'{self._config_path}' still does not exist"
                )

        self._check_file_permissions(self._config_path)
        raw = self._read_json()
        raw = self._migrate_if_needed(raw)
        raw = self.secrets_manager.merge(raw)
        raw = self._apply_setting_overrides(raw)
        validated = self._validate(raw)

        with self._lock:
            self._data = validated
            self._targets_by_name = dict(validated.get("ssh_targets", {}))
            self._last_mtime = os.path.getmtime(self._config_path)
            self._record_success_locked()

        logger.info("Config loaded from %s", self._config_path)
        self._log_config_event(
            "config.load",
            True,
            "Configuration loaded successfully",
            target_count=len(validated.get("ssh_targets", {})),
        )
        return validated

    def reload(self, trigger: str = "manual") -> bool:
        """Re-read the config file and atomically replace in-memory data.

        Args:
            trigger: Source of the reload — ``"manual"``, ``"watchdog"``
                or ``"polling"`` — included in the structured event.

        Returns ``True`` if the reload succeeded, ``False`` if validation
        failed (the existing data is preserved).
        """
        try:
            self._check_file_permissions(self._config_path)
            raw = self._read_json()
            raw = self._migrate_if_needed(raw)
            raw = self.secrets_manager.merge(raw)
            raw = self._apply_setting_overrides(raw)
        except (
            json.JSONDecodeError,
            OSError,
            SecretsError,
            ConfigMigrationError,
        ) as exc:
            logger.error("Failed to read config for reload: %s", exc)
            with self._lock:
                self._last_error = f"Failed to read config: {exc}"
            self._log_config_event(
                "config.reload",
                False,
                f"Failed to read config: {exc}",
                trigger=trigger,
            )
            return False

        try:
            validated = self._validate(raw)
        except ConfigValidationError as exc:
            logger.error("Reload validation failed — keeping existing config: %s", exc)
            with self._lock:
                self._last_error = f"Config validation failed: {exc}"
            self._log_config_event(
                "config.reload",
                False,
                f"Config validation failed: {exc}",
                trigger=trigger,
            )
            return False

        with self._lock:
            previous = self._data
            self._data = validated
            self._targets_by_name = dict(validated.get("ssh_targets", {}))
            self._last_mtime = os.path.getmtime(self._config_path)
            self._record_success_locked()

        logger.info("Config reloaded from %s", self._config_path)
        changes = self._compute_changes(previous, validated)
        self._log_config_event(
            "config.reload",
            True,
            "Configuration reloaded successfully",
            trigger=trigger,
            **changes,
        )
        self._notify_config_changed(trigger)
        return True

    def on_config_change(self, callback: Callable[[], None]) -> None:
        """Register *callback* to run after each successful config reload.

        The callback takes no arguments; it should read fresh state via
        :attr:`data` rather than capturing a config reference.  Callbacks are
        not invoked on initial :meth:`load` nor on failed reloads.  A callback
        that raises is logged and isolated — it does not affect other callbacks
        or the reload result.

        Args:
            callback: Zero-argument callable to notify on reload.
        """
        with self._callbacks_lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)


    def unregister_config_change_callback(self, callback: Callable[[], None]) -> None:
        """Remove a previously-registered callback.  No-op if not registered.

        Args:
            callback: The callable previously passed to :meth:`on_config_change`.
        """
        with self._callbacks_lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def _check_file_permissions(self, path: Path) -> None:
        """Warn via a ``config.permissions_insecure`` event if *path* is unsafe.

        Group/world read or write bits on the config file are non-fatal but
        reported at ``WARNING``.  Guarded against the file being removed.
        """
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            return

        if mode & 0o077:
            self._log_config_event(
                "config.permissions_insecure",
                False,
                f"Config file '{path}' permissions are too permissive "
                f"(mode {mode:o}); expected {RESTRICTED_FILE_MODE:o}",
                mode=oct(mode),
                expected_mode=oct(RESTRICTED_FILE_MODE),
                log_level="WARNING",
            )

    def fix_permissions(self) -> list[Path]:
        """Chmod config and secrets files to ``RESTRICTED_FILE_MODE``.

        Returns the list of paths whose mode was changed.
        """
        changed: list[Path] = []
        for path in (self._config_path, self.secrets_manager.secrets_path):
            if not path.exists():
                continue
            try:
                mode = os.stat(path).st_mode & 0o777
            except OSError:
                continue
            if mode & 0o077:
                os.chmod(path, RESTRICTED_FILE_MODE)
                changed.append(path)
                self._log_config_event(
                    "config.permissions_fixed",
                    True,
                    f"Permissions corrected to {RESTRICTED_FILE_MODE:o} for "
                    f"'{path}'",
                    path=str(path),
                    mode=oct(mode),
                    fixed_mode=oct(RESTRICTED_FILE_MODE),
                    log_level="WARNING",
                )
        return changed

    def _record_success_locked(self) -> None:
        """Update health state after a successful load/reload.

        Must be called while holding ``self._lock``.
        """
        import datetime

        self._last_error = None
        self._last_reload_timestamp = (
            datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        self._last_reload_monotonic = time.monotonic()

    def _notify_config_changed(self, trigger: str) -> None:
        """Invoke registered reload callbacks with per-callback error isolation."""
        with self._callbacks_lock:
            callbacks = list(self._callbacks)
        for callback in callbacks:
            try:
                callback()
            except Exception:  # noqa: BLE001 - isolate consumers; never break reload
                logger.exception("Config-change callback failed during reload")
                self._log_config_event(
                    "config.callback_error",
                    False,
                    "A config-change callback raised an exception",
                    trigger=trigger,
                )

    def _log_config_event(self, event: str, success: bool, message: str, **extra) -> None:
        """Emit a structured config event if a logger is configured.

        Every entry carries the active ``config_path`` plus any *extra*
        fields.  Callers must only pass key names and counts — never
        secret values such as passwords or private keys.
        """
        if self._logger is None:
            return
        import datetime

        from lib.request_context import get_request_id

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": event,
            "success": success,
            "message": message,
            "config_path": str(self._config_path),
            "request_id": get_request_id(),
            "log_level": "INFO",
            "log_format_version": LOG_FORMAT_VERSION,
        }
        entry.update(extra)
        self._logger.log(entry)

    def _apply_setting_overrides(self, config: dict) -> dict:
        """Merge ``MCP_SSH_SETTING_*`` env vars into ``config["settings"]``.

        Only keys present in :data:`SETTING_KEY_TYPES` are accepted; the
        values are coerced to the declared type.  Unknown keys and values
        that fail coercion are skipped with a warning event (never raising),
        and the original env-var value is never logged.
        """
        settings = config.setdefault("settings", {})
        if not isinstance(settings, dict):
            settings = {}
            config["settings"] = settings

        prefix = MCP_SSH_SETTING_PREFIX
        for name, value in os.environ.items():
            if not name.startswith(prefix):
                continue
            raw_key = name[len(prefix):]
            key = raw_key.lower()
            if key not in SETTING_KEY_TYPES:
                self._emit_unknown_setting_env_var(raw_key)
                continue
            coerced = self._coerce_setting_value(key, value)
            if coerced is None:
                self._emit_invalid_setting_env_var(raw_key, value)
                continue
            settings[key] = coerced

        return config

    @staticmethod
    def _coerce_setting_value(key: str, value: str) -> int | float | bool | str | None:
        """Coerce an env-var string to the declared ``settings`` type.

        Returns ``None`` when *value* cannot be coerced, so callers can
        warn-and-skip.  ``bool`` accepts the case-insensitive literals
        ``true``/``false``/``1``/``0``/``yes``/``no``/``on``/``off``.
        """
        kind = SETTING_KEY_TYPES.get(key)
        if kind == "int":
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
        if kind == "float":
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
        if kind == "bool":
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "on"}:
                return True
            if normalized in {"false", "0", "no", "off"}:
                return False
            return None
        if kind == "size":
            try:
                return parse_size_bytes(value)
            except ConfigValidationError:
                return None
        return value

    @staticmethod
    def _normalize_trusted_proxy(raw: str) -> str | None:
        """Validate and normalize a trusted-proxy IP string.

        Parses *raw* with :func:`ipaddress.ip_address` and returns the
        canonical string form, collapsing IPv4-mapped IPv6 addresses
        (``::ffff:192.168.1.1``) to plain IPv4 (``192.168.1.1``).  Returns
        ``None`` when *raw* is not a valid IP address at all.
        """
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(addr)

    @staticmethod
    def _normalize_max_output_length(value: object) -> int:
        """Normalize ``settings.max_output_length`` to a positive byte count.

        Accepts a positive ``int`` (used as-is) or a size string understood by
        :func:`parse_size_bytes` (e.g. ``"50kb"``, ``"10mb"``).  Invalid or
        non-positive values raise ``ConfigValidationError``.
        """
        if isinstance(value, bool):  # bool is an int subclass; reject explicitly
            raise ConfigValidationError(
                "'settings.max_output_length' must be an integer or size string",
                field="settings.max_output_length",
            )
        if isinstance(value, int):
            if value < 1:
                raise ConfigValidationError(
                    "'settings.max_output_length' must be an integer >= 1",
                    field="settings.max_output_length",
                )
            return value
        if isinstance(value, str):
            return parse_size_bytes(value)
        raise ConfigValidationError(
            "'settings.max_output_length' must be an integer or size string",
            field="settings.max_output_length",
        )

    def _emit_unknown_setting_env_var(self, raw_key: str) -> None:
        """Emit a warning for an unrecognised ``MCP_SSH_SETTING_*`` var."""
        logger.warning(
            "Ignoring unknown env var %s%s",
            MCP_SSH_SETTING_PREFIX,
            raw_key,
        )
        self._log_config_event(
            "config.setting_env_var",
            False,
            f"Ignoring unknown env var {MCP_SSH_SETTING_PREFIX}{raw_key}",
            setting_key=raw_key.lower(),
            log_level="WARNING",
        )

    def _emit_invalid_setting_env_var(self, raw_key: str, value: str) -> None:
        """Emit a warning for a ``MCP_SSH_SETTING_*`` value that won't coerce.

        Only the key name is logged — never the offending value.
        """
        logger.warning(
            "Ignoring invalid env var %s%s",
            MCP_SSH_SETTING_PREFIX,
            raw_key,
        )
        self._log_config_event(
            "config.setting_env_var",
            False,
            f"Ignoring invalid env var {MCP_SSH_SETTING_PREFIX}{raw_key}",
            setting_key=raw_key.lower(),
            log_level="WARNING",
        )

    @staticmethod
    def _compute_changes(old: dict, new: dict) -> dict:
        """Summarize the differences between two validated configs.

        Only top-level section names, target names, and counts are
        reported — never secret values such as passwords or keys.
        """
        changed_keys = sorted(
            key for key in set(old) | set(new) if old.get(key) != new.get(key)
        )
        old_targets = set(old.get("ssh_targets", {}))
        new_targets = set(new.get("ssh_targets", {}))
        return {
            "changed": bool(changed_keys),
            "changed_keys": changed_keys,
            "targets_added": sorted(new_targets - old_targets),
            "targets_removed": sorted(old_targets - new_targets),
            "target_count": len(new_targets),
        }

    def get_ssh_target(self, target_id: str) -> dict | None:
        """Return the SSH target dict for *target_id*, or ``None``."""
        return self.data.get("ssh_targets", {}).get(target_id)

    def get_target(self, name: str) -> SSHTarget | None:
        """Return the SSH target dict for *name* from the O(1) name index.

        The index is rebuilt on every successful config load/reload, so this
        lookup never scans the full configuration.

        Must not be called while holding ``_callbacks_lock``.
        """
        with self._lock:
            return self._targets_by_name.get(name)

    def list_ssh_targets(self) -> list[str]:
        """Return the list of configured SSH target IDs."""
        return list(self.data.get("ssh_targets", {}).keys())

    # ------------------------------------------------------------------
    # Watcher (hot-reload)
    # ------------------------------------------------------------------

    @property
    def watcher_running(self) -> bool:
        """Return True if the watcher thread is currently active."""
        return self._watcher_thread is not None and self._watcher_thread.is_alive()

    def start_watcher(self, polling_interval: float = DEFAULT_WATCHER_INTERVAL_SECONDS) -> None:
        """Start the config-file watcher for hot-reload.

        Prefers an event-driven ``watchdog`` observer, which receives
        filesystem events instead of polling.  If ``watchdog`` is not
        installed (or cannot be initialized), falls back to a daemon
        polling thread that checks ``os.path.getmtime()`` every
        *polling_interval* seconds.

        Idempotent: calling multiple times has no effect if already
        running.
        """
        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            return

        self._watcher_stop_event.clear()
        self._last_mtime = os.path.getmtime(self._config_path)
        self._last_reload_monotonic = float("-inf")

        try:
            from lib.config_watcher import FileChangeHandler
            from watchdog.observers import Observer

            observer = Observer()
            observer.name = "config-watcher"
            observer.daemon = True
            handler = FileChangeHandler(
                config_path=self._config_path,
                reload_callback=lambda: self.reload(trigger="watchdog"),
                debounce_callback=lambda: self._should_debounce_watchdog(),
                logger=logger,
                log_event=lambda event, success, message: self._log_config_event(
                    event, success, message
                ),
            )
            observer.schedule(handler, str(self._config_dir), recursive=False)
            observer.start()
            self._watcher_thread = observer
            self._watcher_is_observer = True
            logger.info(
                "Config watcher started (watchdog observer, path=%s)",
                self._config_path,
            )
            self._log_config_event(
                "config.watcher.start",
                True,
                "Config watcher started (watchdog observer)",
                mode="watchdog",
                polling_interval=polling_interval,
            )
            return
        except (ImportError, OSError) as exc:
            logger.warning(
                "watchdog unavailable (%s) — falling back to polling "
                "config watcher (interval=%.1fs)",
                exc,
                polling_interval,
            )
            self._watcher_is_observer = False

        self._watcher_thread = threading.Thread(
            target=self._watcher_loop,
            args=(polling_interval,),
            name="config-watcher",
            daemon=True,
        )
        self._watcher_thread.start()
        logger.info(
            "Config watcher started (interval=%.1fs, path=%s)",
            polling_interval,
            self._config_path,
        )
        self._log_config_event(
            "config.watcher.start",
            True,
            "Config watcher started (polling)",
            mode="polling",
            polling_interval=polling_interval,
        )

    def stop_watcher(self) -> None:
        """Stop the config watcher gracefully.

        Stops and joins the watchdog observer (or signals the polling
        thread to exit via a ``threading.Event`` and joins with a
        timeout).  Safe to call if the watcher was never started.
        """
        if self._watcher_is_observer:
            if self._watcher_thread is not None and self._watcher_thread.is_alive():
                stop = getattr(self._watcher_thread, "stop", None)
                if callable(stop):
                    stop()
                self._watcher_thread.join(timeout=20.0)
                if self._watcher_thread.is_alive():
                    logger.warning("Config watcher observer did not exit within timeout")
            self._watcher_thread = None
            self._watcher_is_observer = False
            self._log_config_event(
                "config.watcher.stop",
                True,
                "Config watcher stopped (watchdog observer)",
                mode="watchdog",
            )
            return

        self._watcher_stop_event.set()

        if self._watcher_thread is not None and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=20.0)
            if self._watcher_thread.is_alive():
                logger.warning("Config watcher thread did not exit within timeout")
            self._watcher_thread = None
        self._log_config_event(
            "config.watcher.stop",
            True,
            "Config watcher stopped (polling)",
            mode="polling",
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _watcher_loop(self, polling_interval: float) -> None:
        """Poll ``os.path.getmtime()`` and trigger :meth:`reload` on change."""
        while not self._watcher_stop_event.is_set():
            self._watcher_stop_event.wait(timeout=polling_interval)

            if self._watcher_stop_event.is_set():
                break

            try:
                if not self._config_path.exists():
                    logger.warning(
                        "Config file %s no longer exists — skipping reload",
                        self._config_path,
                    )
                    self._log_config_event(
                        "config.watcher.file_missing",
                        False,
                        "Config file no longer exists — skipping reload",
                    )
                    continue

                current_mtime = os.path.getmtime(self._config_path)
                if current_mtime != self._last_mtime:
                    if self._should_debounce(self._get_watcher_debounce_seconds()):
                        logger.info(
                            "Config change within debounce window — skipping reload"
                        )
                        self._log_config_event(
                            "config.watcher.debounced",
                            True,
                            "Config change within debounce window — skipping reload",
                        )
                        continue
                    logger.info("Config file changed, reloading...")
                    success = self.reload(trigger="polling")
                    if success:
                        logger.info("Config reloaded successfully")
                    else:
                        logger.error(
                            "Config reload failed, keeping previous config"
                        )
            except Exception:
                logger.exception("Unhandled error in config watcher loop")

    def _should_debounce(self, debounce_seconds: float) -> bool:
        """Return True when a change arrived within the debounce window.

        Compares the current monotonic clock against the last successful
        load/reload timestamp, so repeated filesystem events triggered by
        a single edit are coalesced into one reload.
        """
        with self._lock:
            return (
                time.monotonic() - self._last_reload_monotonic
                < debounce_seconds
            )

    def _should_debounce_watchdog(self) -> bool:
        """Return True when the watchdog event carries no *new* configuration.

        The watchdog fires a burst of duplicate events for a single edit
        (multiple ``on_modified`` calls plus intermediate renames).  These
        must coalesce into one reload.  The wall-clock
        :meth:`_should_debounce` drops any event that lands *inside the
        previous reload's window*, which can permanently swallow a genuinely
        new write that follows a reload within that window -- the polling
        fallback re-checks every tick and never drops it.

        Instead, treat an event as a duplicate only when the config file's
        current mtime *equals* the last mtime that was actually loaded
        (``reload()`` updates ``_last_mtime`` under the lock on every
        success).  Once the reload for a given write has completed, every
        subsequent event for that same mtime is redundant and is dropped.
        Any event whose mtime *differs* from the loaded value -- in either
        direction -- represents new content and is reloaded.  Comparing for
        equality (rather than "newer than") correctly handles writes whose
        mtime moves backwards (e.g. a file extracted from a tarball whose
        entries carry an epoch mtime), which a forward-only comparison would
        silently discard.
        """
        with self._lock:
            try:
                current_mtime = os.path.getmtime(self._config_path)
            except OSError:
                # File momentarily missing or unreadable -- do not reload.
                return True
            return current_mtime == self._last_mtime

    def _get_watcher_debounce_seconds(self) -> float:
        """Return the configured config-watcher debounce interval.

        Reads ``settings.watcher_debounce_seconds`` from the loaded
        config on every call (so a hot-reload is picked up immediately),
        falling back to :data:`DEFAULT_WATCHER_DEBOUNCE_SECONDS` when the
        key is absent.
        """
        return float(
            self.data.get("settings", {}).get(
                "watcher_debounce_seconds", DEFAULT_WATCHER_DEBOUNCE_SECONDS
            )
        )

    def _ensure_default_config(self) -> None:
        """Copy the bundled default config to ``self._config_path``."""
        source = Path(__file__).parent.parent / "default-config.json"
        if not source.exists():
            raise FileNotFoundError(
                f"Default config template not found at '{source}'"
            )

        self._config_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, self._config_path)
        os.chmod(self._config_path, 0o600)
        logger.info("Created default config at %s", self._config_path)
        self._log_config_event(
            "config.default_created",
            True,
            "Created default config",
            source=str(source),
        )

    def _read_json(self) -> dict:
        """Read and parse the JSON config file."""
        with open(self._config_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _migrate_if_needed(self, raw: dict) -> dict:
        """Migrate *raw* to the latest schema version, persisting any change.

        Applies the registered migration chain via :func:`migrate_config`.
        When a real change occurred (returned dict differs from the input),
        an atomic pre-migration ``.bak`` backup is written and the migrated
        dict is persisted back to ``self._config_path``.  If the backup or
        write fails (e.g. a read-only filesystem), the error is logged and
        the in-memory migrated dict is still returned so the server can
        start.

        Returns:
            The (possibly migrated) config dict.
        """
        migrated = migrate_config(raw)
        if migrated is not raw:
            try:
                backup_config_file(self._config_path)
                write_migrated_config(self._config_path, migrated)
            except OSError as exc:
                logger.warning(
                    "Could not persist config migration (%s) — using migrated "
                    "config in-memory only",
                    exc,
                )
                self._log_config_event(
                    "config.migrated",
                    False,
                    f"Could not persist config migration: {exc}",
                    from_version=raw.get("version"),
                    to_version=migrated.get("version"),
                )
                return migrated
            self._log_config_event(
                "config.migrated",
                True,
                "Config schema migration applied and persisted",
                from_version=raw.get("version"),
                to_version=migrated.get("version"),
            )
        return migrated

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self, config: dict) -> dict:
        """Validate *config* and return a deep copy with defaults applied.

        Raises :class:`ConfigValidationError` on the first violation.
        """
        if not isinstance(config, dict):
            raise ConfigValidationError("Config root must be a JSON object")

        # ---- known top-level keys ----
        # ``$schema`` is a standard JSON Schema annotation carried for editor /
        # CI tooling (see config.schema.json); it is accepted and ignored here.
        KNOWN_TOP_KEYS = {
            "$schema",
            "version",
            "ssh_targets",
            "block_patterns",
            "allowed_commands",
            "settings",
        }
        for key in config:
            if key not in KNOWN_TOP_KEYS:
                raise ConfigValidationError(
                    "Unknown top-level key",
                    field=key,
                )

        # -- version --
        version = config.get("version", 1)
        if not isinstance(version, int) or version < 1:
            raise ConfigValidationError(
                "'version' must be a positive integer",
                field="version",
            )
        if version != LATEST_CONFIG_VERSION:
            raise ConfigValidationError(
                f"Unsupported config version (latest supported version is {LATEST_CONFIG_VERSION})",
                field="version",
            )

        # -- ssh_targets --
        ssh_targets_raw = config.get("ssh_targets")
        if not isinstance(ssh_targets_raw, dict) or len(ssh_targets_raw) == 0:
            raise ConfigValidationError(
                "'ssh_targets' must be a non-empty object",
                field="ssh_targets",
            )

        if len(ssh_targets_raw) > MAX_TARGETS:
            raise ConfigValidationError(
                f"ssh_targets must not exceed {MAX_TARGETS} entries "
                f"(found {len(ssh_targets_raw)})",
                field="ssh_targets",
            )

        ssh_targets = {}
        ALLOWED_TARGET_KEYS = {"host", "port", "username", "private_key", "password", "checkcommand"}
        for tid, tdef in ssh_targets_raw.items():
            # Validate server name format -- the value is never logged so an
            # invalid/poisoned name cannot leak into logs or error messages.
            if not isinstance(tid, str):
                raise ConfigValidationError(
                    "ssh_targets: server name must be a string",
                    field="ssh_targets",
                )
            if len(tid) > MAX_TARGET_NAME_LENGTH:
                raise ConfigValidationError(
                    "ssh_targets: target name exceeds maximum length of "
                    f"{MAX_TARGET_NAME_LENGTH} characters",
                    field="ssh_targets",
                )
            if not re.fullmatch(TARGET_NAME_PATTERN, tid):
                raise ConfigValidationError(
                    "ssh_targets: target name contains invalid characters. "
                    "Allowed pattern: letters, digits, '.', '_', '-'",
                    field="ssh_targets",
                )
            if not isinstance(tdef, dict):
                raise ConfigValidationError(
                    "ssh_target must be an object",
                    field=f"ssh_targets.{tid}",
                )
            for k in tdef:
                if k not in ALLOWED_TARGET_KEYS:
                    raise ConfigValidationError(
                        "Unknown key in ssh_target",
                        field=f"ssh_targets.{tid}.{k}",
                    )

            host = tdef.get("host")
            if not isinstance(host, str) or not host.strip():
                raise ConfigValidationError(
                    "'host' must be a non-empty string",
                    field=f"ssh_targets.{tid}.host",
                )

            username = tdef.get("username")
            if not isinstance(username, str) or not username.strip():
                raise ConfigValidationError(
                    "'username' must be a non-empty string",
                    field=f"ssh_targets.{tid}.username",
                )

            port = tdef.get("port", DEFAULT_SSH_PORT)
            if port is not None and (not isinstance(port, int) or port < 1 or port > 65535):
                raise ConfigValidationError(
                    "'port' must be an integer 1-65535",
                    field=f"ssh_targets.{tid}.port",
                )

            private_key = tdef.get("private_key", "")
            password = tdef.get("password", "")
            has_key = isinstance(private_key, str) and private_key.strip() != ""
            has_pw = isinstance(password, str) and password.strip() != ""
            if not has_key and not has_pw:
                raise ConfigValidationError(
                    "at least one of 'private_key' or 'password' must be non-empty",
                    field=f"ssh_targets.{tid}",
                )
            if "private_key" in tdef and (
                not isinstance(private_key, str)
                or private_key.strip() == ""
            ):
                raise ConfigValidationError(
                    "'private_key'/'password' must be a non-empty string",
                    field=f"ssh_targets.{tid}.private_key",
                )
            if "password" in tdef and (not isinstance(password, str) or password.strip() == ""):
                raise ConfigValidationError(
                    "'private_key'/'password' must be a non-empty string",
                    field=f"ssh_targets.{tid}.password",
                )

            normalized = {
                "host": host,
                "port": port,
                "username": username,
            }
            if has_key:
                normalized["private_key"] = private_key
            if has_pw:
                normalized["password"] = password
            if "checkcommand" in tdef:
                normalized["checkcommand"] = tdef["checkcommand"]
            ssh_targets[tid] = normalized

        # Collect ssh target IDs for cross-reference validation
        ssh_target_ids = set(ssh_targets.keys())

        # -- block_patterns --
        block_patterns_raw = config.get("block_patterns", [])
        if not isinstance(block_patterns_raw, list):
            raise ConfigValidationError(
                "'block_patterns' must be a list of strings",
                field="block_patterns",
            )
        if len(block_patterns_raw) > MAX_BLOCK_PATTERNS:
            raise ConfigValidationError(
                f"block_patterns must not exceed {MAX_BLOCK_PATTERNS} entries "
                f"(found {len(block_patterns_raw)})",
                field="block_patterns",
            )
        for idx, pat in enumerate(block_patterns_raw):
            if not isinstance(pat, str):
                raise ConfigValidationError(
                    "'block_patterns' entries must be strings",
                    field=f"block_patterns[{idx}]",
                )
            if len(pat) > MAX_REGEX_PATTERN_LENGTH:
                raise ConfigValidationError(
                    f"block_patterns entry exceeds {MAX_REGEX_PATTERN_LENGTH} "
                    f"character limit (found {len(pat)})",
                    field=f"block_patterns[{idx}]",
                )
            risk_reason = check_redos_risk(pat)
            if risk_reason:
                raise ConfigValidationError(
                    f"block_patterns entry has potential ReDoS risk: "
                    f"{risk_reason}",
                    field=f"block_patterns[{idx}]",
                )
            try:
                # Compile with re.LIMITED_TIME (if available) so the engine
                # itself enforces a time bound on matching.
                compile_safe_pattern(pat)
            except re.error:
                raise ConfigValidationError(
                    "block_patterns entry is not a valid regex",
                    field=f"block_patterns[{idx}]",
                )

        # -- allowed_commands --
        allowed_raw = config.get("allowed_commands")
        if not isinstance(allowed_raw, dict):
            raise ConfigValidationError(
                "'allowed_commands' must be an object",
                field="allowed_commands",
            )

        allowed = {}

        # --- default rules ---
        default_rules_raw = allowed_raw.get("default")
        if not isinstance(default_rules_raw, list) or len(default_rules_raw) == 0:
            raise ConfigValidationError(
                "'allowed_commands.default' must be a non-empty list of rules",
                field="allowed_commands.default",
            )
        allowed["default"] = self._validate_rules(
            default_rules_raw, ssh_target_ids, "allowed_commands.default"
        )

        # --- api_keys ---
        api_keys_raw = allowed_raw.get("api_keys")
        if not isinstance(api_keys_raw, list):
            raise ConfigValidationError(
                "'allowed_commands.api_keys' must be a list",
                field="allowed_commands.api_keys",
            )
        api_keys = []
        KEY_HASH_RE = re.compile(
            r"^(?:sha256:[a-f0-9]{64}"
            r"|pbkdf2:sha256:\d+\$[a-f0-9]+\$[a-f0-9]{64})$"
        )
        # Map API key name -> first occurrence index for duplicate detection.
        seen_api_key_names: dict[str, int] = {}
        for idx, entry in enumerate(api_keys_raw):
            if not isinstance(entry, dict):
                raise ConfigValidationError(
                    "api_keys entry must be an object",
                    field=f"api_keys[{idx}]",
                )
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigValidationError(
                    "api_keys entry 'name' must be a non-empty string",
                    field=f"api_keys[{idx}].name",
                )
            if name in seen_api_key_names:
                raise ConfigValidationError(
                    "Duplicate API key name in 'allowed_commands.api_keys'",
                    field=f"api_keys[{idx}].name",
                )
            seen_api_key_names[name] = idx
            key_hash = entry.get("key_hash")
            if not isinstance(key_hash, str) or not KEY_HASH_RE.match(key_hash):
                raise ConfigValidationError(
                    "api_keys entry 'key_hash' must match pattern "
                    "'sha256:<64 hex chars>' or 'pbkdf2:sha256:<iter>$<salt>$<64 hex chars>'",
                    field=f"api_keys[{idx}].key_hash",
                )
            rules_raw = entry.get("rules")
            if not isinstance(rules_raw, list) or len(rules_raw) == 0:
                raise ConfigValidationError(
                    "api_keys entry 'rules' must be a non-empty list of rules",
                    field=f"api_keys[{idx}].rules",
                )
            rules = self._validate_rules(
                rules_raw, ssh_target_ids, f"api_keys[{idx}].rules"
            )
            api_keys.append({"name": name, "key_hash": key_hash, "rules": rules})
        allowed["api_keys"] = api_keys

        # --- networks ---
        networks_raw = allowed_raw.get("networks")
        if not isinstance(networks_raw, list):
            raise ConfigValidationError(
                "'allowed_commands.networks' must be a list",
                field="allowed_commands.networks",
            )
        networks = []
        # Accumulate (name, parsed network) for CIDR-overlap detection.
        parsed_networks: list[tuple[str, ipaddress._BaseNetwork]] = []
        for idx, entry in enumerate(networks_raw):
            if not isinstance(entry, dict):
                raise ConfigValidationError(
                    "networks entry must be an object",
                    field=f"networks[{idx}]",
                )
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ConfigValidationError(
                    "networks entry 'name' must be a non-empty string",
                    field=f"networks[{idx}].name",
                )
            cidr = entry.get("range")
            if not isinstance(cidr, str):
                raise ConfigValidationError(
                    "networks entry 'range' must be a string",
                    field=f"networks[{idx}].range",
                )
            try:
                parsed = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                raise ConfigValidationError(
                    "networks entry 'range' is not a valid CIDR",
                    field=f"networks[{idx}].range",
                )
            # Reject networks whose range overlaps a previously-declared one.
            # Note: .overlaps() returns False for mixed IPv4/IPv6 comparisons,
            # so no explicit family check is needed.
            for prev_name, prev_net in parsed_networks:
                if parsed.overlaps(prev_net):
                    raise ConfigValidationError(
                        "Network range overlaps with a previously-declared network",
                        field=f"networks[{idx}].range",
                    )
            parsed_networks.append((name, parsed))
            rules_raw = entry.get("rules")
            if not isinstance(rules_raw, list) or len(rules_raw) == 0:
                raise ConfigValidationError(
                    "networks entry 'rules' must be a non-empty list of rules",
                    field=f"networks[{idx}].rules",
                )
            rules = self._validate_rules(
                rules_raw, ssh_target_ids, f"networks[{idx}].rules"
            )
            networks.append({"name": name, "range": cidr, "rules": rules})
        allowed["networks"] = networks

        # -- settings --
        settings_raw = config.get("settings")
        if not isinstance(settings_raw, dict):
            raise ConfigValidationError(
                "'settings' must be an object",
                field="settings",
            )
        ALLOWED_SETTINGS = {
            "max_output_length",
            "command_timeout_max",
            "retry_max_attempts",
            "retry_backoff_base_seconds",
            "circuit_breaker_failure_threshold",
            "circuit_breaker_timeout_seconds",
            "log_level",
            "max_log_output",
            "compress_rotated",
            "pool_max_connections_per_target",
            "pool_idle_timeout_seconds",
            "pool_cleanup_interval_seconds",
            "max_concurrent_ssh_connections",
            "watcher_debounce_seconds",
            "trusted_proxies",
            "sftp",
            "rate_limit",
        }
        for sk in settings_raw:
            if sk not in ALLOWED_SETTINGS:
                raise ConfigValidationError(
                    "Unknown key in 'settings'",
                    field=f"settings.{sk}",
                )
        max_output = ConfigManager._normalize_max_output_length(
            settings_raw.get("max_output_length")
        )
        timeout_max = settings_raw.get("command_timeout_max")
        if not isinstance(timeout_max, int) or timeout_max < 1:
            raise ConfigValidationError(
                "'settings.command_timeout_max' must be an integer >= 1",
                field="settings.command_timeout_max",
            )

        # Optional resilience settings — defaults come from lib.constants.
        retry_max_attempts = settings_raw.get(
            "retry_max_attempts", DEFAULT_RETRY_MAX_ATTEMPTS
        )
        if not isinstance(retry_max_attempts, int) or retry_max_attempts < 1:
            raise ConfigValidationError(
                "'settings.retry_max_attempts' must be an integer >= 1",
                field="settings.retry_max_attempts",
            )
        retry_backoff_base = settings_raw.get(
            "retry_backoff_base_seconds", DEFAULT_RETRY_BACKOFF_BASE_SECONDS
        )
        if (
            not isinstance(retry_backoff_base, (int, float))
            or isinstance(retry_backoff_base, bool)
            or retry_backoff_base <= 0
        ):
            raise ConfigValidationError(
                "'settings.retry_backoff_base_seconds' must be a number > 0",
                field="settings.retry_backoff_base_seconds",
            )
        cb_threshold = settings_raw.get(
            "circuit_breaker_failure_threshold",
            DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        )
        if not isinstance(cb_threshold, int) or cb_threshold < 1:
            raise ConfigValidationError(
                "'settings.circuit_breaker_failure_threshold' must be an integer >= 1",
                field="settings.circuit_breaker_failure_threshold",
            )
        cb_timeout = settings_raw.get(
            "circuit_breaker_timeout_seconds",
            DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
        )
        if (
            not isinstance(cb_timeout, (int, float))
            or isinstance(cb_timeout, bool)
            or cb_timeout <= 0
        ):
            raise ConfigValidationError(
                "'settings.circuit_breaker_timeout_seconds' must be a number > 0",
                field="settings.circuit_breaker_timeout_seconds",
            )

        # Optional log-level setting — default comes from lib.constants.
        log_level = settings_raw.get("log_level", DEFAULT_LOG_LEVEL)
        if not isinstance(log_level, str) or log_level.upper() not in LOG_LEVELS:
            raise ConfigValidationError(
                f"'settings.log_level' must be one of {', '.join(LOG_LEVELS)}",
                field="settings.log_level",
            )

        # Optional log-output truncation setting — default comes from constants.
        max_log_output = settings_raw.get("max_log_output", DEFAULT_MAX_LOG_OUTPUT)
        if not isinstance(max_log_output, int) or max_log_output < 1:
            raise ConfigValidationError(
                "'settings.max_log_output' must be an integer >= 1",
                field="settings.max_log_output",
            )

        # Optional rotation-compression setting — default comes from constants.
        compress_rotated = settings_raw.get(
            "compress_rotated", DEFAULT_COMPRESS_ROTATED
        )
        if not isinstance(compress_rotated, bool):
            raise ConfigValidationError(
                "'settings.compress_rotated' must be a boolean",
                field="settings.compress_rotated",
            )

        # Optional SSH connection-pool settings — defaults come from constants.
        pool_max_connections = settings_raw.get(
            "pool_max_connections_per_target",
            DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
        )
        if not isinstance(pool_max_connections, int) or pool_max_connections < 1:
            raise ConfigValidationError(
                "'settings.pool_max_connections_per_target' must be an integer >= 1",
                field="settings.pool_max_connections_per_target",
            )
        pool_idle_timeout = settings_raw.get(
            "pool_idle_timeout_seconds", DEFAULT_POOL_IDLE_TIMEOUT_SECONDS
        )
        if (
            not isinstance(pool_idle_timeout, (int, float))
            or isinstance(pool_idle_timeout, bool)
            or pool_idle_timeout <= 0
        ):
            raise ConfigValidationError(
                "'settings.pool_idle_timeout_seconds' must be a number > 0",
                field="settings.pool_idle_timeout_seconds",
            )
        pool_cleanup_interval = settings_raw.get(
            "pool_cleanup_interval_seconds", DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS
        )
        if (
            not isinstance(pool_cleanup_interval, (int, float))
            or isinstance(pool_cleanup_interval, bool)
            or pool_cleanup_interval <= 0
        ):
            raise ConfigValidationError(
                "'settings.pool_cleanup_interval_seconds' must be a number > 0",
                field="settings.pool_cleanup_interval_seconds",
            )

        # Optional global SSH concurrency cap — default comes from constants.
        max_concurrent_ssh_connections = settings_raw.get(
            "max_concurrent_ssh_connections",
            DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
        )
        if (
            not isinstance(max_concurrent_ssh_connections, int)
            or max_concurrent_ssh_connections < 1
        ):
            raise ConfigValidationError(
                "'settings.max_concurrent_ssh_connections' must be an integer >= 1",
                field="settings.max_concurrent_ssh_connections",
            )

        # Optional config-watcher debounce setting — default comes from constants.
        watcher_debounce_seconds = settings_raw.get(
            "watcher_debounce_seconds", DEFAULT_WATCHER_DEBOUNCE_SECONDS
        )
        if (
            not isinstance(watcher_debounce_seconds, (int, float))
            or isinstance(watcher_debounce_seconds, bool)
            or watcher_debounce_seconds < 0
        ):
            raise ConfigValidationError(
                "'settings.watcher_debounce_seconds' must be a non-negative "
                "number (0 disables debounce)",
                field="settings.watcher_debounce_seconds",
            )

        # Optional trusted proxy list for X-Forwarded-For resolution.
        trusted_proxies_raw = settings_raw.get(
            "trusted_proxies", DEFAULT_TRUSTED_PROXIES
        )
        if not isinstance(trusted_proxies_raw, list):
            raise ConfigValidationError(
                "'settings.trusted_proxies' must be a list",
                field="settings.trusted_proxies",
            )
        trusted_proxies: list[str] = []
        for idx, entry in enumerate(trusted_proxies_raw):
            if not isinstance(entry, str) or not entry.strip():
                raise ConfigValidationError(
                    "'settings.trusted_proxies' entries must be non-empty strings",
                    field=f"settings.trusted_proxies[{idx}]",
                )
            normalized = ConfigManager._normalize_trusted_proxy(entry.strip())
            if normalized is None:
                raise ConfigValidationError(
                    "'settings.trusted_proxies' entries must be valid IP addresses",
                    field=f"settings.trusted_proxies[{idx}]",
                )
            trusted_proxies.append(normalized)

        # --- Rate-limiting settings ---
        rate_limit_raw = settings_raw.get("rate_limit", {})
        if not isinstance(rate_limit_raw, dict):
            raise ConfigValidationError(
                "'settings.rate_limit' must be an object",
                field="settings.rate_limit",
            )
        rate_limit_enabled = rate_limit_raw.get(
            "enabled", DEFAULT_RATE_LIMIT_ENABLED
        )
        if not isinstance(rate_limit_enabled, bool):
            raise ConfigValidationError(
                "'settings.rate_limit.enabled' must be a boolean",
                field="settings.rate_limit.enabled",
            )
        rate_limit_max_requests = rate_limit_raw.get(
            "max_requests_per_minute", DEFAULT_RATE_LIMIT_REQUESTS
        )
        if not isinstance(rate_limit_max_requests, int) or rate_limit_max_requests < 1:
            raise ConfigValidationError(
                "'settings.rate_limit.max_requests_per_minute' must be an integer >= 1",
                field="settings.rate_limit.max_requests_per_minute",
            )
        rate_limit_window = rate_limit_raw.get(
            "window_seconds", DEFAULT_RATE_LIMIT_WINDOW_SECONDS
        )
        if not isinstance(rate_limit_window, (int, float)) or rate_limit_window <= 0:
            raise ConfigValidationError(
                "'settings.rate_limit.window_seconds' must be a number > 0",
                field="settings.rate_limit.window_seconds",
            )
        rate_limit_cleanup = rate_limit_raw.get(
            "cleanup_interval_seconds", RATE_LIMIT_CLEANUP_INTERVAL_SECONDS
        )
        if not isinstance(rate_limit_cleanup, (int, float)) or rate_limit_cleanup <= 0:
            raise ConfigValidationError(
                "'settings.rate_limit.cleanup_interval_seconds' must be a number > 0",
                field="settings.rate_limit.cleanup_interval_seconds",
            )

        # --- SFTP settings ---
        sftp_raw = settings_raw.get("sftp", {})
        if not isinstance(sftp_raw, dict):
            raise ConfigValidationError(
                "'settings.sftp' must be an object",
                field="settings.sftp",
            )
        sandbox_root = sftp_raw.get(
            "sandbox_root", DEFAULT_SFTP_SANDBOX_ROOT
        )
        if not isinstance(sandbox_root, str):
            raise ConfigValidationError(
                "'settings.sftp.sandbox_root' must be a string",
                field="settings.sftp.sandbox_root",
            )
        max_path_length = sftp_raw.get(
            "max_path_length", DEFAULT_MAX_SFTP_PATH_LENGTH
        )
        if not isinstance(max_path_length, int) or max_path_length < 0:
            raise ConfigValidationError(
                "'settings.sftp.max_path_length' must be a non-negative integer",
                field="settings.sftp.max_path_length",
            )

        return {
            "version": version,
            "ssh_targets": ssh_targets,
            "block_patterns": list(block_patterns_raw),
            "allowed_commands": allowed,
            "settings": {
                "max_output_length": max_output,
                "command_timeout_max": timeout_max,
                "retry_max_attempts": retry_max_attempts,
                "retry_backoff_base_seconds": float(retry_backoff_base),
                "circuit_breaker_failure_threshold": cb_threshold,
                "circuit_breaker_timeout_seconds": float(cb_timeout),
                "log_level": log_level.upper(),
                "max_log_output": max_log_output,
                "compress_rotated": compress_rotated,
                "pool_max_connections_per_target": pool_max_connections,
                "pool_idle_timeout_seconds": float(pool_idle_timeout),
                "pool_cleanup_interval_seconds": float(pool_cleanup_interval),
                "max_concurrent_ssh_connections": max_concurrent_ssh_connections,
                "watcher_debounce_seconds": float(watcher_debounce_seconds),
                "trusted_proxies": trusted_proxies,
                "sftp": {
                    "sandbox_root": sandbox_root,
                    "max_path_length": max_path_length,
                },
                "rate_limit": {
                    "enabled": rate_limit_enabled,
                    "max_requests_per_minute": rate_limit_max_requests,
                    "window_seconds": float(rate_limit_window),
                    "cleanup_interval_seconds": float(rate_limit_cleanup),
                },
            },
        }

    @staticmethod
    def _validate_rules(
        rules_raw: list,
        ssh_target_ids: set[str],
        field_prefix: str,
    ) -> list[dict]:
        """Validate a list of command-allowance rules.

        Each rule must have a non-empty ``targets`` list and a non-empty
        ``commands`` list.  Non-wildcard targets must exist in
        *ssh_target_ids*.
        """
        rules = []
        for idx, rule in enumerate(rules_raw):
            if not isinstance(rule, dict):
                raise ConfigValidationError(
                    "rules entry must be an object",
                    field=f"{field_prefix}[{idx}]",
                )
            targets = rule.get("targets")
            if not isinstance(targets, list) or len(targets) == 0:
                raise ConfigValidationError(
                    "rules entry 'targets' must be a non-empty list",
                    field=f"{field_prefix}[{idx}].targets",
                )
            for t in targets:
                if not isinstance(t, str):
                    raise ConfigValidationError(
                        "rules entry 'targets' entries must be strings",
                        field=f"{field_prefix}[{idx}].targets",
                    )
                if t != "*" and t not in ssh_target_ids:
                    raise ConfigValidationError(
                        "rules entry 'targets' references an unknown ssh_target",
                        field=f"{field_prefix}[{idx}].targets",
                    )

            commands = rule.get("commands")
            if not isinstance(commands, list) or len(commands) == 0:
                raise ConfigValidationError(
                    "rules entry 'commands' must be a non-empty list",
                    field=f"{field_prefix}[{idx}].commands",
                )
            for c in commands:
                if not isinstance(c, str):
                    raise ConfigValidationError(
                        "rules entry 'commands' entries must be strings",
                        field=f"{field_prefix}[{idx}].commands",
                    )

            rules.append({"targets": list(targets), "commands": list(commands)})
        return rules
