"""Tests for lib.config — ConfigManager validation, loading, and query methods."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

from lib.config import (
    ConfigManager,
    ConfigValidationError,
    build_default_config,
)
from lib.constants import (
    DEFAULT_BLOCK_PATTERNS,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_MAX_OUTPUT_LENGTH,
    DEFAULT_SSH_PORT,
    LATEST_CONFIG_VERSION,
    MAX_BLOCK_PATTERNS,
    MAX_REGEX_PATTERN_LENGTH,
    MAX_TARGETS,
)

_RESTRICTED = 0o600

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmpdir: str, config_dict: dict) -> str:
    """Write *config_dict* as ``ssh-mcp-config.json`` inside *tmpdir*."""
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


def _write_secrets(tmpdir: str, secrets_dict: dict) -> str:
    """Write *secrets_dict* as ``secrets.json`` inside *tmpdir*."""
    secrets_path = Path(tmpdir) / "secrets.json"
    secrets_path.write_text(json.dumps(secrets_dict), encoding="utf-8")
    return str(secrets_path)


def _minimal_valid_config(**overrides) -> dict:
    """Return a minimal config dict that passes validation."""
    cfg = {
        "version": 1,
        "ssh_targets": {
            "testbox": {
                "host": "10.0.0.1",
                "username": "admin",
                "password": "secret",
                "port": 22,
            },
        },
        "block_patterns": ["\\brm\\s+-rf\\b"],
        "allowed_commands": {
            "default": [{"targets": ["*"], "commands": ["hostname", "whoami"]}],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }
    cfg.update(overrides)
    return cfg


class RecordingLogger:
    """Duck-typed :class:`~lib.loggers.BaseLogger` that records entries."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, entry: dict) -> None:
        self.entries.append(entry)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Tests: successful loading & queries
# ---------------------------------------------------------------------------


class TestLoadValidConfig:
    def test_load_valid_config(self):
        """ConfigManager loads a valid config and data property matches."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            data = mgr.data
            assert data["version"] == 1
            assert "testbox" in data["ssh_targets"]
            assert data["ssh_targets"]["testbox"]["port"] == 22

    def test_default_config_creation(self):
        """When no config file exists, the default is created and loads."""
        with tempfile.TemporaryDirectory() as td:
            mgr = ConfigManager(td)
            data = mgr.data
            assert data["version"] == 1
            # At least one target from the real default-config.json
            assert len(data["ssh_targets"]) >= 1
            assert os.path.exists(mgr.config_path)

    def test_get_ssh_target_returns_correct_dict(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            tgt = mgr.get_ssh_target("testbox")
            assert tgt is not None
            assert tgt["host"] == "10.0.0.1"
            assert tgt["username"] == "admin"

    def test_get_ssh_target_returns_none_for_missing(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.get_ssh_target("nonexistent") is None

    def test_list_ssh_targets_returns_all_ids(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["ssh_targets"]["box2"] = {
                "host": "10.0.0.2",
                "username": "root",
                "password": "pass",
            }
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            ids = mgr.list_ssh_targets()
            assert sorted(ids) == ["box2", "testbox"]


# ---------------------------------------------------------------------------
# Tests: build_default_config
# ---------------------------------------------------------------------------


class TestBuildDefaultConfig:
    """Tests for :func:`lib.config.build_default_config`."""

    def test_returns_expected_structure(self) -> None:
        """The emitted config carries the canonical top-level keys."""
        cfg = build_default_config()
        assert set(cfg.keys()) == {
            "version",
            "ssh_targets",
            "block_patterns",
            "allowed_commands",
            "settings",
        }

    def test_uses_constant_driven_values(self) -> None:
        """Magic values come from lib.constants, not inline literals."""
        cfg = build_default_config()
        assert cfg["version"] == LATEST_CONFIG_VERSION
        assert cfg["block_patterns"] == list(DEFAULT_BLOCK_PATTERNS)
        target = next(iter(cfg["ssh_targets"].values()))
        assert target["port"] == DEFAULT_SSH_PORT
        assert cfg["settings"]["max_output_length"] == DEFAULT_MAX_OUTPUT_LENGTH
        assert (
            cfg["settings"]["command_timeout_max"]
            == DEFAULT_COMMAND_TIMEOUT_SECONDS
        )

    def test_emits_single_placeholder_target_and_rule(self) -> None:
        """Ships one placeholder target and one default rule (non-empty)."""
        cfg = build_default_config()
        assert len(cfg["ssh_targets"]) >= 1
        assert len(cfg["allowed_commands"]["default"]) >= 1

    def test_emitted_config_passes_validation(self) -> None:
        """A config produced by build_default_config() loads successfully."""
        cfg = build_default_config()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["version"] == LATEST_CONFIG_VERSION
            assert mgr.list_ssh_targets() == list(cfg["ssh_targets"].keys())


# ---------------------------------------------------------------------------
# Tests: validation failures
# ---------------------------------------------------------------------------


class TestValidationFailures:
    def test_missing_version_is_treated_as_v1(self):
        """A config missing the version key loads fine, treated as v1."""
        cfg = _minimal_valid_config()
        del cfg["version"]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["version"] == 1
            assert "testbox" in mgr.data["ssh_targets"]

    def test_validation_fails_empty_ssh_targets(self):
        cfg = _minimal_valid_config()
        cfg["ssh_targets"] = {}
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="ssh_targets"):
                ConfigManager(td)

    def test_validation_fails_missing_auth(self):
        cfg = _minimal_valid_config()
        cfg["ssh_targets"]["testbox"] = {
            "host": "10.0.0.1",
            "username": "admin",
            "port": 22,
        }
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="private_key.*password"):
                ConfigManager(td)

    def test_validation_fails_invalid_port(self):
        for bad_port in (-1, 0, 99999, "abc"):
            cfg = _minimal_valid_config()
            cfg["ssh_targets"]["testbox"]["port"] = bad_port
            with tempfile.TemporaryDirectory() as td:
                _write_config(td, cfg)
                with pytest.raises(ConfigValidationError, match="port"):
                    ConfigManager(td)

    def test_validation_fails_invalid_cidr(self):
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["networks"] = [
            {
                "name": "bad",
                "range": "not-a-cidr",
                "rules": [{"targets": ["*"], "commands": ["ls"]}],
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="CIDR"):
                ConfigManager(td)

    def test_validation_fails_invalid_regex(self):
        cfg = _minimal_valid_config()
        cfg["block_patterns"] = ["[unclosed"]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="valid regex"):
                ConfigManager(td)

    def test_validation_rejects_redos_nested_quantifiers(self):
        """A block_pattern with nested quantifiers is rejected at load time."""
        cfg = _minimal_valid_config(block_patterns=["(a+)+"])
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="ReDoS"):
                ConfigManager(td)

    def test_validation_rejects_redos_overlapping_alternation(self):
        """A block_pattern with overlapping alternation is rejected."""
        cfg = _minimal_valid_config(block_patterns=["(a|a)+"])
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="ReDoS"):
                ConfigManager(td)

    def test_validation_error_message_includes_redos_reason(self):
        """The rejection message explains the specific ReDoS risk."""
        cfg = _minimal_valid_config(block_patterns=["(a+)+"])
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="potential ReDoS risk"):
                ConfigManager(td)

    def test_validation_accepts_safe_block_patterns(self):
        """All default block patterns (and benign alternation) pass validation."""
        safe_patterns = list(DEFAULT_BLOCK_PATTERNS) + ["(dev|proc|sys)"]
        cfg = _minimal_valid_config(block_patterns=safe_patterns)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            ConfigManager(td)

    def test_validation_fails_invalid_key_hash(self):
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["api_keys"] = [
            {
                "name": "k1",
                "key_hash": "bad-hash-format",
                "rules": [{"targets": ["*"], "commands": ["ls"]}],
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="sha256"):
                ConfigManager(td)

    def test_validation_fails_targets_references_nonexistent(self):
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["default"][0]["targets"] = ["ghost"]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="unknown ssh_target"):
                ConfigManager(td)

    def test_validation_fails_unknown_top_level_key(self):
        cfg = _minimal_valid_config()
        cfg["bogus_key"] = "unexpected"
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="Unknown top-level key"):
                ConfigManager(td)

    def test_validation_fails_unknown_ssh_target_key(self):
        cfg = _minimal_valid_config()
        cfg["ssh_targets"]["testbox"]["extra_field"] = "no"
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="Unknown key"):
                ConfigManager(td)


# ---------------------------------------------------------------------------
# Tests: normalization & reload
# ---------------------------------------------------------------------------


class TestNormalizationAndReload:
    def test_port_defaults_to_22(self):
        cfg = _minimal_valid_config()
        del cfg["ssh_targets"]["testbox"]["port"]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["ssh_targets"]["testbox"]["port"] == 22

    def test_reload_with_valid_config_updates_data(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert mgr.data["ssh_targets"]["testbox"]["host"] == "10.99.99.99"

    def test_reload_with_invalid_config_preserves_old_data(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            original_host = mgr.data["ssh_targets"]["testbox"]["host"]

            # write a broken config
            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)

            assert mgr.reload() is False
            assert mgr.data["ssh_targets"]["testbox"]["host"] == original_host


# ---------------------------------------------------------------------------
# Tests: config-change callbacks
# ---------------------------------------------------------------------------


class TestConfigChangeCallbacks:
    """Config-change notification callbacks are registered and fired on reload."""

    def test_callback_fires_on_successful_reload(self):
        """A registered callback runs exactly once after a successful reload."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            calls = []
            mgr.on_config_change(lambda: calls.append(1))

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert len(calls) == 1

    def test_callback_not_fired_on_failed_reload(self):
        """A failed reload does not invoke registered callbacks."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            calls = []
            mgr.on_config_change(lambda: calls.append(1))

            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)

            assert mgr.reload() is False
            assert len(calls) == 0

    def test_callback_not_fired_on_initial_load(self):
        """Callbacks registered after construction are not fired by initial load."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            calls = []
            mgr.on_config_change(lambda: calls.append(1))
            assert len(calls) == 0

    def test_callback_exception_is_isolated_and_reload_succeeds(self):
        """A raising callback does not block other callbacks or the reload."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            ran = []

            def _boom() -> None:
                raise RuntimeError("callback boom")

            mgr.on_config_change(_boom)
            mgr.on_config_change(lambda: ran.append(1))

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert ran == [1]

    def test_unregister_stops_callback(self):
        """Unregistering a callback prevents it from firing on reload."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            calls = []
            cb = lambda: calls.append(1)  # noqa: E731
            mgr.on_config_change(cb)
            mgr.unregister_config_change_callback(cb)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert len(calls) == 0

    def test_duplicate_registration_invoked_once(self):
        """Registering the same callable twice still invokes it once."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            calls = []

            def cb() -> None:
                calls.append(1)

            mgr.on_config_change(cb)
            mgr.on_config_change(cb)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert len(calls) == 1

    def test_callback_observes_post_swap_data(self):
        """A callback sees the NEW data committed by the reload, not the old."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            observed = []
            mgr.on_config_change(lambda: observed.append(mgr.data))

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.99.99.99"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert observed
            # The callback reads ``mgr.data`` after the atomic swap, so it must
            # observe the freshly reloaded host rather than the previous value.
            assert observed[-1]["ssh_targets"]["testbox"]["host"] == "10.99.99.99"


# ---------------------------------------------------------------------------
# Tests: thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_data_property_thread_safety(self):
        """Multiple concurrent reads of ``data`` should not deadlock."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            errors = []

            def reader():
                try:
                    for _ in range(100):
                        _ = mgr.data
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=reader) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0


# ---------------------------------------------------------------------------
# Tests: hot-reload watcher
# ---------------------------------------------------------------------------


class TestWatcher:
    """Tests for the background polling watcher (start_watcher / stop_watcher)."""

    def test_start_watcher_spawns_thread_and_watcher_running(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.watcher_running is False

            mgr.start_watcher(polling_interval=0.1)
            assert mgr.watcher_running is True
            assert mgr._watcher_thread is not None
            assert mgr._watcher_thread.daemon is True
            assert mgr._watcher_thread.name == "config-watcher"

            mgr.stop_watcher()
            assert mgr.watcher_running is False

    def test_watchdog_observer_runs_as_daemon(self, monkeypatch):
        """The watchdog observer branch must run its watcher as a daemon.

        Forces the ``from watchdog.observers import Observer`` import inside
        :meth:`ConfigManager.start_watcher` to succeed by substituting a fake
        ``watchdog.observers`` module, then asserts the observer stored as
        ``mgr._watcher_thread`` carries ``daemon is True``.
        """
        import sys
        import types

        class FakeObserver:
            def __init__(self) -> None:
                self.name = ""
                self.daemon = False

            def schedule(self, handler, path, recursive=False) -> None:
                pass

            def start(self) -> None:
                self._started = True

            def stop(self) -> None:
                self._started = False

            def join(self, timeout=None) -> None:
                pass

            def is_alive(self) -> bool:
                return bool(getattr(self, "_started", False))

        fake_observers = types.ModuleType("watchdog.observers")
        setattr(fake_observers, "Observer", FakeObserver)
        monkeypatch.setitem(sys.modules, "watchdog.observers", fake_observers)

        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.watcher_running is False

            mgr.start_watcher(polling_interval=0.1)
            assert mgr._watcher_is_observer is True
            assert mgr.watcher_running is True
            assert mgr._watcher_thread is not None
            assert mgr._watcher_thread.daemon is True

            mgr.stop_watcher()
            assert mgr.watcher_running is False

    def test_start_watcher_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)

            mgr.start_watcher(polling_interval=0.1)
            first_thread = mgr._watcher_thread
            assert first_thread is not None
            assert first_thread.is_alive()

            # second call should be a no-op
            mgr.start_watcher(polling_interval=0.1)
            assert mgr._watcher_thread is first_thread  # same object

            mgr.stop_watcher()
            first_thread.join(timeout=3.0)

    def test_stop_watcher_stops_thread(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=5.0)
            assert mgr.watcher_running is True

            mgr.stop_watcher()
            # Thread should stop shortly after stop_event is set
            if mgr._watcher_thread is not None:
                mgr._watcher_thread.join(timeout=3.0)
            assert mgr.watcher_running is False

    def test_stop_watcher_safe_when_never_started(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            # should not raise
            mgr.stop_watcher()
            assert mgr.watcher_running is False

    def test_watcher_detects_change_and_reloads(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=0.1)

            assert mgr.data["ssh_targets"]["testbox"]["host"] == "10.0.0.1"

            # Modify the config file on disk
            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "192.168.99.99"
            _write_config(td, new_cfg)

            # Wait for the watcher to pick up the change (up to 2× interval)
            import time
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if mgr.data["ssh_targets"]["testbox"]["host"] == "192.168.99.99":
                    break
                time.sleep(0.05)
            else:
                mgr.stop_watcher()
                pytest.fail("Watcher did not detect config change within timeout")

            assert mgr.data["ssh_targets"]["testbox"]["host"] == "192.168.99.99"
            mgr.stop_watcher()

    def test_watcher_rejects_invalid_config_preserves_old(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=0.1)

            original_host = mgr.data["ssh_targets"]["testbox"]["host"]

            # Write invalid config (missing version)
            broken = _minimal_valid_config()
            del broken["version"]
            _write_config(td, broken)

            import time
            time.sleep(0.5)  # give watcher time to notice and reject

            # data should still be the original valid config
            assert mgr.data["ssh_targets"]["testbox"]["host"] == original_host
            mgr.stop_watcher()

    def test_watcher_handles_deleted_config_file(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=0.1)

            original_host = mgr.data["ssh_targets"]["testbox"]["host"]

            # Delete the config file
            os.remove(mgr.config_path)

            import time
            time.sleep(0.5)  # give watcher time to notice the missing file

            # watcher should not crash; data should be preserved
            assert mgr.data["ssh_targets"]["testbox"]["host"] == original_host
            assert mgr.watcher_running is True

            mgr.stop_watcher()

    def test_reload_updates_last_mtime_on_success(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)

            old_mtime = mgr._last_mtime
            assert old_mtime > 0.0  # set by load()

            import time
            time.sleep(0.01)  # ensure mtime would differ

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.1.2.3"
            _write_config(td, new_cfg)

            assert mgr.reload() is True
            assert mgr._last_mtime > old_mtime

    def test_reload_does_not_update_last_mtime_on_failure(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)

            old_mtime = mgr._last_mtime

            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)

            assert mgr.reload() is False
            assert mgr._last_mtime == old_mtime

    def test_concurrent_reads_during_reload(self):
        """Concurrent reads of ``data`` during a reload do not raise exceptions."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=0.05)
            errors = []

            def reader():
                try:
                    for _ in range(200):
                        _ = mgr.data
                except Exception as exc:
                    errors.append(exc)

            def modifier():
                for i in range(10):
                    new_cfg = _minimal_valid_config()
                    new_cfg["settings"]["max_output_length"] = 50000 + i
                    _write_config(td, new_cfg)
                    import time
                    time.sleep(0.02)

            threads = [threading.Thread(target=reader) for _ in range(4)]
            mod_thread = threading.Thread(target=modifier)

            for t in threads:
                t.start()
            mod_thread.start()

            for t in threads:
                t.join()
            mod_thread.join()

            mgr.stop_watcher()
            assert len(errors) == 0

    def test_watcher_debounce_coalesces_rapid_changes(self):
        """Rapid successive file changes are coalesced into a single reload."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"]["watcher_debounce_seconds"] = 1.0
            _write_config(td, cfg)
            mgr = ConfigManager(td)

            import time

            mgr._last_reload_monotonic = time.monotonic()
            # Immediately after a reload a change is debounced (must not reload).
            assert mgr._should_debounce(mgr._get_watcher_debounce_seconds()) is True

            # After advancing beyond the debounce window the change is allowed.
            mgr._last_reload_monotonic = time.monotonic() - 2.0
            assert mgr._should_debounce(mgr._get_watcher_debounce_seconds()) is False

    def test_watcher_debounce_disabled_when_zero(self):
        """A zero debounce value disables the coalescing behaviour."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"]["watcher_debounce_seconds"] = 0
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["watcher_debounce_seconds"] == 0.0

            import time

            mgr._last_reload_monotonic = time.monotonic()
            # With 0 debounce, a change is never suppressed, even right after reload.
            assert mgr._should_debounce(mgr._get_watcher_debounce_seconds()) is False

    def test_watcher_debounce_uses_configured_value(self):
        """The configured value flows through to the debounce helper."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"]["watcher_debounce_seconds"] = 7.5
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr._get_watcher_debounce_seconds() == 7.5

            import time

            mgr._last_reload_monotonic = time.monotonic()
            assert mgr._should_debounce(mgr._get_watcher_debounce_seconds()) is True


# ---------------------------------------------------------------------------
# Tests: watcher health (last_reload_timestamp / last_error / healthy)
# ---------------------------------------------------------------------------


class TestWatcherHealth:
    """Health state exposed by ConfigManager for the background watcher."""

    def test_healthy_after_initial_load(self):
        """A successful load leaves healthy=True and a reload timestamp."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.healthy is True
            assert mgr.last_error is None
            assert mgr.last_reload_timestamp is not None
            assert "T" in mgr.last_reload_timestamp  # ISO-8601 with date/time

    def test_failed_reload_sets_last_error_and_unhealthy(self):
        """A failed reload records the error and flips healthy to False."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.healthy is True

            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)

            assert mgr.reload() is False
            assert mgr.healthy is False
            assert mgr.last_error is not None
            assert "Config validation failed" in mgr.last_error

    def test_failed_read_sets_last_error(self):
        """A read failure (invalid JSON) also records the error."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)

            # Corrupt the file so JSON decoding fails on reload.
            Path(mgr.config_path).write_text("{ not json", encoding="utf-8")

            assert mgr.reload() is False
            assert mgr.healthy is False
            assert mgr.last_error is not None
            assert "Failed to read config" in mgr.last_error

    def test_successful_reload_clears_error_and_updates_timestamp(self):
        """A later successful reload restores health and refreshes the timestamp."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            first_ts = mgr.last_reload_timestamp

            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)
            assert mgr.reload() is False
            assert mgr.healthy is False

            _write_config(td, _minimal_valid_config())
            assert mgr.reload() is True
            assert mgr.healthy is True
            assert mgr.last_error is None
            assert mgr.last_reload_timestamp is not None
            assert first_ts is not None
            assert mgr.last_reload_timestamp >= first_ts

    def test_watcher_updates_health_after_invalid_change(self):
        """The watcher marks the manager unhealthy after noticing bad config."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            mgr.start_watcher(polling_interval=0.05)
            assert mgr.healthy is True

            broken = _minimal_valid_config()
            broken["settings"]["retry_max_attempts"] = 0  # invalid
            _write_config(td, broken)

            import time
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if not mgr.healthy:
                    break
                time.sleep(0.05)
            else:
                mgr.stop_watcher()
                pytest.fail("Watcher did not record the invalid config")

            assert mgr.last_error is not None
            assert "retry_max_attempts" in mgr.last_error
            mgr.stop_watcher()


# ---------------------------------------------------------------------------
# Tests: resilience settings validation
# ---------------------------------------------------------------------------


class TestResilienceSettings:
    """Validation of retry / circuit-breaker settings keys."""

    def test_validated_settings_contain_all_fifteen_keys(self):
        """The validated settings dict always exposes all fifteen settings."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            settings = mgr.data["settings"]
            assert set(settings) == {
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
            }

    def test_defaults_applied_when_keys_missing(self):
        """Missing resilience keys fall back to the bundled defaults."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            settings = mgr.data["settings"]
            assert settings["retry_max_attempts"] == 3
            assert settings["retry_backoff_base_seconds"] == 1.0
            assert settings["circuit_breaker_failure_threshold"] == 5
            assert settings["circuit_breaker_timeout_seconds"] == 60.0
            assert settings["max_log_output"] == 4096
            assert settings["compress_rotated"] is True
            assert settings["max_concurrent_ssh_connections"] == 20
            assert settings["watcher_debounce_seconds"] == 2.0

    def test_valid_values_accepted(self):
        """Positive int/float values for the resilience settings load fine."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"].update(
                {
                    "retry_max_attempts": 7,
                    "retry_backoff_base_seconds": 0.5,
                    "circuit_breaker_failure_threshold": 10,
                    "circuit_breaker_timeout_seconds": 120.0,
                    "log_level": "debug",
                    "pool_max_connections_per_target": 10,
                    "pool_idle_timeout_seconds": 600.0,
                    "pool_cleanup_interval_seconds": 30.0,
                    "max_concurrent_ssh_connections": 25,
                    "watcher_debounce_seconds": 5.0,
                }
            )
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            settings = mgr.data["settings"]
            assert settings["retry_max_attempts"] == 7
            assert settings["retry_backoff_base_seconds"] == 0.5
            assert settings["circuit_breaker_failure_threshold"] == 10
            assert settings["circuit_breaker_timeout_seconds"] == 120.0
            assert settings["log_level"] == "DEBUG"
            assert settings["pool_max_connections_per_target"] == 10
            assert settings["pool_idle_timeout_seconds"] == 600.0
            assert settings["pool_cleanup_interval_seconds"] == 30.0
            assert settings["max_concurrent_ssh_connections"] == 25
            assert settings["watcher_debounce_seconds"] == 5.0

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("retry_max_attempts", 0),
            ("retry_max_attempts", "3"),
            ("circuit_breaker_failure_threshold", 0),
            ("circuit_breaker_failure_threshold", 2.5),
            ("retry_backoff_base_seconds", 0),
            ("retry_backoff_base_seconds", -1.0),
            ("retry_backoff_base_seconds", True),
            ("circuit_breaker_timeout_seconds", 0),
            ("circuit_breaker_timeout_seconds", "60"),
            ("circuit_breaker_timeout_seconds", False),
            ("log_level", "VERBOSE"),
            ("log_level", 10),
            ("max_log_output", 0),
            ("max_log_output", "4096"),
            ("max_log_output", -5),
            ("compress_rotated", "yes"),
            ("compress_rotated", 1),
            ("pool_max_connections_per_target", 0),
            ("pool_max_connections_per_target", "5"),
            ("pool_idle_timeout_seconds", 0),
            ("pool_idle_timeout_seconds", -1.0),
            ("pool_idle_timeout_seconds", True),
            ("pool_cleanup_interval_seconds", 0),
            ("pool_cleanup_interval_seconds", "60"),
            ("pool_cleanup_interval_seconds", False),
            ("max_concurrent_ssh_connections", 1.5),
            ("max_concurrent_ssh_connections", 0),
            ("max_concurrent_ssh_connections", "20"),
            ("watcher_debounce_seconds", -1.0),
            ("watcher_debounce_seconds", "2"),
            ("watcher_debounce_seconds", True),
        ],
    )
    def test_invalid_values_rejected(self, key, value):
        """Non-positive or wrongly-typed resilience settings are rejected."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"][key] = value
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    def test_watcher_debounce_zero_is_accepted(self):
        """A zero debounce value is accepted (disables debouncing)."""
        with tempfile.TemporaryDirectory() as td:
            cfg = _minimal_valid_config()
            cfg["settings"]["watcher_debounce_seconds"] = 0
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["watcher_debounce_seconds"] == 0.0


# ---------------------------------------------------------------------------
# Tests: structured config events (config.load / config.reload / watcher)
# ---------------------------------------------------------------------------


class TestStructuredConfigEvents:
    """Structured ``config.*`` events emitted through a BaseLogger."""

    def test_load_emits_config_load_event(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            ConfigManager(td, logger=recorder)

            events = [e for e in recorder.entries if e["event"] == "config.load"]
            assert len(events) == 1
            entry = events[0]
            assert entry["success"] is True
            assert entry["config_path"] == str(Path(td) / "ssh-mcp-config.json")
            assert entry["target_count"] == 1
            assert entry["request_id"] is not None

    def test_default_creation_emits_event(self):
        with tempfile.TemporaryDirectory() as td:
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            events = [e for e in recorder.entries if e["event"] == "config.default_created"]
            assert len(events) == 1
            assert events[0]["success"] is True
            assert events[0]["config_path"] == str(mgr.config_path)
            assert events[0]["source"].endswith("default-config.json")

    def test_reload_emits_diff_summary(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "192.168.1.10"
            _write_config(td, new_cfg)
            assert mgr.reload() is True

            events = [e for e in recorder.entries if e["event"] == "config.reload"]
            assert len(events) == 1
            entry = events[0]
            assert entry["success"] is True
            assert entry["trigger"] == "manual"
            assert entry["changed"] is True
            assert "ssh_targets" in entry["changed_keys"]
            assert entry["targets_added"] == []
            assert entry["targets_removed"] == []
            assert entry["target_count"] == 1

    def test_reload_emits_trigger_value(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.9.9.9"
            _write_config(td, new_cfg)
            assert mgr.reload(trigger="polling") is True

            events = [e for e in recorder.entries if e["event"] == "config.reload"]
            assert events[-1]["trigger"] == "polling"

    def test_reload_failure_emits_failed_event_and_preserves_data(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            broken = _minimal_valid_config()
            del broken["ssh_targets"]
            _write_config(td, broken)
            assert mgr.reload() is False

            events = [e for e in recorder.entries if e["event"] == "config.reload"]
            assert len(events) == 1
            entry = events[0]
            assert entry["success"] is False
            assert "validation failed" in entry["message"]
            assert "changed_keys" not in entry
            # Old data preserved
            assert mgr.data["ssh_targets"]["testbox"]["host"] == "10.0.0.1"

    def test_events_never_leak_secret_values(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["password"] = "hunter2-super-secret"
            new_cfg["ssh_targets"]["newbox"] = {
                "host": "10.0.0.2",
                "username": "root",
                "password": "another-secret",
                "port": 22,
            }
            _write_config(td, new_cfg)
            assert mgr.reload() is True

            serialized = json.dumps(recorder.entries)
            assert "hunter2-super-secret" not in serialized
            assert "another-secret" not in serialized
            assert "secret" not in serialized

    def test_compute_changes_summary(self):
        old_cfg = _minimal_valid_config()
        new_cfg = _minimal_valid_config()
        new_cfg["ssh_targets"]["testbox"]["host"] = "10.1.1.1"
        new_cfg["ssh_targets"]["added_box"] = {
            "host": "10.0.0.9",
            "username": "admin",
            "password": "pw",
            "port": 22,
        }
        del new_cfg["ssh_targets"]["testbox"]

        summary = ConfigManager._compute_changes(old_cfg, new_cfg)
        assert summary["changed"] is True
        assert "ssh_targets" in summary["changed_keys"]
        assert summary["targets_added"] == ["added_box"]
        assert summary["targets_removed"] == ["testbox"]
        assert summary["target_count"] == 1

    def test_compute_changes_no_changes(self):
        cfg = _minimal_valid_config()
        summary = ConfigManager._compute_changes(cfg, _minimal_valid_config())
        assert summary["changed"] is False
        assert summary["changed_keys"] == []
        assert summary["targets_added"] == []
        assert summary["targets_removed"] == []
        assert summary["target_count"] == 1

    def test_watcher_start_stop_emit_events(self):
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)
            mgr.start_watcher(polling_interval=5.0)

            starts = [e for e in recorder.entries if e["event"] == "config.watcher.start"]
            assert len(starts) == 1
            assert starts[0]["success"] is True
            assert starts[0]["config_path"] == str(mgr.config_path)

            mgr.stop_watcher()
            stops = [e for e in recorder.entries if e["event"] == "config.watcher.stop"]
            assert len(stops) == 1
            assert stops[0]["success"] is True

    def test_watcher_handler_reload_emits_watchdog_trigger(self):
        """A watchdog-handler reload carries the ``watchdog`` trigger."""
        from types import SimpleNamespace

        from lib.config_watcher import FileChangeHandler

        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)

            new_cfg = _minimal_valid_config()
            new_cfg["ssh_targets"]["testbox"]["host"] = "10.7.7.7"
            _write_config(td, new_cfg)

            # Drive the handler directly — deterministic, no background race.
            handler = FileChangeHandler(
                config_path=mgr.config_path,
                reload_callback=lambda: mgr.reload(trigger="watchdog"),
                debounce_callback=lambda: False,
                logger=None,
                log_event=lambda event, success, message: recorder.log(
                    {
                        "event": event,
                        "success": success,
                        "message": message,
                        "config_path": str(mgr.config_path),
                    }
                ),
            )
            handler.on_modified(
                SimpleNamespace(is_directory=False, src_path=str(mgr.config_path))
            )

            triggered = [
                e
                for e in recorder.entries
                if e["event"] == "config.watcher.reload_triggered"
            ]
            assert len(triggered) == 1
            reloads = [e for e in recorder.entries if e["event"] == "config.reload"]
            assert reloads[-1]["trigger"] == "watchdog"
            assert mgr.data["ssh_targets"]["testbox"]["host"] == "10.7.7.7"

    def test_file_change_handler_emits_debounced_event(self):
        from types import SimpleNamespace

        from lib.config_watcher import FileChangeHandler

        with tempfile.TemporaryDirectory() as td:
            config_path = _write_config(td, _minimal_valid_config())
            events = []
            handler = FileChangeHandler(
                config_path=Path(config_path),
                reload_callback=lambda: pytest.fail("reload should not fire"),
                debounce_callback=lambda: True,
                log_event=lambda event, success, message: events.append(
                    (event, success)
                ),
            )
            handler.on_modified(
                SimpleNamespace(is_directory=False, src_path=config_path)
            )
            assert events == [("config.watcher.debounced", True)]


# ---------------------------------------------------------------------------
# Tests: SecretsManager integration with ConfigManager
# ---------------------------------------------------------------------------


class TestSecretsIntegration:
    """Integration of SecretsManager with ConfigManager load/reload/validation."""

    def _config_without_auth(self) -> dict:
        """Return a valid config whose testbox target has no password/private_key."""
        cfg = _minimal_valid_config()
        del cfg["ssh_targets"]["testbox"]["password"]
        return cfg

    def test_secrets_merge_applied_before_validation(self):
        """A target password supplied only by secrets.json passes validation."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, self._config_without_auth())
            _write_secrets(
                td,
                {
                    "version": 1,
                    "ssh_targets": {"testbox": {"password": "from-secrets"}},
                },
            )
            mgr = ConfigManager(td)
            assert mgr.data["ssh_targets"]["testbox"]["password"] == "from-secrets"

    def test_missing_secret_password_fails_validation(self):
        """A target with neither config nor secrets credentials is rejected."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, self._config_without_auth())
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    def test_reload_applies_new_secrets(self):
        """Rewriting secrets.json and reloading updates the merged data."""
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, self._config_without_auth())
            _write_secrets(
                td,
                {"version": 1, "ssh_targets": {"testbox": {"password": "first"}}},
            )
            mgr = ConfigManager(td)
            assert mgr.data["ssh_targets"]["testbox"]["password"] == "first"

            _write_secrets(
                td,
                {"version": 1, "ssh_targets": {"testbox": {"password": "second"}}},
            )
            assert mgr.reload() is True
            assert mgr.data["ssh_targets"]["testbox"]["password"] == "second"


# ---------------------------------------------------------------------------
# Tests: MCP_SSH_SETTING_* environment-variable overrides
# ---------------------------------------------------------------------------


class TestSettingEnvOverrides:
    """``MCP_SSH_SETTING_*`` vars override ``settings`` with type coercion."""

    def test_int_override_beats_config_file(self, monkeypatch):
        """An int env var wins over the value written in config.json."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "100")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == 100

    def test_float_override(self, monkeypatch):
        """A float env var is coerced to float."""
        monkeypatch.setenv("MCP_SSH_SETTING_RETRY_BACKOFF_BASE_SECONDS", "2.5")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["retry_backoff_base_seconds"] == 2.5

    def test_bool_override_true(self, monkeypatch):
        """A bool env var accepts the literal ``true``."""
        monkeypatch.setenv("MCP_SSH_SETTING_COMPRESS_ROTATED", "true")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["compress_rotated"] is True

    def test_bool_override_false(self, monkeypatch):
        """A bool env var accepts the literal ``off``."""
        monkeypatch.setenv("MCP_SSH_SETTING_COMPRESS_ROTATED", "off")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["compress_rotated"] is False

    def test_reload_reapplies_env_override(self, monkeypatch):
        """Reload applies the current env value even if config is rewritten."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "123")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == 123
            _write_config(td, _minimal_valid_config())
            assert mgr.reload() is True
            assert mgr.data["settings"]["max_output_length"] == 123

    def test_unknown_key_is_skipped_with_warning(self, monkeypatch):
        """An unrecognised ``MCP_SSH_SETTING_*`` key is ignored, not fatal."""
        monkeypatch.setenv("MCP_SSH_SETTING_NOT_A_REAL_KEY", "nope")
        logger = RecordingLogger()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td, logger=logger)
            assert "not_a_real_key" not in mgr.data["settings"]
        warning_events = [e for e in logger.entries if e.get("log_level") == "WARNING"]
        assert warning_events, "expected a warning event for the unknown env var"
        assert any(
            "MCP_SSH_SETTING_NOT_A_REAL_KEY" in e["message"]
            for e in warning_events
        )

    def test_invalid_value_is_skipped_and_config_preserved(self, monkeypatch):
        """A non-coercible value is ignored; the config value is kept."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "not-an-int")
        logger = RecordingLogger()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td, logger=logger)
            # The invalid env var is skipped, so the config value remains.
            assert mgr.data["settings"]["max_output_length"] == 50000
        warning_events = [e for e in logger.entries if e.get("log_level") == "WARNING"]
        assert warning_events, "expected a warning event for the invalid env var"
        # The offending value must never be logged.
        assert all("not-an-int" not in e["message"] for e in warning_events)

    def test_env_value_never_logged(self, monkeypatch):
        """The env-var value is never leaked into structured events."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "supersecret")
        logger = RecordingLogger()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            ConfigManager(td, logger=logger)
        serialized = json.dumps(logger.entries)
        assert "supersecret" not in serialized

    def test_env_override_size_string(self, monkeypatch):
        """A size-string env var is normalised to a byte count."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "10mb")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == 10 * 1024 * 1024

    def test_env_override_size_string_uppercase(self, monkeypatch):
        """An uppercase size-string env var is parsed case-insensitively."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "1KB")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == 1024

    def test_env_override_invalid_size_skipped_and_config_preserved(self, monkeypatch):
        """An invalid size-string env var is skipped; the config value is kept."""
        monkeypatch.setenv("MCP_SSH_SETTING_MAX_OUTPUT_LENGTH", "10tb")
        logger = RecordingLogger()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td, logger=logger)
            # The invalid env var is skipped, so the config value remains.
            assert mgr.data["settings"]["max_output_length"] == 50000
        warning_events = [e for e in logger.entries if e.get("log_level") == "WARNING"]
        assert warning_events, "expected a warning event for the invalid env var"
        # The offending value must never be logged.
        assert all("10tb" not in e["message"] for e in warning_events)

    def test_watcher_debounce_override(self, monkeypatch):
        """MCP_SSH_SETTING_WATCHER_DEBOUNCE_SECONDS coerces to a float."""
        monkeypatch.setenv("MCP_SSH_SETTING_WATCHER_DEBOUNCE_SECONDS", "3")
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["watcher_debounce_seconds"] == 3.0

    def test_watcher_debounce_override_invalid_skipped(self, monkeypatch):
        """A non-numeric debounce env var is skipped with a warning."""
        monkeypatch.setenv("MCP_SSH_SETTING_WATCHER_DEBOUNCE_SECONDS", "abc")
        logger = RecordingLogger()
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, _minimal_valid_config())
            mgr = ConfigManager(td, logger=logger)
            # The invalid env var is skipped, so the default remains.
            assert mgr.data["settings"]["watcher_debounce_seconds"] == 2.0
        warning_events = [e for e in logger.entries if e.get("log_level") == "WARNING"]
        assert warning_events, "expected a warning event for the invalid env var"
        assert all("abc" not in e["message"] for e in warning_events)


# ---------------------------------------------------------------------------
# Tests: duplicate API-key names and overlapping network CIDRs
# ---------------------------------------------------------------------------


class TestDuplicateAndOverlapValidation:
    """Duplicate api_keys names and overlapping networks CIDRs are rejected."""

    def _api_key(self, name: str, seed: str) -> dict:
        """Return a valid api_keys entry with the given *name* and hash seed."""
        return {
            "name": name,
            "key_hash": "sha256:" + seed * 64,
            "rules": [{"targets": ["*"], "commands": ["hostname"]}],
        }

    def _network(self, name: str, cidr: str) -> dict:
        """Return a valid networks entry with the given *name* and CIDR."""
        return {
            "name": name,
            "range": cidr,
            "rules": [{"targets": ["*"], "commands": ["hostname"]}],
        }

    @pytest.mark.parametrize(
        "names",
        [
            ["key-a", "key-a"],
            ["dupe", "dupe"],
        ],
    )
    def test_duplicate_api_key_names_rejected(self, names):
        """Two api_keys sharing a name raise ConfigValidationError."""
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["api_keys"] = [
            self._api_key(names[0], "0"),
            self._api_key(names[1], "1"),
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError) as exc:
                ConfigManager(td)
        assert "Duplicate API key name" in str(exc.value)
        assert exc.value.field == "api_keys[1].name"

    def test_unique_api_key_names_accepted(self):
        """Distinct api_keys names load successfully (regression guard)."""
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["api_keys"] = [
            self._api_key("key-a", "0"),
            self._api_key("key-b", "1"),
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert len(mgr.data["allowed_commands"]["api_keys"]) == 2

    @pytest.mark.parametrize(
        "cidrs",
        [
            ["10.0.0.0/8", "10.1.0.0/16"],
            ["192.168.0.0/24", "192.168.0.128/25"],
        ],
    )
    def test_overlapping_network_cidrs_rejected(self, cidrs):
        """Two overlapping network ranges raise ConfigValidationError."""
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["networks"] = [
            self._network("net-a", cidrs[0]),
            self._network("net-b", cidrs[1]),
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError) as exc:
                ConfigManager(td)
        assert "overlaps" in str(exc.value)
        assert exc.value.field == "networks[1].range"

    @pytest.mark.parametrize(
        "cidrs",
        [
            ["10.0.0.0/8", "192.168.0.0/16"],
            ["172.16.0.0/12", "198.18.0.0/15"],
        ],
    )
    def test_non_overlapping_network_cidrs_accepted(self, cidrs):
        """Two disjoint network ranges load successfully."""
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["networks"] = [
            self._network("net-a", cidrs[0]),
            self._network("net-b", cidrs[1]),
        ]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert len(mgr.data["allowed_commands"]["networks"]) == 2


class TestMaxOutputLengthValidation:
    """``settings.max_output_length`` accepts ints or size strings (b/kb/mb/gb)."""

    def test_accepts_integer(self) -> None:
        """A plain integer byte count is accepted unchanged."""
        cfg = _minimal_valid_config()
        cfg["settings"]["max_output_length"] = 50000
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == 50000

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("50kb", 50 * 1024),
            ("10MB", 10 * 1024 * 1024),
            ("1gb", 1024 * 1024 * 1024),
            ("2048", 2048),
        ],
    )
    def test_accepts_size_string(self, raw: str, expected: int) -> None:
        """A size string is normalised to a byte count."""
        cfg = _minimal_valid_config()
        cfg["settings"]["max_output_length"] = raw
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert mgr.data["settings"]["max_output_length"] == expected

    @pytest.mark.parametrize("raw", ["50tb", "abc", "", "50.5kb", "-50kb"])
    def test_rejects_invalid_size_string(self, raw: str) -> None:
        """An invalid size string raises :class:`ConfigValidationError`."""
        cfg = _minimal_valid_config()
        cfg["settings"]["max_output_length"] = raw
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    @pytest.mark.parametrize("raw", ["0", "0kb", "0mb"])
    def test_rejects_nonpositive(self, raw: str) -> None:
        """A size resolving to fewer than one byte is rejected."""
        cfg = _minimal_valid_config()
        cfg["settings"]["max_output_length"] = raw
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    @pytest.mark.parametrize("bad", [None, True, False, 12.5, [], {}])
    def test_rejects_wrong_types(self, bad: object) -> None:
        """Non-int / non-str values are rejected."""
        cfg = _minimal_valid_config()
        cfg["settings"]["max_output_length"] = bad
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)


class TestFilePermissions:
    """File-permission warning and ``--fix-permissions`` behavior."""

    def test_insecure_config_permissions_warn(self):
        """A group/world-readable config emits a ``config.permissions_insecure`` warning."""
        with tempfile.TemporaryDirectory() as td:
            conf = _write_config(td, _minimal_valid_config())
            os.chmod(conf, 0o644)
            recorder = RecordingLogger()
            ConfigManager(td, logger=recorder)

            events = [e for e in recorder.entries if e["event"] == "config.permissions_insecure"]
            assert len(events) == 1
            assert events[0]["log_level"] == "WARNING"
            assert events[0]["success"] is False
            assert events[0]["mode"] == "0o644"

    def test_secure_config_permissions_no_warning(self):
        """A correctly restricted (0o600) config emits no ``permissions_insecure`` event."""
        with tempfile.TemporaryDirectory() as td:
            conf = _write_config(td, _minimal_valid_config())
            os.chmod(conf, _RESTRICTED)
            recorder = RecordingLogger()
            ConfigManager(td, logger=recorder)

            events = [e for e in recorder.entries if e["event"] == "config.permissions_insecure"]
            assert events == []

    def test_fix_permissions_corrects_mode(self):
        """``fix_permissions=True`` chmods an insecure config to 0o600."""
        with tempfile.TemporaryDirectory() as td:
            conf = _write_config(td, _minimal_valid_config())
            _write_secrets(td, {})
            os.chmod(conf, 0o644)
            recorder = RecordingLogger()
            ConfigManager(td, logger=recorder, fix_permissions=True)

            assert os.stat(conf).st_mode & 0o777 == _RESTRICTED
            events = [e for e in recorder.entries if e["event"] == "config.permissions_fixed"]
            assert len(events) >= 1
            assert events[0]["fixed_mode"] == "0o600"

    def test_fix_permissions_reports_changed_paths(self):
        """``fix_permissions()`` returns every config/secrets path it corrected."""
        with tempfile.TemporaryDirectory() as td:
            conf = _write_config(td, _minimal_valid_config())
            sec = _write_secrets(td, {})
            os.chmod(conf, 0o644)
            os.chmod(sec, 0o644)
            mgr = ConfigManager(td)

            changed = mgr.fix_permissions()
            changed_set = {str(p) for p in changed}
            assert str(Path(conf)) in changed_set
            assert str(Path(sec)) in changed_set

    def test_reload_warns_on_insecure_permissions(self):
        """``reload()`` also warns when the config stays insecure."""
        with tempfile.TemporaryDirectory() as td:
            conf = _write_config(td, _minimal_valid_config())
            os.chmod(conf, 0o644)
            recorder = RecordingLogger()
            mgr = ConfigManager(td, logger=recorder)
            mgr.reload()

            events = [e for e in recorder.entries if e["event"] == "config.permissions_insecure"]
            assert len(events) >= 1


# ---------------------------------------------------------------------------
# Tests: ConfigValidationError sanitization (API-safe messages)
# ---------------------------------------------------------------------------


class TestConfigValidationErrorSanitization:
    """`ConfigValidationError` messages never leak raw values while ``field=``
    stays intact as the structured, machine-readable channel."""

    @pytest.mark.parametrize(
        ("mutate", "raw_value", "expected_field"),
        [
            # Wrong-typed port -> the offending int must not appear in the message.
            (
                lambda cfg: cfg["ssh_targets"]["testbox"].update(
                    {"port": 99999, "password": "secret"}
                ),
                "99999",
                "ssh_targets.testbox.port",
            ),
            # Empty host -> nothing sensitive, but field must be present.
            (
                lambda cfg: cfg["ssh_targets"]["testbox"].update(
                    {"host": "   ", "password": "secret"}
                ),
                "   ",
                "ssh_targets.testbox.host",
            ),
            # Invalid CIDR -> the raw CIDR string must not leak.
            (
                lambda cfg: cfg["allowed_commands"].update(
                    {
                        "networks": [
                            {
                                "name": "bad",
                                "range": "999.999.999.999/999",
                                "rules": [
                                    {"targets": ["*"], "commands": ["ls"]}
                                ],
                            }
                        ]
                    }
                ),
                "999.999.999.999/999",
                "networks[0].range",
            ),
            # Bad max_output_length -> the raw value must not leak.
            (
                lambda cfg: cfg["settings"].update({"max_output_length": -5}),
                "-5",
                "settings.max_output_length",
            ),
        ],
    )
    def test_offending_value_not_leaked(
        self, mutate, raw_value: str, expected_field: str
    ) -> None:
        """The raw offending value never appears in the message, while
        ``field=`` still carries the structured, machine-readable path."""
        cfg = _minimal_valid_config()
        mutate(cfg)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError) as exc:
                ConfigManager(td)
        message = str(exc.value)
        assert raw_value not in message
        assert exc.value.field == expected_field
        assert exc.value.field


# ---------------------------------------------------------------------------
# Server name validation at config load time
# ---------------------------------------------------------------------------


def _config_with_target_name(name: object) -> dict:
    """Return a minimal-valid config whose first ssh_target uses *name*.

    ``name`` may be any JSON value; it is spliced in as the ssh_targets key so
    the new load-time server-name checks are exercised directly.
    """
    cfg = _minimal_valid_config()
    cfg["ssh_targets"] = {name: cfg["ssh_targets"].pop("testbox")}
    return cfg


class TestTargetNameValidation:
    """Target names are validated for type, length, and allowed characters when
    the config is loaded -- not only at runtime via ``sanitize_target_name``."""

    @pytest.mark.parametrize(
        "name",
        [
            "bad name",        # space
            "bad@name",        # at sign
            "bad#name",        # hash
            "bad!name",        # bang
            "bad/name",        # slash
            "bad\\name",       # backslash
            "bad;name",        # semicolon
            "bad&name",        # ampersand
            "bad|name",        # pipe
            "bad$name",        # dollar
            "ünïcode",         # non-ASCII letters
            "名字",            # CJK characters
            "bad.name/hack",   # mixed valid + slash
        ],
    )
    def test_invalid_characters_raise(self, name: str) -> None:
        """Names with disallowed characters are rejected at load time."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    @pytest.mark.parametrize(
        "name",
        [
            "h" * 129,  # one char beyond the 128 limit
            "host.name_" * 15 + "tok",  # 15*9+3 = 138, also over length
        ],
    )
    def test_over_length_name_raises(self, name: str) -> None:
        """Names longer than MAX_TARGET_NAME_LENGTH are rejected."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    @pytest.mark.parametrize(
        "name",
        [
            "h" * 128,  # exactly the max length -> valid
        ],
    )
    def test_boundary_max_length_valid(self, name: str) -> None:
        """A name of exactly MAX_TARGET_NAME_LENGTH loads successfully."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert name in mgr.data["ssh_targets"]

    @pytest.mark.parametrize(
        "name",
        [
            "h" * 129,  # one char beyond the 128 limit
        ],
    )
    def test_boundary_max_length_plus_one_raises(self, name: str) -> None:
        """A name one char beyond MAX_TARGET_NAME_LENGTH is rejected."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError):
                ConfigManager(td)

    @pytest.mark.parametrize(
        "name",
        [
            "host1",
            "host_1.beta-x",
            "HOST1.2-3_4",
            "a",
            "Z",  # single uppercase
            "0",  # single digit
            "a-b_c.d",
            "42.42-42_42",
        ],
    )
    def test_valid_names_load(self, name: str) -> None:
        """Names using only letters, digits, '.', '_', '-' load successfully."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            mgr = ConfigManager(td)
            assert name in mgr.data["ssh_targets"]

    @pytest.mark.parametrize(
        "name",
        [
            "log\ninject",       # newline
            "log\rinject",       # carriage return
            "log\x00inject",     # null byte
            "a\nb\rc\x00d",      # mixed control characters
        ],
    )
    def test_log_injection_names_raise(self, name: str) -> None:
        """Names containing log-injection control bytes are rejected and do not
        leak into the error message."""
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError) as exc:
                ConfigManager(td)
        # The raw poisoned name must never appear in the error text.
        assert name not in str(exc.value)

    @pytest.mark.parametrize(
        "name",
        [123, 4.5, True, None],
    )
    def test_non_string_name_raises(self, name: object) -> None:
        """Non-string target names are rejected.

        The type check cannot be exercised through the JSON file path because
        ``json.dumps`` coerces dict keys to strings (``123`` loads as ``"123"``,
        which is a valid name). Calling ``_validate()`` directly with an
        in-memory dict keeps the key as its original type.
        """
        cfg = _config_with_target_name(name)
        with tempfile.TemporaryDirectory() as td:
            mgr = ConfigManager(td)
            with pytest.raises(ConfigValidationError):
                mgr._validate(cfg)


class TestResourceLimits:
    """Validate that config resource limits are enforced."""

    # -- SSH target count limits --

    def test_exactly_max_targets_accepted(self) -> None:
        """A config with exactly MAX_TARGETS targets loads successfully."""
        targets = {
            f"host{i}": {
                "host": f"10.0.{i // 256}.{i % 256}",
                "username": "admin",
                "password": "secret",
                "port": 22,
            }
            for i in range(MAX_TARGETS)
        }
        cfg = _minimal_valid_config(ssh_targets=targets)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            ConfigManager(td)

    def test_max_targets_plus_one_rejected(self) -> None:
        """A config with MAX_TARGETS + 1 targets is rejected."""
        targets = {
            f"host{i}": {
                "host": f"10.0.{i // 256}.{i % 256}",
                "username": "admin",
                "password": "secret",
                "port": 22,
            }
            for i in range(MAX_TARGETS + 1)
        }
        cfg = _minimal_valid_config(ssh_targets=targets)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="ssh_targets must not exceed"):
                ConfigManager(td)

    # -- Block pattern count limits --

    def test_exactly_max_block_patterns_accepted(self) -> None:
        """A config with exactly MAX_BLOCK_PATTERNS patterns loads."""
        patterns = [f"pattern{i}" for i in range(MAX_BLOCK_PATTERNS)]
        cfg = _minimal_valid_config(block_patterns=patterns)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            ConfigManager(td)

    def test_max_block_patterns_plus_one_rejected(self) -> None:
        """A config with MAX_BLOCK_PATTERNS + 1 patterns is rejected."""
        patterns = [f"pattern{i}" for i in range(MAX_BLOCK_PATTERNS + 1)]
        cfg = _minimal_valid_config(block_patterns=patterns)
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="block_patterns must not exceed"):
                ConfigManager(td)

    # -- Regex pattern length limits --

    def test_exactly_max_regex_pattern_length_accepted(self) -> None:
        """A regex of exactly MAX_REGEX_PATTERN_LENGTH chars loads."""
        long_pattern = "a" * MAX_REGEX_PATTERN_LENGTH
        cfg = _minimal_valid_config(block_patterns=[long_pattern])
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            ConfigManager(td)

    def test_max_regex_pattern_length_plus_one_rejected(self) -> None:
        """A regex of MAX_REGEX_PATTERN_LENGTH + 1 chars is rejected."""
        long_pattern = "a" * (MAX_REGEX_PATTERN_LENGTH + 1)
        cfg = _minimal_valid_config(block_patterns=[long_pattern])
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="exceeds.*character limit"):
                ConfigManager(td)
