"""Tests for lib.config — ConfigManager validation, loading, and query methods."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

from lib.config import ConfigManager, ConfigValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmpdir: str, config_dict: dict) -> str:
    """Write *config_dict* as ``ssh-mcp-config.json`` inside *tmpdir*."""
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


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
# Tests: validation failures
# ---------------------------------------------------------------------------


class TestValidationFailures:
    def test_validation_fails_missing_version(self):
        cfg = _minimal_valid_config()
        del cfg["version"]
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="version"):
                ConfigManager(td)

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
            {"name": "bad", "range": "not-a-cidr", "rules": [{"targets": ["*"], "commands": ["ls"]}]}
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

    def test_validation_fails_invalid_key_hash(self):
        cfg = _minimal_valid_config()
        cfg["allowed_commands"]["api_keys"] = [
            {"name": "k1", "key_hash": "bad-hash-format", "rules": [{"targets": ["*"], "commands": ["ls"]}]}
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
            with pytest.raises(ConfigValidationError, match="unknown.*ssh_target.*ghost"):
                ConfigManager(td)

    def test_validation_fails_unknown_top_level_key(self):
        cfg = _minimal_valid_config()
        cfg["bogus_key"] = "unexpected"
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="Unknown top-level key.*bogus_key"):
                ConfigManager(td)

    def test_validation_fails_unknown_ssh_target_key(self):
        cfg = _minimal_valid_config()
        cfg["ssh_targets"]["testbox"]["extra_field"] = "no"
        with tempfile.TemporaryDirectory() as td:
            _write_config(td, cfg)
            with pytest.raises(ConfigValidationError, match="Unknown key.*extra_field"):
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
            del broken["version"]
            _write_config(td, broken)

            assert mgr.reload() is False
            assert mgr.data["ssh_targets"]["testbox"]["host"] == original_host


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
            del broken["version"]
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
            del broken["version"]
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
            del broken["version"]
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

    def test_validated_settings_contain_all_twelve_keys(self):
        """The validated settings dict always exposes all twelve settings."""
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
