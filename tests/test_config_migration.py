"""Tests for lib.config_migration — config schema version migration.

Covers :func:`get_config_version`, :func:`migrate_config` (including the
registered v1→v2 placeholder), the atomic backup / rewrite helpers, and the
end-to-end migration hook wired into :class:`lib.config.ConfigManager`.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

import lib.config_migration
import lib.config
from lib.config import ConfigManager
from lib.config_migration import (
    MIGRATIONS,
    _migrate_v1_to_v2,
    backup_config_file,
    get_config_version,
    migrate_config,
    write_migrated_config,
)
from lib.constants import CONFIG_BACKUP_SUFFIX, LATEST_CONFIG_VERSION
from lib.exceptions import ConfigMigrationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_config(**overrides) -> dict:
    """Return a minimal, migration-relevant config dict."""
    cfg = {
        "version": 1,
        "ssh_targets": {
            "testbox": {
                "host": "10.0.0.1",
                "username": "admin",
                "password": "secret",
            },
        },
        "block_patterns": ["\\brm\\s+-rf\\b"],
        "allowed_commands": {
            "default": [{"targets": ["*"], "commands": ["hostname"]}],
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


def _write_config_dir(config_dict: dict) -> str:
    """Write *config_dict* to a temp dir and return the temp dir path."""
    td = tempfile.mkdtemp()
    path = Path(td) / "ssh-mcp-config.json"
    path.write_text(json.dumps(config_dict), encoding="utf-8")
    return td


class RecordingLogger:
    """Duck-typed :class:`~lib.loggers.BaseLogger` that records entries."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, entry: dict) -> None:
        self.entries.append(entry)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# get_config_version
# ---------------------------------------------------------------------------


class TestGetConfigVersion:
    def test_missing_version_defaults_to_one(self):
        """A config without a ``version`` key is treated as v1."""
        assert get_config_version({"ssh_targets": {}}) == 1

    def test_positive_integer_accepted(self):
        assert get_config_version({"version": 1}) == 1
        assert get_config_version({"version": 7}) == 7

    def test_non_integer_rejected(self):
        """A string version, a float, or None-in-value is rejected."""
        for bad in ("1", 1.0, "abc"):
            with pytest.raises(ConfigMigrationError, match="version"):
                get_config_version({"version": bad})

    def test_bool_rejected(self):
        """``bool`` is a subclass of ``int`` and must be rejected."""
        with pytest.raises(ConfigMigrationError, match="version"):
            get_config_version({"version": True})

    def test_version_below_one_rejected(self):
        for bad in (0, -3):
            with pytest.raises(ConfigMigrationError, match="version"):
                get_config_version({"version": bad})


# ---------------------------------------------------------------------------
# Migrations & migrate_config
# ---------------------------------------------------------------------------


class TestMigrations:
    def test_v1_to_v2_is_registered_for_v1(self):
        """The placeholder migration is registered for starting version 1."""
        assert 1 in MIGRATIONS

    def test_v1_to_v2_bumps_version_and_copies(self):
        """The placeholder copies the dict and sets version to 2."""
        cfg = _minimal_config()
        migrated = _migrate_v1_to_v2(cfg)
        assert migrated["version"] == 2
        assert migrated["ssh_targets"] == cfg["ssh_targets"]

    def test_v1_to_v2_does_not_mutate_input(self):
        """Migration must never mutate the input dict."""
        cfg = _minimal_config()
        original = {"version": 1, "ssh_targets": dict(cfg["ssh_targets"])}
        _migrate_v1_to_v2(original)
        assert original == {"version": 1, "ssh_targets": cfg["ssh_targets"]}


class TestMigrateConfig:
    def test_already_current_returns_same_object(self):
        """When config already equals latest, the SAME object is returned."""
        cfg = _minimal_config(version=LATEST_CONFIG_VERSION)
        result = migrate_config(cfg)
        assert result is cfg

    def test_newer_than_latest_raises(self):
        """A config newer than the release's latest raises a hard error."""
        cfg = {"version": LATEST_CONFIG_VERSION + 5}
        with pytest.raises(ConfigMigrationError, match="newer"):
            migrate_config(cfg)

    def test_placeholder_runs_when_latest_is_two(self, monkeypatch):
        """With latest bumped to 2, a v1 config migrates to v2."""
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 2)
        cfg = _minimal_config(version=1)
        result = migrate_config(cfg)
        assert result is not cfg
        assert result["version"] == 2

    def test_migration_does_not_mutate_input(self, monkeypatch):
        """migrate_config returns a fresh dict without altering the input."""
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 2)
        cfg = _minimal_config(version=1)
        migrate_config(cfg)
        assert cfg["version"] == 1

    def test_missing_migration_raises(self, monkeypatch):
        """No registered migration for a version below latest raises."""
        # latest is 3 here, but no migration from 2 -> 3 is registered
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 3)
        cfg = {"version": 2}
        with pytest.raises(ConfigMigrationError, match="No migration"):
            migrate_config(cfg)


# ---------------------------------------------------------------------------
# backup_config_file
# ---------------------------------------------------------------------------


class TestBackupConfigFile:
    def test_creates_backup_with_suffix(self, tmp_path):
        src = tmp_path / "config.json"
        src.write_text("{\"a\": 1}", encoding="utf-8")
        result = backup_config_file(src)
        assert result is not None
        assert result == Path(str(src) + CONFIG_BACKUP_SUFFIX)
        assert result.read_text(encoding="utf-8") == "{\"a\": 1}"

    def test_backup_not_overwritten(self, tmp_path):
        """An existing .bak sentinel is never overwritten."""
        src = tmp_path / "config.json"
        src.write_text("new", encoding="utf-8")
        backup = Path(str(src) + CONFIG_BACKUP_SUFFIX)
        backup.write_text("sentinel", encoding="utf-8")
        assert backup_config_file(src) is None
        assert backup.read_text(encoding="utf-8") == "sentinel"

    def test_missing_source_returns_none(self, tmp_path):
        src = tmp_path / "does-not-exist.json"
        assert backup_config_file(src) is None

    def test_backup_has_restricted_mode(self, tmp_path):
        src = tmp_path / "config.json"
        src.write_text("data", encoding="utf-8")
        result = backup_config_file(src)
        assert result is not None
        assert (result.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# write_migrated_config
# ---------------------------------------------------------------------------


class TestWriteMigratedConfig:
    def test_writes_json_and_version(self, tmp_path):
        dst = tmp_path / "ssh-mcp-config.json"
        migrated = _minimal_config(version=LATEST_CONFIG_VERSION)
        write_migrated_config(dst, migrated)
        on_disk = json.loads(dst.read_text(encoding="utf-8"))
        assert on_disk["version"] == LATEST_CONFIG_VERSION
        assert "testbox" in on_disk["ssh_targets"]

    def test_creates_parent_directories(self, tmp_path):
        dst = tmp_path / "nested" / "deeper" / "config.json"
        write_migrated_config(dst, {"version": LATEST_CONFIG_VERSION})
        assert dst.exists()

    def test_written_file_has_restricted_mode(self, tmp_path):
        dst = tmp_path / "config.json"
        write_migrated_config(dst, {"version": LATEST_CONFIG_VERSION})
        assert (dst.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# End-to-end via ConfigManager
# ---------------------------------------------------------------------------


class TestConfigManagerMigration:
    def test_load_current_version_no_migration(self, tmp_path):
        """A config already at the latest version loads unchanged."""
        cfg = _minimal_config(version=LATEST_CONFIG_VERSION)
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        mgr = ConfigManager(str(tmp_path))
        assert mgr.data["version"] == LATEST_CONFIG_VERSION
        # No backup should be created when no migration is needed
        assert not (tmp_path / ("ssh-mcp-config.json" + CONFIG_BACKUP_SUFFIX)).exists()

    def test_load_missing_version_treated_as_v1(self, tmp_path):
        """A config without a version key loads fine (treated as v1)."""
        cfg = _minimal_config()
        del cfg["version"]
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        mgr = ConfigManager(str(tmp_path))
        assert mgr.data["version"] == LATEST_CONFIG_VERSION
        assert "testbox" in mgr.data["ssh_targets"]

    def test_load_newer_version_raises(self, tmp_path):
        """A config newer than this release raises on load."""
        cfg = _minimal_config(version=LATEST_CONFIG_VERSION + 1)
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")
        with pytest.raises(Exception):
            ConfigManager(str(tmp_path))

    def test_migration_persists_and_backs_up(self, tmp_path, monkeypatch):
        """A v1 config is migrated, backed up, and rewritten in place."""
        # Simulate the next schema release: latest becomes 2 and the
        # v1->v2 placeholder migration actually runs.
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 2)
        monkeypatch.setattr(lib.config, "LATEST_CONFIG_VERSION", 2)

        cfg = _minimal_config(version=1)
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        mgr = ConfigManager(str(tmp_path))
        # In-memory config is at the new latest version
        assert mgr.data["version"] == 2
        # Original config file was rewritten to the migrated version
        on_disk = json.loads(config_path.read_text(encoding="utf-8"))
        assert on_disk["version"] == 2
        # A pre-migration backup was left in place with the original version
        backup = tmp_path / ("ssh-mcp-config.json" + CONFIG_BACKUP_SUFFIX)
        assert backup.exists()
        assert json.loads(backup.read_text(encoding="utf-8"))["version"] == 1

    def test_migration_idempotent_on_fresh_manager(self, tmp_path, monkeypatch):
        """A second manager sees the already-migrated config and does not re-migrate."""
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 2)
        monkeypatch.setattr(lib.config, "LATEST_CONFIG_VERSION", 2)

        cfg = _minimal_config(version=1)
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        ConfigManager(str(tmp_path))  # first load migrates + persists
        # Second, fresh manager loads the persisted (already migrated) file
        mgr2 = ConfigManager(str(tmp_path))
        assert mgr2.data["version"] == 2

    def test_migration_emits_log_event(self, tmp_path, monkeypatch):
        """A persisted migration emits a ``config.migrated`` event."""
        monkeypatch.setattr(lib.config_migration, "LATEST_CONFIG_VERSION", 2)
        monkeypatch.setattr(lib.config, "LATEST_CONFIG_VERSION", 2)

        logger = RecordingLogger()
        cfg = _minimal_config(version=1)
        config_path = tmp_path / "ssh-mcp-config.json"
        config_path.write_text(json.dumps(cfg), encoding="utf-8")

        ConfigManager(str(tmp_path), logger=logger)
        migrated_events = [
            e for e in logger.entries if e.get("event") == "config.migrated"
        ]
        assert migrated_events, "expected a config.migrated event"
        event = migrated_events[0]
        assert event["from_version"] == 1
        assert event["to_version"] == 2
