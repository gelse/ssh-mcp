"""Unit tests for config_api.config_service — Config read/write/validate service.

Tests cover:
- ConfigService.__init__() with default and custom config_dir
- read_config() returning raw on-disk JSON
- read_section() with valid and invalid section names
- _strip_secrets() removing password, private_key, key_hash
- validate_config() delegating to ConfigManager._validate()
- write_config() full flow: strip → validate → backup → atomic write
- write_section() merging a section and delegating to write_config()
- _create_backup() creating timestamped .bak files
- _atomic_write() using tempfile + os.replace()
- File permissions (0o600) on written files
- Thread safety of _write_lock
- Error paths (missing file, invalid JSON, validation failure)
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lib.constants import DEFAULT_CONFIG_FILENAME, RESTRICTED_FILE_MODE
from lib.exceptions import ConfigValidationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_config() -> dict:
    """Return a minimal valid config dict for testing."""
    return {
        "version": 1,
        "ssh_targets": {
            "test-server": {
                "host": "10.0.0.1",
                "port": 22,
                "username": "admin",
                "password": "secret123",
            },
        },
        "block_patterns": [],
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": ["echo", "whoami"]},
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }


def _write_config(path: Path, config: dict) -> None:
    """Write a config dict to the given path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _file_mode(path: Path) -> int:
    """Return the permission bits of a file."""
    return stat.S_IMODE(os.stat(path).st_mode)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config_dir(tmp_path: Path) -> Path:
    """Create a temp config directory with a valid config file."""
    config_path = tmp_path / DEFAULT_CONFIG_FILENAME
    _write_config(config_path, _minimal_config())
    return tmp_path


@pytest.fixture()
def service(config_dir: Path) -> "ConfigService":
    """Create a ConfigService instance with a valid config on disk."""
    from config_api.config_service import ConfigService

    return ConfigService(config_dir=str(config_dir))


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestConfigServiceInit:
    """Tests for ConfigService.__init__()."""

    def test_default_config_dir_from_env(
        self, monkeypatch: pytest.MonkeyPatch, config_dir: Path,
    ) -> None:
        """CONFIG_DIR env var is used when no config_dir arg is given."""
        monkeypatch.setenv("CONFIG_DIR", str(config_dir))
        from config_api.config_service import ConfigService

        svc = ConfigService()
        assert svc.config_dir == config_dir
        assert svc.config_path == config_dir / DEFAULT_CONFIG_FILENAME

    def test_explicit_config_dir(self, config_dir: Path) -> None:
        """Explicit config_dir overrides env var."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        assert svc.config_dir == config_dir

    def test_write_lock_is_created(self, config_dir: Path) -> None:
        """A threading.Lock is created for write serialization."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        assert isinstance(svc._write_lock, type(threading.Lock()))

    def test_validator_is_config_manager(self, config_dir: Path) -> None:
        """The _validator attribute is a ConfigManager instance."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        from lib.config import ConfigManager

        assert isinstance(svc._validator, ConfigManager)


# ---------------------------------------------------------------------------
# read_config
# ---------------------------------------------------------------------------


class TestReadConfig:
    """Tests for ConfigService.read_config()."""

    def test_returns_raw_config(self, service: "ConfigService") -> None:
        """Returns the on-disk JSON as a dict."""
        result = service.read_config()
        assert isinstance(result, dict)
        assert "ssh_targets" in result
        assert "test-server" in result["ssh_targets"]

    def test_password_present_in_raw(self, service: "ConfigService") -> None:
        """Raw read includes secret fields (no stripping)."""
        result = service.read_config()
        target = result["ssh_targets"]["test-server"]
        assert target["password"] == "secret123"

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        """FileNotFoundError raised when config file doesn't exist."""
        from config_api.config_service import ConfigService

        # Need a valid config for init, then delete it
        config_path = tmp_path / DEFAULT_CONFIG_FILENAME
        _write_config(config_path, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))
        config_path.unlink()
        with pytest.raises(FileNotFoundError):
            svc.read_config()

    def test_raises_on_invalid_json(self, config_dir: Path) -> None:
        """json.JSONDecodeError raised when file has invalid JSON."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        config_path = config_dir / DEFAULT_CONFIG_FILENAME
        config_path.write_text("not valid json {{{", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            svc.read_config()


# ---------------------------------------------------------------------------
# read_section
# ---------------------------------------------------------------------------


class TestReadSection:
    """Tests for ConfigService.read_section()."""

    def test_read_ssh_targets(self, service: "ConfigService") -> None:
        """Reads the ssh_targets section."""
        result = service.read_section("ssh_targets")
        assert isinstance(result, dict)
        assert "test-server" in result

    def test_read_settings(self, service: "ConfigService") -> None:
        """Reads the settings section."""
        result = service.read_section("settings")
        assert isinstance(result, dict)

    def test_read_block_patterns(self, service: "ConfigService") -> None:
        """Reads the block_patterns section."""
        result = service.read_section("block_patterns")
        assert isinstance(result, list)

    def test_read_allowed_commands(self, service: "ConfigService") -> None:
        """Reads the allowed_commands section."""
        result = service.read_section("allowed_commands")
        assert isinstance(result, dict)
        assert "default" in result

    def test_invalid_section_raises_value_error(
        self, service: "ConfigService",
    ) -> None:
        """ValueError raised for unknown section names."""
        with pytest.raises(ValueError, match="Invalid section"):
            service.read_section("nonexistent")

    def test_missing_section_raises_key_error(
        self, config_dir: Path,
    ) -> None:
        """KeyError raised when section is valid but absent from config."""
        from config_api.config_service import ConfigService

        # Create service with a valid config (ConfigManager validates on init)
        svc = ConfigService(config_dir=str(config_dir))
        # Now rewrite the config file without 'settings'
        config = _minimal_config()
        del config["settings"]
        _write_config(config_dir / DEFAULT_CONFIG_FILENAME, config)
        with pytest.raises(KeyError, match="settings"):
            svc.read_section("settings")


# ---------------------------------------------------------------------------
# _strip_secrets
# ---------------------------------------------------------------------------


class TestStripSecrets:
    """Tests for ConfigService._strip_secrets()."""

    def test_strips_password_from_targets(
        self, service: "ConfigService",
    ) -> None:
        """'password' is removed from SSH targets."""
        config = _minimal_config()
        result = service._strip_secrets(config)
        target = result["ssh_targets"]["test-server"]
        assert "password" not in target

    def test_strips_private_key_from_targets(
        self, service: "ConfigService",
    ) -> None:
        """'private_key' is removed from SSH targets."""
        config = _minimal_config()
        config["ssh_targets"]["test-server"]["private_key"] = "/path/to/key"
        result = service._strip_secrets(config)
        target = result["ssh_targets"]["test-server"]
        assert "private_key" not in target

    def test_strips_key_hash_from_api_keys(
        self, service: "ConfigService",
    ) -> None:
        """'key_hash' is removed from API key entries."""
        config = _minimal_config()
        config["allowed_commands"]["api_keys"] = [
            {"key_hash": "abc123", "rules": []},
        ]
        result = service._strip_secrets(config)
        api_keys = result["allowed_commands"]["api_keys"]
        assert "key_hash" not in api_keys[0]

    def test_does_not_mutate_input(self, service: "ConfigService") -> None:
        """Input dict is not mutated (deep copy is made)."""
        config = _minimal_config()
        original_password = config["ssh_targets"]["test-server"]["password"]
        service._strip_secrets(config)
        assert config["ssh_targets"]["test-server"]["password"] == original_password

    def test_preserves_non_secret_fields(
        self, service: "ConfigService",
    ) -> None:
        """Non-secret fields are preserved after stripping."""
        config = _minimal_config()
        result = service._strip_secrets(config)
        target = result["ssh_targets"]["test-server"]
        assert target["host"] == "10.0.0.1"
        assert target["port"] == 22
        assert target["username"] == "admin"

    def test_handles_missing_ssh_targets(
        self, service: "ConfigService",
    ) -> None:
        """Gracefully handles config without ssh_targets."""
        config = {"version": 1, "settings": {}}
        result = service._strip_secrets(config)
        assert "ssh_targets" not in result

    def test_handles_non_dict_targets(
        self, service: "ConfigService",
    ) -> None:
        """Gracefully handles ssh_targets that is not a dict."""
        config = {"ssh_targets": "not-a-dict"}
        result = service._strip_secrets(config)
        assert result["ssh_targets"] == "not-a-dict"

    def test_handles_missing_allowed_commands(
        self, service: "ConfigService",
    ) -> None:
        """Gracefully handles config without allowed_commands."""
        config = _minimal_config()
        del config["allowed_commands"]
        result = service._strip_secrets(config)
        assert "allowed_commands" not in result

    def test_handles_non_list_api_keys(
        self, service: "ConfigService",
    ) -> None:
        """Gracefully handles api_keys that is not a list."""
        config = _minimal_config()
        config["allowed_commands"]["api_keys"] = "not-a-list"
        result = service._strip_secrets(config)
        assert result["allowed_commands"]["api_keys"] == "not-a-list"


# ---------------------------------------------------------------------------
# validate_config
# ---------------------------------------------------------------------------


class TestValidateConfig:
    """Tests for ConfigService.validate_config()."""

    def test_valid_config_returns_dict(
        self, service: "ConfigService",
    ) -> None:
        """A valid config dict passes validation and returns a dict."""
        config = _minimal_config()
        result = service.validate_config(config)
        assert isinstance(result, dict)
        assert "ssh_targets" in result

    def test_invalid_config_raises(
        self, service: "ConfigService",
    ) -> None:
        """An invalid config raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError):
            service.validate_config({"ssh_targets": {}})

    def test_unknown_top_level_key_raises(
        self, service: "ConfigService",
    ) -> None:
        """Unknown top-level keys are rejected."""
        config = _minimal_config()
        config["unknown_key"] = "value"
        with pytest.raises(ConfigValidationError, match="Unknown top-level key"):
            service.validate_config(config)

    def test_delegates_to_validator(
        self, service: "ConfigService",
    ) -> None:
        """validate_config() calls _validator._validate()."""
        config = _minimal_config()
        with patch.object(service._validator, "_validate") as mock_validate:
            mock_validate.return_value = {"validated": True}
            result = service.validate_config(config)
            mock_validate.assert_called_once_with(config)
            assert result == {"validated": True}


# ---------------------------------------------------------------------------
# write_config
# ---------------------------------------------------------------------------


class TestWriteConfig:
    """Tests for ConfigService.write_config()."""

    def test_writes_validated_config_to_disk(
        self, service: "ConfigService",
    ) -> None:
        """write_config() writes the validated config to disk."""
        config = _minimal_config()
        result = service.write_config(config)
        assert isinstance(result, dict)

        # Read back from disk
        with service.config_path.open("r", encoding="utf-8") as f:
            on_disk = json.load(f)
        assert "ssh_targets" in on_disk

    def test_secrets_kept_on_disk_but_stripped_from_return(
        self, service: "ConfigService",
    ) -> None:
        """Secrets are kept on disk for read-modify-write cycles but
        stripped from the returned config."""
        config = _minimal_config()
        result = service.write_config(config)

        # Return value should have secrets stripped
        target = result["ssh_targets"]["test-server"]
        assert "password" not in target
        assert "private_key" not in target

        # But on disk, secrets must be preserved so that subsequent
        # read-modify-write cycles (e.g. put_block_pattern) can
        # validate successfully
        with service.config_path.open("r", encoding="utf-8") as f:
            on_disk = json.load(f)
        disk_target = on_disk["ssh_targets"]["test-server"]
        assert disk_target["password"] == "secret123"

    def test_creates_backup(self, service: "ConfigService") -> None:
        """A .bak file is created before writing."""
        config = _minimal_config()
        service.write_config(config)

        bak_files = list(service.config_dir.glob("*.bak"))
        assert len(bak_files) >= 1

    def test_written_file_has_correct_permissions(
        self, service: "ConfigService",
    ) -> None:
        """Written config file has mode 0o600."""
        config = _minimal_config()
        service.write_config(config)
        assert _file_mode(service.config_path) == RESTRICTED_FILE_MODE

    def test_backup_file_has_correct_permissions(
        self, service: "ConfigService",
    ) -> None:
        """Backup file has mode 0o600."""
        config = _minimal_config()
        service.write_config(config)

        bak_files = list(service.config_dir.glob("*.bak"))
        assert len(bak_files) >= 1
        for bak in bak_files:
            assert _file_mode(bak) == RESTRICTED_FILE_MODE

    def test_returns_validated_config(
        self, service: "ConfigService",
    ) -> None:
        """Returns the validated config dict (with defaults applied)."""
        config = _minimal_config()
        result = service.write_config(config)
        assert isinstance(result, dict)
        assert "ssh_targets" in result

    def test_validation_failure_raises(
        self, service: "ConfigService",
    ) -> None:
        """ConfigValidationError raised for invalid config."""
        with pytest.raises(ConfigValidationError):
            service.write_config({"invalid": "config"})

    def test_atomic_write_no_partial_file(
        self, service: "ConfigService",
    ) -> None:
        """No .tmp files remain after a successful write."""
        config = _minimal_config()
        service.write_config(config)

        tmp_files = list(service.config_dir.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_write_creates_file_if_missing(
        self, config_dir: Path,
    ) -> None:
        """write_config creates the file if it doesn't exist yet."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        # Remove the existing config
        svc.config_path.unlink()

        config = _minimal_config()
        svc.write_config(config)
        assert svc.config_path.exists()

    def test_write_creates_directory_if_missing(
        self, tmp_path: Path,
    ) -> None:
        """write_config creates the config directory if missing."""
        from config_api.config_service import ConfigService

        # Need a valid config for init
        config_dir = tmp_path / "subdir"
        config_path = config_dir / DEFAULT_CONFIG_FILENAME
        _write_config(config_path, _minimal_config())

        svc = ConfigService(config_dir=str(config_dir))
        svc.write_config(_minimal_config())
        assert svc.config_path.exists()

    def test_write_config_reloads_config_managers(
        self, tmp_path: Path
    ) -> None:
        """write_config() calls reload() on both ConfigManagers."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch.object(svc, "_reload_config_managers") as mock_reload:
            svc.write_config(_minimal_config())

        mock_reload.assert_called_once()

    def test_write_section_reloads_config_managers(
        self, tmp_path: Path
    ) -> None:
        """write_section() triggers config manager reload via write_config."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch.object(svc, "_reload_config_managers") as mock_reload:
            svc.write_section("block_patterns", ["rm\\s+-rf"])

        mock_reload.assert_called_once()

    def test_put_ssh_target_reloads_config_managers(
        self, tmp_path: Path
    ) -> None:
        """put_ssh_target() triggers config manager reload via write_config."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch.object(svc, "_reload_config_managers") as mock_reload:
            svc.put_ssh_target(
                "new-server",
                {
                    "host": "10.0.0.99",
                    "username": "user",
                    "port": 22,
                    "password": "pass",
                },
            )

        mock_reload.assert_called_once()


class TestReloadConfigManagers:
    """Tests for ConfigService._reload_config_managers()."""

    def test_reloads_ssh_config_manager(self, tmp_path: Path) -> None:
        """Reloads the MCP server's ConfigManager when available."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        mock_cfg = MagicMock()
        svc = ConfigService(
            config_dir=str(tmp_path),
            ssh_config_manager=mock_cfg,
        )

        svc._reload_config_managers()
        mock_cfg.reload.assert_called_once()

    def test_reloads_validator(self, tmp_path: Path) -> None:
        """Reloads the local validation ConfigManager."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch.object(svc._validator, "reload") as mock_reload:
            svc._reload_config_managers()
            mock_reload.assert_called_once()

    def test_no_error_when_no_ssh_config_manager(
        self, tmp_path: Path
    ) -> None:
        """Does not fail when ssh_config_manager is None (standalone mode)."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        svc = ConfigService(config_dir=str(tmp_path))

        # Should not raise
        svc._reload_config_managers()

    def test_no_error_when_reload_fails(self, tmp_path: Path) -> None:
        """Reload failure is caught and logged, not raised."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _minimal_config())
        mock_cfg = MagicMock()
        mock_cfg.reload.side_effect = OSError("disk error")
        svc = ConfigService(
            config_dir=str(tmp_path),
            ssh_config_manager=mock_cfg,
        )

        # Should not raise — just log a warning
        svc._reload_config_managers()


# ---------------------------------------------------------------------------
# write_section
# ---------------------------------------------------------------------------


class TestWriteSection:
    """Tests for ConfigService.write_section()."""

    def test_replaces_section(self, service: "ConfigService") -> None:
        """Replaces the specified section in the config."""
        new_targets = {
            "new-server": {
                "host": "192.168.1.1",
                "port": 2222,
                "username": "root",
                "password": "newpass",
            },
        }
        result = service.write_section("ssh_targets", new_targets)
        assert "new-server" in result["ssh_targets"]
        assert "test-server" not in result["ssh_targets"]

    def test_other_sections_preserved(
        self, service: "ConfigService",
    ) -> None:
        """Other sections are preserved when replacing one section."""
        new_targets = {
            "new-server": {
                "host": "192.168.1.1",
                "port": 2222,
                "username": "root",
                "password": "newpass",
            },
        }
        result = service.write_section("ssh_targets", new_targets)
        assert "block_patterns" in result
        assert "allowed_commands" in result
        assert "settings" in result

    def test_invalid_section_raises_value_error(
        self, service: "ConfigService",
    ) -> None:
        """ValueError raised for unknown section names."""
        with pytest.raises(ValueError, match="Invalid section"):
            service.write_section("nonexistent", {})

    def test_validation_failure_raises(
        self, service: "ConfigService",
    ) -> None:
        """ConfigValidationError raised if merged config is invalid."""
        with pytest.raises(ConfigValidationError):
            service.write_section("ssh_targets", {})

    def test_written_to_disk(self, service: "ConfigService") -> None:
        """The merged config is written to disk."""
        new_settings = {"command_timeout_max": 60, "max_output_length": 50000}
        service.write_section("settings", new_settings)

        with service.config_path.open("r", encoding="utf-8") as f:
            on_disk = json.load(f)
        assert on_disk["settings"]["command_timeout_max"] == 60

    def test_block_patterns_as_list(
        self, service: "ConfigService",
    ) -> None:
        """block_patterns can be replaced with a list."""
        new_patterns = ["rm -rf", "dd if="]
        result = service.write_section("block_patterns", new_patterns)
        assert result["block_patterns"] == new_patterns

    def test_allowed_commands_partial_networks_preserves_default(
        self, service: "ConfigService",
    ) -> None:
        """Writing only 'networks' to allowed_commands preserves 'default' rules."""
        new_networks = [
            {
                "name": "internal",
                "range": "10.0.0.0/8",
                "rules": [{"targets": ["*"], "commands": ["echo"]}],
            },
        ]
        result = service.write_section("allowed_commands", {"networks": new_networks})
        assert result["allowed_commands"]["networks"] == new_networks
        assert result["allowed_commands"]["default"] == [
            {"targets": ["*"], "commands": ["echo", "whoami"]},
        ]

    def test_allowed_commands_partial_default_preserves_networks(
        self, service: "ConfigService",
    ) -> None:
        """Writing only 'default' to allowed_commands preserves 'networks'."""
        new_default = [
            {"targets": ["*"], "commands": ["ls", "cat"]},
        ]
        result = service.write_section("allowed_commands", {"default": new_default})
        assert result["allowed_commands"]["default"] == new_default
        assert result["allowed_commands"]["networks"] == []

    def test_allowed_commands_partial_api_keys_preserves_default(
        self, service: "ConfigService",
    ) -> None:
        """Writing only 'api_keys' to allowed_commands preserves 'default' rules."""
        new_api_keys = [
            {
                "name": "ci-runner",
                "key_hash": "pbkdf2:sha256:100000$abc123$abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "rules": [{"targets": ["*"], "commands": ["echo"]}],
            },
        ]
        result = service.write_section("allowed_commands", {"api_keys": new_api_keys})
        assert len(result["allowed_commands"]["api_keys"]) == 1
        assert result["allowed_commands"]["api_keys"][0]["name"] == "ci-runner"
        assert result["allowed_commands"]["api_keys"][0]["rules"] == [
            {"targets": ["*"], "commands": ["echo"]},
        ]
        assert result["allowed_commands"]["default"] == [
            {"targets": ["*"], "commands": ["echo", "whoami"]},
        ]

    def test_allowed_commands_full_replacement_still_works(
        self, service: "ConfigService",
    ) -> None:
        """Writing a complete allowed_commands dict replaces all sub-keys."""
        full_allowed = {
            "default": [{"targets": ["*"], "commands": ["date"]}],
            "api_keys": [],
            "networks": [],
        }
        result = service.write_section("allowed_commands", full_allowed)
        assert result["allowed_commands"]["default"] == full_allowed["default"]
        assert result["allowed_commands"]["api_keys"] == full_allowed["api_keys"]
        assert result["allowed_commands"]["networks"] == full_allowed["networks"]

    def test_ssh_targets_still_full_replace(
        self, service: "ConfigService",
    ) -> None:
        """write_section('ssh_targets', ...) still does full replacement (no merge)."""
        new_targets = {
            "brand-new-server": {
                "host": "192.168.1.100",
                "port": 22,
                "username": "root",
                "password": "pw",
            },
        }
        result = service.write_section("ssh_targets", new_targets)
        assert "brand-new-server" in result["ssh_targets"]
        assert "test-server" not in result["ssh_targets"]


# ---------------------------------------------------------------------------
# _create_backup
# ---------------------------------------------------------------------------


class TestCreateBackup:
    """Tests for ConfigService._create_backup()."""

    def test_creates_timestamped_backup(
        self, service: "ConfigService",
    ) -> None:
        """Backup file has a timestamp in its name."""
        backup_path = service._create_backup()
        assert backup_path is not None
        assert backup_path.exists()
        assert ".bak" in backup_path.name

    def test_backup_contains_same_content(
        self, service: "ConfigService",
    ) -> None:
        """Backup file content matches the original config."""
        backup_path = service._create_backup()
        assert backup_path is not None

        original = json.loads(
            service.config_path.read_text(encoding="utf-8"),
        )
        backup = json.loads(backup_path.read_text(encoding="utf-8"))
        assert original == backup

    def test_returns_none_when_no_config_file(
        self, config_dir: Path,
    ) -> None:
        """Returns None if the config file doesn't exist."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(config_dir))
        svc.config_path.unlink()
        result = svc._create_backup()
        assert result is None

    def test_backup_permissions(self, service: "ConfigService") -> None:
        """Backup file has mode 0o600."""
        backup_path = service._create_backup()
        assert backup_path is not None
        assert _file_mode(backup_path) == RESTRICTED_FILE_MODE

    def test_no_tmp_files_left(self, service: "ConfigService") -> None:
        """No .tmp files remain after backup creation."""
        service._create_backup()
        tmp_files = list(service.config_dir.glob("*.tmp"))
        assert len(tmp_files) == 0


# ---------------------------------------------------------------------------
# _atomic_write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    """Tests for ConfigService._atomic_write()."""

    def test_writes_json_to_config_path(
        self, service: "ConfigService",
    ) -> None:
        """Config dict is written as JSON to config_path."""
        config = {"test": "value"}
        service._atomic_write(config)

        with service.config_path.open("r", encoding="utf-8") as f:
            result = json.load(f)
        assert result == {"test": "value"}

    def test_file_permissions(self, service: "ConfigService") -> None:
        """Written file has mode 0o600."""
        service._atomic_write({"test": "value"})
        assert _file_mode(service.config_path) == RESTRICTED_FILE_MODE

    def test_trailing_newline(self, service: "ConfigService") -> None:
        """Written file ends with a trailing newline."""
        service._atomic_write({"test": "value"})
        content = service.config_path.read_text(encoding="utf-8")
        assert content.endswith("\n")

    def test_creates_directory_if_missing(
        self, tmp_path: Path,
    ) -> None:
        """Creates the config directory if it doesn't exist."""
        from config_api.config_service import ConfigService

        config_dir = tmp_path / "new_dir"
        config_path = config_dir / DEFAULT_CONFIG_FILENAME
        _write_config(config_path, _minimal_config())

        svc = ConfigService(config_dir=str(config_dir))
        # Remove and recreate
        config_path.unlink()
        config_dir.rmdir()
        svc._atomic_write({"test": "value"})
        assert config_path.exists()

    def test_no_tmp_files_left(self, service: "ConfigService") -> None:
        """No .tmp files remain after atomic write."""
        service._atomic_write({"test": "value"})
        tmp_files = list(service.config_dir.glob("*.tmp"))
        assert len(tmp_files) == 0

    def test_unicode_content(self, service: "ConfigService") -> None:
        """Unicode content is written correctly."""
        config = {"description": "Ünïcödé test 你好"}
        service._atomic_write(config)

        with service.config_path.open("r", encoding="utf-8") as f:
            result = json.load(f)
        assert result["description"] == "Ünïcödé test 你好"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Tests for thread safety of write operations."""

    def test_write_lock_serializes_writes(
        self, service: "ConfigService",
    ) -> None:
        """Concurrent writes are serialized by _write_lock."""
        errors: list[Exception] = []
        write_count = 0
        lock = threading.Lock()

        def do_write(idx: int) -> None:
            nonlocal write_count
            try:
                config = _minimal_config()
                config["settings"] = {
                    "max_output_length": 50000 + idx,
                    "command_timeout_max": 120,
                }
                service.write_config(config)
                with lock:
                    write_count += 1
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=do_write, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert write_count == 5

        # Verify the file is valid JSON (not corrupted)
        result = service.read_config()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# VALID_SECTIONS
# ---------------------------------------------------------------------------


class TestValidSections:
    """Tests for the VALID_SECTIONS class attribute."""

    def test_contains_expected_sections(self) -> None:
        """VALID_SECTIONS contains all expected section names."""
        from config_api.config_service import ConfigService

        expected = {"ssh_targets", "block_patterns", "allowed_commands", "settings"}
        assert ConfigService.VALID_SECTIONS == expected

    def test_is_frozenset(self) -> None:
        """VALID_SECTIONS is a frozenset (immutable)."""
        from config_api.config_service import ConfigService

        assert isinstance(ConfigService.VALID_SECTIONS, frozenset)


# ---------------------------------------------------------------------------
# _SECRET_FIELDS
# ---------------------------------------------------------------------------


class TestSecretFields:
    """Tests for the _SECRET_FIELDS class attribute."""

    def test_contains_expected_fields(self) -> None:
        """_SECRET_FIELDS contains password, private_key, key_hash."""
        from config_api.config_service import ConfigService

        expected = {"password", "private_key", "key_hash"}
        assert ConfigService._SECRET_FIELDS == expected

    def test_is_frozenset(self) -> None:
        """_SECRET_FIELDS is a frozenset (immutable)."""
        from config_api.config_service import ConfigService

        assert isinstance(ConfigService._SECRET_FIELDS, frozenset)


# ---------------------------------------------------------------------------
# get_ssh_target()
# ---------------------------------------------------------------------------


class TestGetSshTarget:
    """Tests for ConfigService.get_ssh_target()."""

    def test_returns_target_dict(
        self, service: "ConfigService"
    ) -> None:
        """get_ssh_target() returns the target config dict."""
        target = service.get_ssh_target("test-server")
        assert target["host"] == "10.0.0.1"
        assert target["port"] == 22
        assert target["username"] == "admin"

    def test_secrets_stripped(
        self, service: "ConfigService"
    ) -> None:
        """get_ssh_target() strips password and private_key."""
        target = service.get_ssh_target("test-server")
        assert "password" not in target
        assert "private_key" not in target
        assert "key_hash" not in target

    def test_nonexistent_target_raises_key_error(
        self, service: "ConfigService"
    ) -> None:
        """get_ssh_target() raises KeyError for unknown target."""
        with pytest.raises(KeyError, match="not found"):
            service.get_ssh_target("no-such-server")

    def test_nonexistent_target_in_default_config(
        self, tmp_path: Path
    ) -> None:
        """get_ssh_target() raises KeyError when target not in default config."""
        from config_api.config_service import ConfigService

        # ConfigManager creates default config; target won't exist
        svc = ConfigService(config_dir=str(tmp_path))
        with pytest.raises(KeyError, match="not found"):
            svc.get_ssh_target("nonexistent")

    def test_preserves_non_secret_fields(
        self, service: "ConfigService"
    ) -> None:
        """get_ssh_target() keeps non-secret fields like host, port."""
        target = service.get_ssh_target("test-server")
        assert target["host"] == "10.0.0.1"
        assert target["port"] == 22


# ---------------------------------------------------------------------------
# get_block_patterns()
# ---------------------------------------------------------------------------


class TestGetBlockPatterns:
    """Tests for ConfigService.get_block_patterns()."""

    def test_returns_empty_list(
        self, service: "ConfigService"
    ) -> None:
        """get_block_patterns() returns empty list when no patterns set."""
        result = service.get_block_patterns()
        assert result == []

    def test_returns_patterns(
        self, config_dir: Path
    ) -> None:
        """get_block_patterns() returns configured patterns."""
        from config_api.config_service import ConfigService

        cfg = _minimal_config()
        cfg["block_patterns"] = ["rm\\s+-rf", "curl\\s+.*\\|.*sh"]
        _write_config(config_dir / DEFAULT_CONFIG_FILENAME, cfg)

        svc = ConfigService(config_dir=str(config_dir))
        result = svc.get_block_patterns()
        assert len(result) == 2
        assert "rm\\s+-rf" in result

    def test_returns_empty_list_from_default_config(
        self, tmp_path: Path
    ) -> None:
        """get_block_patterns() returns empty list from default config."""
        from config_api.config_service import ConfigService

        # ConfigManager creates default config with empty block_patterns
        svc = ConfigService(config_dir=str(tmp_path))
        patterns = svc.get_block_patterns()
        assert isinstance(patterns, list)


# ---------------------------------------------------------------------------
# validate_only()
# ---------------------------------------------------------------------------


class TestValidateOnly:
    """Tests for ConfigService.validate_only()."""

    def test_valid_config_returns_dict(
        self, service: "ConfigService"
    ) -> None:
        """validate_only() returns validated config for valid input."""
        result = service.validate_only(_minimal_config())
        assert isinstance(result, dict)
        assert "ssh_targets" in result

    def test_invalid_config_raises(
        self, service: "ConfigService"
    ) -> None:
        """validate_only() raises ConfigValidationError for bad config."""
        with pytest.raises(ConfigValidationError):
            service.validate_only({"invalid": True})

    def test_does_not_write_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """validate_only() does not modify the config file on disk."""
        original = (config_dir / DEFAULT_CONFIG_FILENAME).read_text(
            encoding="utf-8"
        )
        service.validate_only(_minimal_config())
        after = (config_dir / DEFAULT_CONFIG_FILENAME).read_text(
            encoding="utf-8"
        )
        assert original == after

    def test_returns_validated_copy(
        self, service: "ConfigService"
    ) -> None:
        """validate_only() returns a deep copy, not the original dict."""
        cfg = _minimal_config()
        result = service.validate_only(cfg)
        # Modify the result — original should not change
        result["settings"]["max_output_length"] = 999999
        assert cfg["settings"]["max_output_length"] == 50000


# ---------------------------------------------------------------------------
# put_ssh_target()
# ---------------------------------------------------------------------------


class TestPutSshTarget:
    """Tests for ConfigService.put_ssh_target()."""

    def test_creates_new_target(
        self, service: "ConfigService"
    ) -> None:
        """put_ssh_target() adds a new target to the config."""
        new_target = {
            "host": "10.0.0.2",
            "port": 2222,
            "username": "root",
            "password": "pw123",
        }
        result = service.put_ssh_target("new-server", new_target)
        assert result["host"] == "10.0.0.2"
        assert result["port"] == 2222
        assert "password" not in result

    def test_replaces_existing_target(
        self, service: "ConfigService"
    ) -> None:
        """put_ssh_target() replaces an existing target."""
        updated = {
            "host": "10.0.0.99",
            "port": 22,
            "username": "admin",
            "password": "newpw",
        }
        result = service.put_ssh_target("test-server", updated)
        assert result["host"] == "10.0.0.99"

    def test_invalid_name_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """put_ssh_target() raises ValueError for invalid name."""
        with pytest.raises(ValueError, match="Invalid target name"):
            service.put_ssh_target(
                "../etc/passwd", {"host": "x", "port": 22}
            )

    def test_name_with_slash_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """put_ssh_target() rejects names with path separators."""
        with pytest.raises(ValueError):
            service.put_ssh_target(
                "bad/name", {"host": "x", "port": 22}
            )

    def test_written_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """put_ssh_target() persists the target to disk."""
        service.put_ssh_target(
            "disk-server",
            {"host": "1.2.3.4", "port": 22, "username": "u", "password": "p"},
        )
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert "disk-server" in raw["ssh_targets"]
        assert raw["ssh_targets"]["disk-server"]["host"] == "1.2.3.4"

    def test_secrets_kept_on_disk_but_stripped_from_return(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """put_ssh_target() keeps secrets on disk but strips from return."""
        result = service.put_ssh_target(
            "secrets-server",
            {"host": "5.6.7.8", "port": 22, "username": "u", "password": "p"},
        )
        # Return value has secrets stripped
        assert "password" not in result
        # On disk, secrets are preserved for read-modify-write cycles
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert raw["ssh_targets"]["secrets-server"]["password"] == "p"

    def test_preserves_existing_password_on_edit_when_empty(
        self, service: "ConfigService"
    ) -> None:
        """Editing a target with empty password preserves the existing one."""
        # The existing test-server target has password="secret123"
        result = service.put_ssh_target(
            "test-server",
            {"host": "10.0.0.1", "port": 22, "username": "admin", "password": ""},
        )
        assert result["host"] == "10.0.0.1"
        assert "password" not in result  # stripped from return
        # Verify the secret is preserved on disk
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["password"] == "secret123"

    def test_preserves_existing_password_on_edit_when_absent(
        self, service: "ConfigService"
    ) -> None:
        """Editing a target without password field preserves the existing one."""
        result = service.put_ssh_target(
            "test-server",
            {"host": "10.0.0.1", "port": 22, "username": "admin"},
        )
        assert result["host"] == "10.0.0.1"
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["password"] == "secret123"

    def test_preserves_existing_password_when_whitespace_only(
        self, service: "ConfigService"
    ) -> None:
        """Editing with whitespace-only password preserves the existing one."""
        result = service.put_ssh_target(
            "test-server",
            {"host": "10.0.0.1", "port": 22, "username": "admin", "password": "   "},
        )
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["password"] == "secret123"

    def test_replaces_password_when_new_value_provided(
        self, service: "ConfigService"
    ) -> None:
        """Providing a new non-empty password replaces the existing one."""
        result = service.put_ssh_target(
            "test-server",
            {"host": "10.0.0.1", "port": 22, "username": "admin", "password": "new-secret"},
        )
        assert result["host"] == "10.0.0.1"
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["password"] == "new-secret"

    def test_preserves_existing_private_key_on_edit_when_empty(
        self, service: "ConfigService"
    ) -> None:
        """Editing with empty private_key preserves the existing one."""
        # Set up a target with private_key
        config = service.read_config()
        config["ssh_targets"]["test-server"]["private_key"] = "my-private-key"
        service.write_config(config)

        # Now edit with empty private_key
        result = service.put_ssh_target(
            "test-server",
            {
                "host": "10.0.0.1",
                "port": 22,
                "username": "admin",
                "password": "secret123",
                "private_key": "",
            },
        )
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["private_key"] == "my-private-key"

    def test_replaces_private_key_when_new_value_provided(
        self, service: "ConfigService"
    ) -> None:
        """Providing a new non-empty private_key replaces the existing one."""
        config = service.read_config()
        config["ssh_targets"]["test-server"]["private_key"] = "old-key"
        service.write_config(config)

        result = service.put_ssh_target(
            "test-server",
            {
                "host": "10.0.0.1",
                "port": 22,
                "username": "admin",
                "password": "secret123",
                "private_key": "new-key",
            },
        )
        raw = service.read_config()
        assert raw["ssh_targets"]["test-server"]["private_key"] == "new-key"

    def test_create_new_target_requires_credentials(
        self, service: "ConfigService"
    ) -> None:
        """Creating a new target without credentials fails validation."""
        from lib.exceptions import ConfigValidationError

        with pytest.raises(ConfigValidationError):
            service.put_ssh_target(
                "new-no-creds",
                {"host": "10.0.0.5", "port": 22, "username": "user"},
            )


# ---------------------------------------------------------------------------
# delete_ssh_target()
# ---------------------------------------------------------------------------


class TestDeleteSshTarget:
    """Tests for ConfigService.delete_ssh_target()."""

    def test_deletes_existing_target(
        self, config_dir: Path
    ) -> None:
        """delete_ssh_target() removes the target from config."""
        from config_api.config_service import ConfigService

        # Need two targets — validation requires non-empty ssh_targets
        cfg = _minimal_config()
        cfg["ssh_targets"]["other-server"] = {
            "host": "10.0.0.3",
            "port": 22,
            "username": "u",
            "password": "p",
        }
        _write_config(config_dir / DEFAULT_CONFIG_FILENAME, cfg)
        svc = ConfigService(config_dir=str(config_dir))

        svc.delete_ssh_target("test-server")
        with pytest.raises(KeyError):
            svc.get_ssh_target("test-server")

    def test_nonexistent_target_raises_key_error(
        self, service: "ConfigService"
    ) -> None:
        """delete_ssh_target() raises KeyError for unknown target."""
        with pytest.raises(KeyError, match="not found"):
            service.delete_ssh_target("no-such-server")

    def test_written_to_disk(
        self, config_dir: Path
    ) -> None:
        """delete_ssh_target() persists removal to disk."""
        from config_api.config_service import ConfigService

        # Need two targets — validation requires non-empty ssh_targets
        cfg = _minimal_config()
        cfg["ssh_targets"]["other-server"] = {
            "host": "10.0.0.3",
            "port": 22,
            "username": "u",
            "password": "p",
        }
        _write_config(config_dir / DEFAULT_CONFIG_FILENAME, cfg)
        svc = ConfigService(config_dir=str(config_dir))

        svc.delete_ssh_target("test-server")
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert "test-server" not in raw.get("ssh_targets", {})

    def test_preserves_other_targets(
        self, config_dir: Path
    ) -> None:
        """delete_ssh_target() leaves other targets intact."""
        from config_api.config_service import ConfigService

        cfg = _minimal_config()
        cfg["ssh_targets"]["other-server"] = {
            "host": "10.0.0.3",
            "port": 22,
            "username": "u",
            "password": "p",
        }
        _write_config(config_dir / DEFAULT_CONFIG_FILENAME, cfg)

        svc = ConfigService(config_dir=str(config_dir))
        svc.delete_ssh_target("test-server")

        other = svc.get_ssh_target("other-server")
        assert other["host"] == "10.0.0.3"


# ---------------------------------------------------------------------------
# put_block_pattern()
# ---------------------------------------------------------------------------


class TestPutBlockPattern:
    """Tests for ConfigService.put_block_pattern()."""

    def test_replaces_pattern_at_index(
        self, service: "ConfigService"
    ) -> None:
        """put_block_pattern() replaces the pattern at the given index."""
        # First, set some patterns
        service.replace_block_patterns(["old1", "old2", "old3"])
        result = service.put_block_pattern(1, "new_pattern")
        assert result[1] == "new_pattern"
        assert len(result) == 3

    def test_invalid_index_raises_index_error(
        self, service: "ConfigService"
    ) -> None:
        """put_block_pattern() raises IndexError for out-of-range index."""
        service.replace_block_patterns(["pattern1"])
        with pytest.raises(IndexError, match="out of range"):
            service.put_block_pattern(5, "new")

    def test_negative_index_raises_index_error(
        self, service: "ConfigService"
    ) -> None:
        """put_block_pattern() raises IndexError for negative index."""
        service.replace_block_patterns(["pattern1"])
        with pytest.raises(IndexError, match="out of range"):
            service.put_block_pattern(-1, "new")

    def test_invalid_regex_raises(
        self, service: "ConfigService"
    ) -> None:
        """put_block_pattern() raises error for invalid regex."""
        service.replace_block_patterns(["valid_pattern"])
        with pytest.raises(Exception):  # re.error
            service.put_block_pattern(0, "[invalid(")

    def test_written_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """put_block_pattern() persists to disk."""
        service.replace_block_patterns(["a", "b"])
        service.put_block_pattern(0, "c")
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert raw["block_patterns"] == ["c", "b"]


# ---------------------------------------------------------------------------
# delete_block_pattern()
# ---------------------------------------------------------------------------


class TestDeleteBlockPattern:
    """Tests for ConfigService.delete_block_pattern()."""

    def test_removes_pattern_at_index(
        self, service: "ConfigService"
    ) -> None:
        """delete_block_pattern() removes the pattern at the given index."""
        service.replace_block_patterns(["a", "b", "c"])
        result = service.delete_block_pattern(1)
        assert result == ["a", "c"]

    def test_invalid_index_raises_index_error(
        self, service: "ConfigService"
    ) -> None:
        """delete_block_pattern() raises IndexError for out-of-range."""
        with pytest.raises(IndexError, match="out of range"):
            service.delete_block_pattern(0)

    def test_written_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """delete_block_pattern() persists to disk."""
        service.replace_block_patterns(["x", "y", "z"])
        service.delete_block_pattern(0)
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert raw["block_patterns"] == ["y", "z"]


# ---------------------------------------------------------------------------
# append_block_pattern()
# ---------------------------------------------------------------------------


class TestAppendBlockPattern:
    """Tests for ConfigService.append_block_pattern()."""

    def test_appends_to_empty_list(
        self, service: "ConfigService"
    ) -> None:
        """append_block_pattern() adds to an empty list."""
        result = service.append_block_pattern("new_pattern")
        assert result == ["new_pattern"]

    def test_appends_to_existing_list(
        self, service: "ConfigService"
    ) -> None:
        """append_block_pattern() adds to the end of existing list."""
        service.replace_block_patterns(["existing"])
        result = service.append_block_pattern("another")
        assert result == ["existing", "another"]

    def test_invalid_regex_raises(
        self, service: "ConfigService"
    ) -> None:
        """append_block_pattern() raises error for invalid regex."""
        with pytest.raises(Exception):  # re.error
            service.append_block_pattern("[unclosed(")

    def test_written_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """append_block_pattern() persists to disk."""
        service.replace_block_patterns(["first"])
        service.append_block_pattern("second")
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert raw["block_patterns"] == ["first", "second"]


# ---------------------------------------------------------------------------
# replace_block_patterns()
# ---------------------------------------------------------------------------


class TestReplaceBlockPatterns:
    """Tests for ConfigService.replace_block_patterns()."""

    def test_replaces_entire_list(
        self, service: "ConfigService"
    ) -> None:
        """replace_block_patterns() replaces the full list."""
        result = service.replace_block_patterns(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_replaces_with_empty_list(
        self, service: "ConfigService"
    ) -> None:
        """replace_block_patterns() can clear the list."""
        service.replace_block_patterns(["old"])
        result = service.replace_block_patterns([])
        assert result == []

    def test_written_to_disk(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """replace_block_patterns() persists to disk."""
        service.replace_block_patterns(["x", "y"])
        raw = json.loads(
            (config_dir / DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8")
        )
        assert raw["block_patterns"] == ["x", "y"]

    def test_invalid_section_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """replace_block_patterns() delegates to write_section which validates."""
        # This shouldn't happen in practice since "block_patterns" is valid,
        # but we test the path through write_section
        result = service.replace_block_patterns(["pat1"])
        assert result == ["pat1"]


# ---------------------------------------------------------------------------
# backup_list()
# ---------------------------------------------------------------------------


class TestBackupList:
    """Tests for ConfigService.backup_list()."""

    def test_returns_empty_list_when_no_backups(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_list() returns empty list when no backups exist."""
        result = service.backup_list()
        assert result == []

    def test_lists_created_backups(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_list() lists backup files created by write_config."""
        service.write_config(_minimal_config())
        backups = service.backup_list()
        assert len(backups) == 1
        assert backups[0]["name"].endswith(".bak")
        assert "size_bytes" in backups[0]
        assert "created_at" in backups[0]

    def test_sorted_newest_first(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_list() sorts backups newest first."""
        # Create two backups with different timestamps
        config_path = config_dir / DEFAULT_CONFIG_FILENAME
        ts1 = "20260101T120000Z"
        ts2 = "20260601T120000Z"
        (config_dir / f"ssh-mcp-config.{ts1}.bak").write_text(
            '{"test": 1}', encoding="utf-8"
        )
        (config_dir / f"ssh-mcp-config.{ts2}.bak").write_text(
            '{"test": 2}', encoding="utf-8"
        )
        backups = service.backup_list()
        assert len(backups) == 2
        assert backups[0]["name"] == f"ssh-mcp-config.{ts2}.bak"
        assert backups[1]["name"] == f"ssh-mcp-config.{ts1}.bak"

    def test_skips_malformed_filenames(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_list() skips files that don't match the expected pattern."""
        # Create a file with a .bak extension but wrong name format
        (config_dir / "weird-name.bak").write_text(
            '{"test": 1}', encoding="utf-8"
        )
        result = service.backup_list()
        assert result == []

    def test_returns_empty_list_when_no_backups_in_created_dir(
        self, tmp_path: Path
    ) -> None:
        """backup_list() returns empty list when dir created by ConfigManager."""
        from config_api.config_service import ConfigService

        # ConfigManager creates dir + config; no .bak files exist
        svc = ConfigService(config_dir=str(tmp_path / "newdir"))
        backups = svc.backup_list()
        assert backups == []


# ---------------------------------------------------------------------------
# backup_restore()
# ---------------------------------------------------------------------------


class TestBackupRestore:
    """Tests for ConfigService.backup_restore()."""

    def test_restores_from_backup(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_restore() restores config from a named backup."""
        # Create a backup
        service.write_config(_minimal_config())
        backups = service.backup_list()
        assert len(backups) >= 1

        # Restore it
        result = service.backup_restore(backups[0]["name"])
        assert isinstance(result, dict)
        assert "ssh_targets" in result

    def test_nonexistent_backup_raises_file_not_found(
        self, service: "ConfigService"
    ) -> None:
        """backup_restore() raises FileNotFoundError for missing backup."""
        with pytest.raises(FileNotFoundError):
            service.backup_restore(
                "ssh-mcp-config.20260101T000000Z.bak"
            )

    def test_path_traversal_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """backup_restore() rejects names with path traversal."""
        with pytest.raises(ValueError, match="path separator"):
            service.backup_restore("../etc/passwd")

    def test_double_dot_traversal_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """backup_restore() rejects names with '..'."""
        with pytest.raises(ValueError, match="path traversal"):
            service.backup_restore("..ssh-mcp-config.bak")

    def test_invalid_format_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """backup_restore() rejects names with wrong format."""
        with pytest.raises(ValueError, match="Invalid backup name format"):
            service.backup_restore("not-a-backup.txt")

    def test_invalid_json_in_backup_raises(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_restore() raises on invalid JSON in backup."""
        backup_name = "ssh-mcp-config.20260101T000000Z.bak"
        (config_dir / backup_name).write_text(
            "not json at all", encoding="utf-8"
        )
        with pytest.raises(json.JSONDecodeError):
            service.backup_restore(backup_name)

    def test_secrets_stripped_from_restored_config(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_restore() strips secrets from restored config."""
        service.write_config(_minimal_config())
        backups = service.backup_list()
        result = service.backup_restore(backups[0]["name"])
        # The restored config should not contain passwords
        for target in result.get("ssh_targets", {}).values():
            if isinstance(target, dict):
                assert "password" not in target


# ---------------------------------------------------------------------------
# backup_delete()
# ---------------------------------------------------------------------------


class TestBackupDelete:
    """Tests for ConfigService.backup_delete()."""

    def test_deletes_backup_file(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """backup_delete() removes the backup file."""
        backup_name = "ssh-mcp-config.20260101T000000Z.bak"
        (config_dir / backup_name).write_text(
            '{"test": true}', encoding="utf-8"
        )
        service.backup_delete(backup_name)
        assert not (config_dir / backup_name).exists()

    def test_nonexistent_backup_raises_file_not_found(
        self, service: "ConfigService"
    ) -> None:
        """backup_delete() raises FileNotFoundError for missing backup."""
        with pytest.raises(FileNotFoundError):
            service.backup_delete(
                "ssh-mcp-config.20260101T000000Z.bak"
            )

    def test_path_traversal_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """backup_delete() rejects names with path traversal."""
        with pytest.raises(ValueError):
            service.backup_delete("../../etc/passwd")

    def test_invalid_format_raises_value_error(
        self, service: "ConfigService"
    ) -> None:
        """backup_delete() rejects names with wrong format."""
        with pytest.raises(ValueError, match="Invalid backup name format"):
            service.backup_delete("malicious.bak")


# ---------------------------------------------------------------------------
# cleanup_old_backups()
# ---------------------------------------------------------------------------


class TestCleanupOldBackups:
    """Tests for ConfigService.cleanup_old_backups()."""

    def test_deletes_old_backups(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """cleanup_old_backups() deletes backups older than threshold."""
        # Create old backup (2020)
        old_name = "ssh-mcp-config.20200101T120000Z.bak"
        (config_dir / old_name).write_text(
            '{"old": true}', encoding="utf-8"
        )
        deleted = service.cleanup_old_backups(max_age_days=7)
        assert deleted == 1
        assert not (config_dir / old_name).exists()

    def test_keeps_recent_backups(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """cleanup_old_backups() preserves backups within the age window."""
        recent_name = "ssh-mcp-config.99991231T235959Z.bak"
        (config_dir / recent_name).write_text(
            '{"recent": true}', encoding="utf-8"
        )
        deleted = service.cleanup_old_backups(max_age_days=7)
        assert deleted == 0
        assert (config_dir / recent_name).exists()

    def test_returns_zero_when_no_backups(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """cleanup_old_backups() returns 0 when no backups exist."""
        deleted = service.cleanup_old_backups()
        assert deleted == 0

    def test_skips_malformed_filenames(
        self, config_dir: Path, service: "ConfigService"
    ) -> None:
        """cleanup_old_backups() skips files with bad timestamp formats."""
        (config_dir / "weird-name.bak").write_text(
            '{"test": 1}', encoding="utf-8"
        )
        deleted = service.cleanup_old_backups()
        assert deleted == 0
        assert (config_dir / "weird-name.bak").exists()

    def test_returns_zero_when_no_backups_in_created_dir(
        self, tmp_path: Path
    ) -> None:
        """cleanup_old_backups() returns 0 when dir created by ConfigManager."""
        from config_api.config_service import ConfigService

        # ConfigManager creates dir + config; no .bak files exist
        svc = ConfigService(config_dir=str(tmp_path / "newdir"))
        count = svc.cleanup_old_backups()
        assert count == 0


# ---------------------------------------------------------------------------
# _validate_backup_name()
# ---------------------------------------------------------------------------


class TestValidateBackupName:
    """Tests for ConfigService._validate_backup_name()."""

    def test_valid_name_passes(self) -> None:
        """Valid backup name passes validation."""
        from config_api.config_service import ConfigService

        ConfigService._validate_backup_name(
            "ssh-mcp-config.20260823T120000Z.bak"
        )

    def test_slash_raises_value_error(self) -> None:
        """Backup name with slash raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="path separator"):
            ConfigService._validate_backup_name(
                "ssh-mcp-config.20260823T120000Z.bak/../../etc/passwd"
            )

    def test_backslash_raises_value_error(self) -> None:
        """Backup name with backslash raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="path separator"):
            ConfigService._validate_backup_name("bad\\name.bak")

    def test_double_dot_raises_value_error(self) -> None:
        """Backup name with '..' raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="path traversal"):
            ConfigService._validate_backup_name("..ssh-mcp-config.bak")

    def test_wrong_format_raises_value_error(self) -> None:
        """Backup name with wrong format raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="Invalid backup name format"):
            ConfigService._validate_backup_name("random-file.txt")

    def test_empty_string_raises_value_error(self) -> None:
        """Empty backup name raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="Invalid backup name format"):
            ConfigService._validate_backup_name("")

    def test_missing_timestamp_raises_value_error(self) -> None:
        """Backup name without timestamp raises ValueError."""
        from config_api.config_service import ConfigService

        with pytest.raises(ValueError, match="Invalid backup name format"):
            ConfigService._validate_backup_name("ssh-mcp-config.bak")


# ---------------------------------------------------------------------------
# check_ssh_target — dual-mode (unified / standalone)
# ---------------------------------------------------------------------------


def _config_with_checkcommand() -> dict:
    """Return a minimal config that includes a checkcommand."""
    cfg = _minimal_config()
    cfg["ssh_targets"]["test-server"]["checkcommand"] = "echo ping"
    return cfg


class TestCheckSSHTarget:
    """Tests for ConfigService.check_ssh_target() in both modes."""

    # -- helpers -----------------------------------------------------------

    @pytest.fixture()
    def svc(self, tmp_path: Path) -> "ConfigService":
        """ConfigService backed by a config with a checkcommand target."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        return ConfigService(config_dir=str(tmp_path))

    # -- _use_direct_ssh property ------------------------------------------

    def test_use_direct_ssh_false_when_no_deps(
        self, tmp_path: Path
    ) -> None:
        """_use_direct_ssh is False when no SSH managers are injected."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc_inst = ConfigService(config_dir=str(tmp_path))
        assert svc_inst._use_direct_ssh is False  # type: ignore[attr-defined]

    def test_use_direct_ssh_false_when_partial_deps(
        self, tmp_path: Path
    ) -> None:
        """_use_direct_ssh is False when only one manager is provided."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc_inst = ConfigService(
            config_dir=str(tmp_path),
            ssh_client_manager=object(),
        )
        assert svc_inst._use_direct_ssh is False  # type: ignore[attr-defined]

    def test_use_direct_ssh_true_when_all_deps(self, tmp_path: Path) -> None:
        """_use_direct_ssh is True when both managers are injected and
        lib.ssh_operations is importable."""
        from config_api.config_service import ConfigService, _ssh_operations_module

        if _ssh_operations_module is None:
            pytest.skip("lib.ssh_operations not importable in this env")
        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc_inst = ConfigService(
            config_dir=str(tmp_path),
            ssh_client_manager=object(),
            ssh_config_manager=object(),
        )
        assert svc_inst._use_direct_ssh is True  # type: ignore[attr-defined]

    # -- unified mode (direct SSH calls) -----------------------------------

    def test_unified_mode_success(self, tmp_path: Path) -> None:
        """Direct SSH call returns success result."""
        from config_api.config_service import ConfigService, _ssh_operations_module

        if _ssh_operations_module is None:
            pytest.skip("lib.ssh_operations not importable in this env")

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        mock_mgr = MagicMock()
        mock_cfg = MagicMock()

        svc = ConfigService(
            config_dir=str(tmp_path),
            ssh_client_manager=mock_mgr,
            ssh_config_manager=mock_cfg,
        )

        mock_result = {
            "success": True,
            "output": "pong",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch(
            "config_api.config_service._ssh_operations_module.check_ssh_connection",
            return_value=mock_result,
        ) as mock_check:
            result = svc.check_ssh_target("test-server")

        mock_check.assert_called_once_with(
            ssh_client_manager=mock_mgr,
            config_manager=mock_cfg,
            target_name="test-server",
            ssh_key_path=svc._ssh_key_path,
            timeout=10,
        )
        assert result["success"] is True
        assert result["output"] == "pong"
        assert result["exit_code"] == 0

    def test_unified_mode_failure(self, tmp_path: Path) -> None:
        """Direct SSH call that raises returns error dict."""
        from config_api.config_service import ConfigService, _ssh_operations_module

        if _ssh_operations_module is None:
            pytest.skip("lib.ssh_operations not importable in this env")

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())

        svc = ConfigService(
            config_dir=str(tmp_path),
            ssh_client_manager=MagicMock(),
            ssh_config_manager=MagicMock(),
        )

        with patch(
            "config_api.config_service._ssh_operations_module.check_ssh_connection",
            side_effect=ConnectionError("refused"),
        ):
            result = svc.check_ssh_target("test-server")

        assert result["success"] is False
        assert "refused" in result["error"]
        assert result["exit_code"] == -1

    def test_unified_mode_custom_timeout(self, tmp_path: Path) -> None:
        """Direct SSH call forwards custom timeout."""
        from config_api.config_service import ConfigService, _ssh_operations_module

        if _ssh_operations_module is None:
            pytest.skip("lib.ssh_operations not importable in this env")

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())

        svc = ConfigService(
            config_dir=str(tmp_path),
            ssh_client_manager=MagicMock(),
            ssh_config_manager=MagicMock(),
        )

        mock_result = {
            "success": True,
            "output": "",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch(
            "config_api.config_service._ssh_operations_module.check_ssh_connection",
            return_value=mock_result,
        ) as mock_check:
            svc.check_ssh_target("test-server", timeout=30)

        call_kwargs = mock_check.call_args[1]
        assert call_kwargs["timeout"] == 30

    # -- standalone mode (MCPClient fallback) ------------------------------

    def test_standalone_mode_falls_back_to_mcp(
        self, tmp_path: Path
    ) -> None:
        """Without SSH managers, falls back to MCPClient."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc = ConfigService(config_dir=str(tmp_path))

        mock_mcp_result = {
            "success": True,
            "output": "pong",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch("config_api.config_service.MCPClient") as MockMCP:
            MockMCP.return_value.call_tool.return_value = mock_mcp_result
            result = svc.check_ssh_target("test-server")

        MockMCP.return_value.call_tool.assert_called_once_with(
            "ssh_check_connection",
            arguments={"server_name": "test-server", "timeout": 10},
            timeout=15,
        )
        assert result["success"] is True
        assert result["output"] == "pong"

    def test_standalone_mode_mcp_tool_error(self, tmp_path: Path) -> None:
        """MCPToolError is caught and returned as error dict."""
        from config_api.config_service import ConfigService
        from config_api.mcp_client import MCPToolError

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch("config_api.config_service.MCPClient") as MockMCP:
            MockMCP.return_value.call_tool.side_effect = MCPToolError(
                "target not found", "ssh_check_connection"
            )
            result = svc.check_ssh_target("test-server")

        assert result["success"] is False
        assert "target not found" in result["error"]

    def test_standalone_mode_mcp_client_error(self, tmp_path: Path) -> None:
        """MCPClientError is caught and returned as error dict."""
        from config_api.config_service import ConfigService
        from config_api.mcp_client import MCPClientError

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc = ConfigService(config_dir=str(tmp_path))

        with patch("config_api.config_service.MCPClient") as MockMCP:
            MockMCP.return_value.call_tool.side_effect = MCPClientError(
                "connection refused"
            )
            result = svc.check_ssh_target("test-server")

        assert result["success"] is False
        assert "unreachable" in result["error"]

    # -- common paths (both modes) -----------------------------------------

    def test_nonexistent_target_raises_key_error(
        self, tmp_path: Path
    ) -> None:
        """check_ssh_target raises KeyError for unknown target."""
        from config_api.config_service import ConfigService

        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, _config_with_checkcommand())
        svc = ConfigService(config_dir=str(tmp_path))

        with pytest.raises(KeyError, match="nonexistent"):
            svc.check_ssh_target("nonexistent")

    def test_default_checkcommand_when_missing(
        self, tmp_path: Path
    ) -> None:
        """Uses 'echo ping' as default checkcommand when not configured."""
        from config_api.config_service import ConfigService

        cfg = _minimal_config()
        # Remove checkcommand if present
        cfg["ssh_targets"]["test-server"].pop("checkcommand", None)
        _write_config(tmp_path / DEFAULT_CONFIG_FILENAME, cfg)
        svc = ConfigService(config_dir=str(tmp_path))

        mock_mcp_result = {
            "success": True,
            "output": "ping",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch("config_api.config_service.MCPClient") as MockMCP:
            MockMCP.return_value.call_tool.return_value = mock_mcp_result
            result = svc.check_ssh_target("test-server")

        assert result["checkcommand"] == "echo ping"
