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

    def test_secrets_stripped_from_written_file(
        self, service: "ConfigService",
    ) -> None:
        """Secret fields are stripped before writing."""
        config = _minimal_config()
        service.write_config(config)

        with service.config_path.open("r", encoding="utf-8") as f:
            on_disk = json.load(f)
        target = on_disk["ssh_targets"]["test-server"]
        assert "password" not in target
        assert "private_key" not in target

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
