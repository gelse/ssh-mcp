"""Unit tests for Pydantic models in config_api.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from config_api.models import (
    AllowedCommandsModel,
    BackupInfo,
    BackupListResponse,
    ConfigModel,
    ConfigSectionResponse,
    ErrorResponse,
    HashKeyRequest,
    HashKeyResponse,
    HealthResponse,
    RuleModel,
    SFTPSettingsModel,
    SettingsModel,
    SSHTargetModel,
    ValidateResponse,
)


# ---------------------------------------------------------------------------
# SSHTargetModel
# ---------------------------------------------------------------------------


class TestSSHTargetModel:
    """Tests for SSHTargetModel validation."""

    def test_valid_minimal(self) -> None:
        """Required fields only; port defaults to 22."""
        target = SSHTargetModel(host="example.com", username="admin")
        assert target.host == "example.com"
        assert target.port == 22
        assert target.username == "admin"
        assert target.private_key is None
        assert target.password is None

    def test_valid_full(self) -> None:
        """All fields provided."""
        target = SSHTargetModel(
            host="10.0.0.1",
            port=2222,
            username="user",
            private_key="/path/to/key",
            password="secret",
        )
        assert target.port == 2222
        assert target.private_key == "/path/to/key"

    def test_host_empty_rejected(self) -> None:
        """Empty host is rejected (min_length=1)."""
        with pytest.raises(ValidationError) as exc_info:
            SSHTargetModel(host="", username="admin")
        assert "host" in str(exc_info.value)

    def test_host_too_long_rejected(self) -> None:
        """Host exceeding 253 chars is rejected."""
        with pytest.raises(ValidationError):
            SSHTargetModel(host="a" * 254, username="admin")

    def test_port_zero_rejected(self) -> None:
        """Port 0 is below the minimum (ge=1)."""
        with pytest.raises(ValidationError):
            SSHTargetModel(host="example.com", username="admin", port=0)

    def test_port_above_65535_rejected(self) -> None:
        """Port above 65535 is rejected."""
        with pytest.raises(ValidationError):
            SSHTargetModel(host="example.com", username="admin", port=65536)

    def test_port_boundary_values(self) -> None:
        """Ports 1 and 65535 are accepted."""
        low = SSHTargetModel(host="h", username="u", port=1)
        high = SSHTargetModel(host="h", username="u", port=65535)
        assert low.port == 1
        assert high.port == 65535

    def test_username_empty_rejected(self) -> None:
        """Empty username is rejected."""
        with pytest.raises(ValidationError):
            SSHTargetModel(host="example.com", username="")

    def test_username_too_long_rejected(self) -> None:
        """Username exceeding 64 chars is rejected."""
        with pytest.raises(ValidationError):
            SSHTargetModel(host="example.com", username="a" * 65)


# ---------------------------------------------------------------------------
# RuleModel
# ---------------------------------------------------------------------------


class TestRuleModel:
    """Tests for RuleModel validation."""

    def test_valid(self) -> None:
        rule = RuleModel(targets=["server1"], commands=["uptime"])
        assert rule.targets == ["server1"]
        assert rule.commands == ["uptime"]

    def test_empty_targets_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RuleModel(targets=[], commands=["uptime"])

    def test_empty_commands_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RuleModel(targets=["server1"], commands=[])

    def test_multiple_entries(self) -> None:
        rule = RuleModel(
            targets=["s1", "s2"],
            commands=["uptime", "df -h"],
        )
        assert len(rule.targets) == 2
        assert len(rule.commands) == 2


# ---------------------------------------------------------------------------
# AllowedCommandsModel
# ---------------------------------------------------------------------------


class TestAllowedCommandsModel:
    """Tests for AllowedCommandsModel."""

    def test_defaults(self) -> None:
        ac = AllowedCommandsModel()
        assert ac.default == []
        assert ac.api_keys is None
        assert ac.networks is None

    def test_with_rules(self) -> None:
        ac = AllowedCommandsModel(
            default=[RuleModel(targets=["s1"], commands=["uptime"])],
        )
        assert len(ac.default) == 1

    def test_with_api_keys_and_networks(self) -> None:
        ac = AllowedCommandsModel(
            api_keys=[{"key_hash": "abc", "rules": []}],
            networks=[{"cidr": "10.0.0.0/8", "rules": []}],
        )
        assert ac.api_keys is not None
        assert ac.networks is not None


# ---------------------------------------------------------------------------
# SFTPSettingsModel
# ---------------------------------------------------------------------------


class TestSFTPSettingsModel:
    """Tests for SFTPSettingsModel."""

    def test_defaults(self) -> None:
        sftp = SFTPSettingsModel()
        assert sftp.sandbox_root is None
        assert sftp.max_path_length is None

    def test_valid(self) -> None:
        sftp = SFTPSettingsModel(sandbox_root="/tmp/sftp", max_path_length=1024)
        assert sftp.sandbox_root == "/tmp/sftp"
        assert sftp.max_path_length == 1024

    def test_max_path_length_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SFTPSettingsModel(max_path_length=0)

    def test_max_path_length_above_4096_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SFTPSettingsModel(max_path_length=4097)


# ---------------------------------------------------------------------------
# SettingsModel
# ---------------------------------------------------------------------------


class TestSettingsModel:
    """Tests for SettingsModel."""

    def test_defaults_all_none(self) -> None:
        settings = SettingsModel()
        assert settings.max_output_length is None
        assert settings.command_timeout_max is None
        assert settings.log_level is None

    def test_valid_values(self) -> None:
        settings = SettingsModel(
            max_output_length="1MB",
            command_timeout_max=30,
            retry_max_attempts=3,
            log_level="INFO",
            compress_rotated=True,
        )
        assert settings.max_output_length == "1MB"
        assert settings.command_timeout_max == 30
        assert settings.compress_rotated is True

    def test_extra_fields_allowed(self) -> None:
        """SettingsModel must accept unknown keys for forward compatibility."""
        settings = SettingsModel(
            future_setting="some_value",
            another_new_setting=42,
        )
        # Pydantic v2 stores extra fields in the model
        assert settings.model_extra is not None
        assert settings.model_extra["future_setting"] == "some_value"

    def test_command_timeout_max_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SettingsModel(command_timeout_max=0)

    def test_retry_max_attempts_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SettingsModel(retry_max_attempts=-1)

    def test_retry_max_attempts_zero_accepted(self) -> None:
        """ge=0 means zero is valid."""
        settings = SettingsModel(retry_max_attempts=0)
        assert settings.retry_max_attempts == 0

    def test_sftp_sub_model(self) -> None:
        settings = SettingsModel(sftp=SFTPSettingsModel(sandbox_root="/tmp"))
        assert settings.sftp is not None
        assert settings.sftp.sandbox_root == "/tmp"


# ---------------------------------------------------------------------------
# ConfigModel
# ---------------------------------------------------------------------------


class TestConfigModel:
    """Tests for ConfigModel (full config)."""

    def _minimal_config(self) -> dict:
        """Return the minimum valid config dict."""
        return {
            "ssh_targets": {
                "server1": {"host": "example.com", "username": "admin"},
            },
        }

    def test_valid_minimal(self) -> None:
        cfg = ConfigModel(**self._minimal_config())
        assert cfg.version == 1
        assert "server1" in cfg.ssh_targets
        assert cfg.block_patterns == []
        assert cfg.settings.model_dump() is not None

    def test_valid_full(self) -> None:
        data = self._minimal_config()
        data["version"] = 2
        data["block_patterns"] = ["rm -rf"]
        data["allowed_commands"] = {
            "default": [{"targets": ["server1"], "commands": ["uptime"]}],
        }
        data["settings"] = {"command_timeout_max": 30}
        cfg = ConfigModel(**data)
        assert cfg.version == 2
        assert cfg.block_patterns == ["rm -rf"]
        assert len(cfg.allowed_commands.default) == 1

    def test_ssh_targets_empty_rejected(self) -> None:
        """ssh_targets must have at least one entry (min_length=1)."""
        with pytest.raises(ValidationError):
            ConfigModel(ssh_targets={})

    def test_ssh_targets_missing_rejected(self) -> None:
        """ssh_targets is required."""
        with pytest.raises(ValidationError):
            ConfigModel()

    def test_extra_fields_allowed(self) -> None:
        """ConfigModel must accept unknown keys for forward compatibility."""
        data = self._minimal_config()
        data["future_section"] = {"key": "value"}
        cfg = ConfigModel(**data)
        assert cfg.model_extra is not None
        assert cfg.model_extra["future_section"] == {"key": "value"}

    def test_version_minimum(self) -> None:
        """Version must be >= 1."""
        data = self._minimal_config()
        data["version"] = 0
        with pytest.raises(ValidationError):
            ConfigModel(**data)

    def test_ssh_target_validation_errors_propagate(self) -> None:
        """Invalid SSH target fields are caught."""
        with pytest.raises(ValidationError) as exc_info:
            ConfigModel(
                ssh_targets={"bad": {"host": "", "username": "admin"}},
            )
        assert "host" in str(exc_info.value)


# ---------------------------------------------------------------------------
# ErrorResponse
# ---------------------------------------------------------------------------


class TestErrorResponse:
    """Tests for ErrorResponse."""

    def test_defaults(self) -> None:
        err = ErrorResponse(error_type="validation_error", message="Bad input")
        assert err.error is True
        assert err.error_type == "validation_error"
        assert err.message == "Bad input"
        assert err.field is None

    def test_with_field(self) -> None:
        err = ErrorResponse(
            error_type="validation_error",
            message="Required",
            field="ssh_targets.host",
        )
        assert err.field == "ssh_targets.host"

    def test_error_type_required(self) -> None:
        with pytest.raises(ValidationError):
            ErrorResponse(message="msg")

    def test_message_required(self) -> None:
        with pytest.raises(ValidationError):
            ErrorResponse(error_type="type")


# ---------------------------------------------------------------------------
# HealthResponse
# ---------------------------------------------------------------------------


class TestHealthResponse:
    """Tests for HealthResponse."""

    def test_default(self) -> None:
        h = HealthResponse()
        assert h.status == "ok"

    def test_custom_status(self) -> None:
        h = HealthResponse(status="degraded")
        assert h.status == "degraded"


# ---------------------------------------------------------------------------
# ConfigSectionResponse
# ---------------------------------------------------------------------------


class TestConfigSectionResponse:
    """Tests for ConfigSectionResponse."""

    def test_valid(self) -> None:
        resp = ConfigSectionResponse(section="settings", data={"log_level": "INFO"})
        assert resp.section == "settings"
        assert resp.data == {"log_level": "INFO"}

    def test_section_required(self) -> None:
        with pytest.raises(ValidationError):
            ConfigSectionResponse(data={})

    def test_data_required(self) -> None:
        with pytest.raises(ValidationError):
            ConfigSectionResponse(section="settings")


# ---------------------------------------------------------------------------
# HashKeyRequest
# ---------------------------------------------------------------------------


class TestHashKeyRequest:
    """Tests for HashKeyRequest validation."""

    def test_valid(self) -> None:
        req = HashKeyRequest(key="my-secret-api-key")
        assert req.key == "my-secret-api-key"

    def test_key_required(self) -> None:
        with pytest.raises(ValidationError):
            HashKeyRequest()

    def test_key_empty_rejected(self) -> None:
        """Empty key is rejected (min_length=1)."""
        with pytest.raises(ValidationError):
            HashKeyRequest(key="")

    def test_key_too_long_rejected(self) -> None:
        """Key exceeding 1024 chars is rejected."""
        with pytest.raises(ValidationError):
            HashKeyRequest(key="a" * 1025)

    def test_key_max_length_accepted(self) -> None:
        """Key at exactly 1024 chars is accepted."""
        req = HashKeyRequest(key="a" * 1024)
        assert len(req.key) == 1024


# ---------------------------------------------------------------------------
# HashKeyResponse
# ---------------------------------------------------------------------------


class TestHashKeyResponse:
    """Tests for HashKeyResponse."""

    def test_valid(self) -> None:
        resp = HashKeyResponse(key_hash="pbkdf2:sha256:100000$abc$def")
        assert resp.key_hash == "pbkdf2:sha256:100000$abc$def"

    def test_key_hash_required(self) -> None:
        with pytest.raises(ValidationError):
            HashKeyResponse()


# ---------------------------------------------------------------------------
# BackupInfo
# ---------------------------------------------------------------------------


class TestBackupInfo:
    """Tests for BackupInfo validation."""

    def test_valid(self) -> None:
        info = BackupInfo(
            name="ssh-mcp-config.20260823T120000Z.bak",
            size_bytes=1024,
            created_at="2026-08-23T12:00:00Z",
        )
        assert info.name == "ssh-mcp-config.20260823T120000Z.bak"
        assert info.size_bytes == 1024
        assert info.created_at == "2026-08-23T12:00:00Z"

    def test_name_required(self) -> None:
        with pytest.raises(ValidationError):
            BackupInfo(size_bytes=100, created_at="2026-01-01T00:00:00Z")

    def test_size_bytes_zero_accepted(self) -> None:
        info = BackupInfo(name="empty.bak", size_bytes=0, created_at="2026-01-01T00:00:00Z")
        assert info.size_bytes == 0

    def test_size_bytes_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            BackupInfo(name="bad.bak", size_bytes=-1, created_at="2026-01-01T00:00:00Z")

    def test_created_at_required(self) -> None:
        with pytest.raises(ValidationError):
            BackupInfo(name="file.bak", size_bytes=100)


# ---------------------------------------------------------------------------
# BackupListResponse
# ---------------------------------------------------------------------------


class TestBackupListResponse:
    """Tests for BackupListResponse."""

    def test_empty_list(self) -> None:
        resp = BackupListResponse(backups=[])
        assert resp.backups == []

    def test_with_backups(self) -> None:
        backups = [
            BackupInfo(name="a.bak", size_bytes=100, created_at="2026-01-01T00:00:00Z"),
            BackupInfo(name="b.bak", size_bytes=200, created_at="2026-01-02T00:00:00Z"),
        ]
        resp = BackupListResponse(backups=backups)
        assert len(resp.backups) == 2
        assert resp.backups[0].name == "a.bak"

    def test_backups_required(self) -> None:
        with pytest.raises(ValidationError):
            BackupListResponse()


# ---------------------------------------------------------------------------
# ValidateResponse
# ---------------------------------------------------------------------------


class TestValidateResponse:
    """Tests for ValidateResponse."""

    def test_valid_true_with_config(self) -> None:
        cfg = {"version": 1, "ssh_targets": {"s1": {"host": "h", "username": "u"}}}
        resp = ValidateResponse(valid=True, config=cfg)
        assert resp.valid is True
        assert resp.config == cfg

    def test_valid_false_no_config(self) -> None:
        resp = ValidateResponse(valid=False)
        assert resp.valid is False
        assert resp.config is None

    def test_valid_required(self) -> None:
        with pytest.raises(ValidationError):
            ValidateResponse()

    def test_valid_true_no_config(self) -> None:
        """valid=True without config is still valid (config defaults to None)."""
        resp = ValidateResponse(valid=True)
        assert resp.valid is True
        assert resp.config is None
