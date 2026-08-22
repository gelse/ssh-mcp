"""Pydantic request/response models for the config API.

Models validate PUT request bodies and serialize GET responses.
They are compatible with the config schema in config.schema.json but
do NOT replicate all of ConfigManager._validate() — that validation
is handled by the config service layer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SSHTargetModel(BaseModel):
    """Schema for a single SSH target in the config."""

    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=64)
    private_key: str | None = None
    password: str | None = None


class RuleModel(BaseModel):
    """Schema for an authorization rule."""

    targets: list[str] = Field(..., min_length=1)
    commands: list[str] = Field(..., min_length=1)


class AllowedCommandsModel(BaseModel):
    """Schema for the allowed_commands section."""

    default: list[RuleModel] = Field(default_factory=list)
    api_keys: list[dict] | None = None
    networks: list[dict] | None = None


class SFTPSettingsModel(BaseModel):
    """Schema for SFTP sub-settings."""

    sandbox_root: str | None = None
    max_path_length: int | None = Field(default=None, ge=1, le=4096)


class SettingsModel(BaseModel):
    """Schema for the settings section."""

    model_config = {"extra": "allow"}  # Allow unknown keys for forward compat

    max_output_length: str | int | None = None
    command_timeout_max: int | None = Field(default=None, ge=1)
    retry_max_attempts: int | None = Field(default=None, ge=0)
    retry_backoff_base_seconds: float | None = Field(default=None, ge=0)
    circuit_breaker_failure_threshold: int | None = Field(default=None, ge=1)
    circuit_breaker_timeout_seconds: float | None = Field(default=None, ge=0)
    log_level: str | None = None
    max_log_output: int | None = Field(default=None, ge=0)
    compress_rotated: bool | None = None
    pool_max_connections_per_target: int | None = Field(default=None, ge=1)
    pool_idle_timeout_seconds: float | None = Field(default=None, ge=0)
    pool_cleanup_interval_seconds: float | None = Field(default=None, ge=0)
    max_concurrent_ssh_connections: int | None = Field(default=None, ge=1)
    watcher_debounce_seconds: float | None = Field(default=None, ge=0)
    trusted_proxies: list[str] | None = None
    sftp: SFTPSettingsModel | None = None


class ConfigModel(BaseModel):
    """Schema for the full configuration file."""

    model_config = {"extra": "allow"}

    version: int = Field(default=1, ge=1)
    ssh_targets: dict[str, SSHTargetModel] = Field(..., min_length=1)
    block_patterns: list[str] = Field(default_factory=list)
    allowed_commands: AllowedCommandsModel = Field(
        default_factory=AllowedCommandsModel,
    )
    settings: SettingsModel = Field(default_factory=SettingsModel)


class ErrorResponse(BaseModel):
    """Standard error response shape."""

    error: bool = True
    error_type: str
    message: str
    field: str | None = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"


class ConfigSectionResponse(BaseModel):
    """Response wrapper for a single config section."""

    section: str
    data: dict | list
