"""FastAPI route handlers for config endpoints.

Defines an ``APIRouter`` with all config management endpoints.  Each route
handler authenticates via ``Depends(verify_token)`` (except ``/health``),
delegates to ``ConfigService`` for file operations, and returns structured
JSON responses with appropriate HTTP status codes.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from config_api.auth import (
    create_session,
    get_token,
    revoke_session,
    validate_session,
    verify_token,
)
from config_api.config_service import ConfigService
from config_api.models import (
    BackupInfo,
    BackupListResponse,
    BackupRestoreResponse,
    ConfigSectionResponse,
    ErrorResponse,
    HashKeyRequest,
    HashKeyResponse,
    HealthResponse,
    ValidateResponse,
)
from lib.constants import (
    CONFIG_API_SESSION_COOKIE_NAME,
    CONFIG_API_SESSION_COOKIE_SAMESITE,
    CONFIG_API_SESSION_COOKIE_SECURE,
    CONFIG_API_SESSION_MAX_AGE_SECONDS,
)

# Allow env-var override for the cookie ``secure`` flag.
# When CONFIG_API_SESSION_COOKIE_SECURE env var is unset, fall back to the
# constant (True).  Any falsy string ("false", "0", "no") disables it.
_cookie_secure_env: str | None = os.environ.get(
    "CONFIG_API_SESSION_COOKIE_SECURE",
)
COOKIE_SECURE: bool = (
    _cookie_secure_env.lower() not in ("false", "0", "no")
    if _cookie_secure_env is not None
    else CONFIG_API_SESSION_COOKIE_SECURE
)
from lib.crypto import hash_api_key
from lib.exceptions import ConfigValidationError

router = APIRouter()
auth_router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# Config service singleton
# ---------------------------------------------------------------------------

_config_service: ConfigService | None = None


def init_config_service(
    config_dir: str | None = None,
    *,
    ssh_client_manager: object | None = None,
    ssh_config_manager: object | None = None,
    ssh_key_path: str | None = None,
) -> ConfigService:
    """Initialize the config service singleton.  Called once at startup.

    Args:
        config_dir: Path to the config directory.
        ssh_client_manager: Optional SSHClientManager for unified mode.
        ssh_config_manager: Optional ConfigManager for unified mode.
        ssh_key_path: Optional path to the SSH key for unified mode.
    """
    global _config_service
    _config_service = ConfigService(
        config_dir,
        ssh_client_manager=ssh_client_manager,
        ssh_config_manager=ssh_config_manager,
        ssh_key_path=ssh_key_path,
    )
    return _config_service


def get_config_service() -> ConfigService:
    """FastAPI dependency that returns the config service singleton."""
    if _config_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Config service not initialized",
        )
    return _config_service


def _error_response(
    status_code: int,
    error_type: str,
    message: str,
    exc: Exception,
    *,
    field: str | None = None,
    log_level: int = logging.WARNING,
) -> JSONResponse:
    """Log full exception and return sanitized error response.

    Args:
        status_code: HTTP status code to return.
        error_type: Error category string (e.g., "OSError", "JSONDecodeError").
        message: Safe user-facing error message.
        exc: The exception to log (full details logged server-side).
        field: Optional field name for validation errors.
        log_level: Logging level (default: WARNING).

    Returns:
        JSONResponse with sanitized ErrorResponse content.
    """
    logger.log(log_level, "[%s] %s", error_type, message, exc_info=True)
    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            error_type=error_type,
            message=message,
            field=field,
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# Health endpoint (no auth)
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe.  No authentication required."""
    logger.debug("health entry")
    result = HealthResponse(status="ok")
    logger.debug("health exit: status=ok")
    return result


# ---------------------------------------------------------------------------
# GET /config — full config
# ---------------------------------------------------------------------------


@router.get("/config")
async def get_config(
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read the full on-disk configuration.

    Returns the raw JSON content of the config file without any
    secret merging or environment variable overrides.
    """
    logger.debug("get_config entry")
    try:
        config = svc.read_config()
        return JSONResponse(content=svc._strip_secrets(config))
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config file not found",
            ).model_dump(),
        )
    except json.JSONDecodeError as e:
        return _error_response(
            500, "JSONDecodeError", "Config file contains invalid JSON", e
        )


# ---------------------------------------------------------------------------
# POST /api/hash-key — hash a plaintext API key
# ---------------------------------------------------------------------------


@router.post("/hash-key")
async def hash_key(
    request: Request,
    token: str = Depends(verify_token),
) -> JSONResponse:
    """Hash a plaintext API key using PBKDF2-HMAC-SHA256.

    Returns the PBKDF2 hash string suitable for storing in the config.
    """
    logger.debug("hash_key entry")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    try:
        parsed = HashKeyRequest.model_validate(body)
    except Exception as exc:
        return _error_response(
            422, "ValidationError", "Invalid request body", exc
        )

    result = hash_api_key(parsed.key)
    return JSONResponse(
        content=HashKeyResponse(key_hash=result).model_dump(),
    )


# ---------------------------------------------------------------------------
# GET /api/config/schema — JSON Schema (no auth)
# ---------------------------------------------------------------------------

# In standalone mode the schema lives next to the config-api package
# (3 levels up from routes.py), while in the unified container it is at
# the app root (2 levels up).  Try both and fall back to the one that
# exists.
_schema_candidates = [
    Path(__file__).resolve().parent.parent.parent / "config.schema.json",
    Path(__file__).resolve().parent.parent / "config.schema.json",
]
_SCHEMA_PATH: Path | None = next(
    (p for p in _schema_candidates if p.is_file()),
    None,
)
_schema_cache: dict | None = None


@router.get("/config/schema")
async def get_config_schema() -> JSONResponse:
    """Return the config JSON Schema.  No authentication required."""
    logger.debug("get_config_schema entry")
    global _schema_cache  # noqa: PLW0603
    if _SCHEMA_PATH is None:
        return JSONResponse(
            status_code=503,
            content={"error": True, "message": "config.schema.json not found"},
        )
    if _schema_cache is None:
        with _SCHEMA_PATH.open("r", encoding="utf-8") as f:
            _schema_cache = json.load(f)
    return JSONResponse(content=_schema_cache)


# ---------------------------------------------------------------------------
# POST /api/config/validate — validate config without writing
# ---------------------------------------------------------------------------


@router.post("/config/validate")
async def validate_config(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Validate a config dict without writing it to disk.

    Returns the validated config with defaults applied on success,
    or an error response if validation fails.
    """
    logger.debug("validate_config entry")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must be a JSON object",
            ).model_dump(),
        )

    try:
        validated = svc.validate_only(body)
        return JSONResponse(
            content=ValidateResponse(
                valid=True, config=validated,
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# GET /api/config/ssh_targets/{name} — single SSH target
# ---------------------------------------------------------------------------


@router.get("/config/ssh_targets/{name}")
async def get_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read a single SSH target by name (secrets stripped)."""
    logger.debug("get_ssh_target entry: name=%s", name)
    try:
        target = svc.get_ssh_target(name)
        return JSONResponse(content=target)
    except KeyError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="KeyError",
                message=f"SSH target '{name}' not found",
            ).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config file not found",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# PUT /api/config/ssh_targets/{name} — create or replace SSH target
# ---------------------------------------------------------------------------


@router.put("/config/ssh_targets/{name}")
async def put_ssh_target(
    name: str,
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Create or replace a single SSH target."""
    logger.debug("put_ssh_target entry: name=%s", name)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must be a JSON object",
            ).model_dump(),
        )

    try:
        result = svc.put_ssh_target(name, body)
        logger.debug("put_ssh_target exit: name=%s, success", name)
        return JSONResponse(content=result)
    except ValueError as e:
        return _error_response(
            400, "ValueError", "Invalid SSH target data", e
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# DELETE /api/config/ssh_targets/{name} — delete SSH target
# ---------------------------------------------------------------------------


@router.delete("/config/ssh_targets/{name}")
async def delete_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Delete a single SSH target."""
    logger.debug("delete_ssh_target entry: name=%s", name)
    try:
        svc.delete_ssh_target(name)
        logger.debug("delete_ssh_target exit: name=%s, success", name)
        return JSONResponse(
            content={"message": f"SSH target '{name}' deleted"},
        )
    except KeyError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="KeyError",
                message=f"SSH target '{name}' not found",
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# POST /api/config/ssh_targets/{name}/check — test SSH connectivity
# ---------------------------------------------------------------------------


@router.post("/config/ssh_targets/{name}/check")
async def check_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Execute the checkcommand on an SSH target to verify connectivity.

    Returns a JSON object with success, output, error, exit_code,
    and checkcommand fields.
    """
    logger.debug("check_ssh_target entry: name=%s", name)
    try:
        result = svc.check_ssh_target(name)
        logger.debug("check_ssh_target exit: name=%s, success=%s", name, result.get("success"))
        return JSONResponse(content=result)
    except KeyError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="KeyError",
                message=f"SSH target '{name}' not found",
            ).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config file not found",
            ).model_dump(),
        )
    except Exception as e:
        return _error_response(
            500, "SSHCheckError", "SSH connection check failed", e,
            log_level=logging.ERROR,
        )


# ---------------------------------------------------------------------------
# POST /api/config/block_patterns — append a block pattern
# ---------------------------------------------------------------------------


@router.post("/config/block_patterns")
async def append_block_pattern(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Append a new block pattern to the list."""
    logger.debug("append_block_pattern entry")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    pattern = body.get("pattern") if isinstance(body, dict) else None
    if not pattern or not isinstance(pattern, str):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must contain a non-empty 'pattern' string",
            ).model_dump(),
        )

    try:
        result = svc.append_block_pattern(pattern)
        logger.debug("append_block_pattern exit: pattern_count=%d", len(result))
        return JSONResponse(
            content=ConfigSectionResponse(
                section="block_patterns", data=result,
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# PUT /api/config/block_patterns — replace all block patterns
# ---------------------------------------------------------------------------


@router.put("/config/block_patterns")
async def replace_block_patterns(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace the entire block_patterns list."""
    logger.debug("replace_block_patterns entry")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    if not isinstance(body, list):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must be a JSON array of pattern strings",
            ).model_dump(),
        )

    try:
        result = svc.replace_block_patterns(body)
        logger.debug("replace_block_patterns exit: pattern_count=%d", len(result))
        return JSONResponse(
            content=ConfigSectionResponse(
                section="block_patterns", data=result,
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# PUT /api/config/block_patterns/{index} — replace single block pattern
# ---------------------------------------------------------------------------


@router.put("/config/block_patterns/{index}")
async def put_block_pattern(
    index: int,
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace a single block pattern at the given index."""
    logger.debug("put_block_pattern entry: index=%d", index)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    pattern = body.get("pattern") if isinstance(body, dict) else None
    if not pattern or not isinstance(pattern, str):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must contain a non-empty 'pattern' string",
            ).model_dump(),
        )

    try:
        result = svc.put_block_pattern(index, pattern)
        logger.debug("put_block_pattern exit: index=%d, pattern_count=%d", index, len(result))
        return JSONResponse(
            content=ConfigSectionResponse(
                section="block_patterns", data=result,
            ).model_dump(),
        )
    except IndexError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="IndexError",
                message=f"Block pattern index {index} out of range",
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# DELETE /api/config/block_patterns/{index} — remove single block pattern
# ---------------------------------------------------------------------------


@router.delete("/config/block_patterns/{index}")
async def delete_block_pattern(
    index: int,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Remove a single block pattern at the given index."""
    logger.debug("delete_block_pattern entry: index=%d", index)
    try:
        result = svc.delete_block_pattern(index)
        logger.debug("delete_block_pattern exit: index=%d, pattern_count=%d", index, len(result))
        return JSONResponse(
            content=ConfigSectionResponse(
                section="block_patterns", data=result,
            ).model_dump(),
        )
    except IndexError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="IndexError",
                message=f"Block pattern index {index} out of range",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# GET /api/backups — list config backups
# ---------------------------------------------------------------------------


@router.get("/backups")
async def list_backups(
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """List all config backup files, sorted newest first."""
    logger.debug("list_backups entry")
    try:
        raw_backups = svc.backup_list()
        backups = [BackupInfo(**b) for b in raw_backups]
        logger.debug("list_backups exit: backup_count=%d", len(backups))
        return JSONResponse(
            content=BackupListResponse(backups=backups).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config directory not found",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# POST /api/backups/{name}/restore — restore from backup
# ---------------------------------------------------------------------------


@router.post("/backups/{name}/restore")
async def restore_backup(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Restore configuration from a backup file."""
    logger.debug("restore_backup entry: name=%s", name)
    try:
        restored = svc.backup_restore(name)
        logger.debug("restore_backup exit: name=%s, success", name)
        return JSONResponse(
            content=BackupRestoreResponse(
                message=f"Config restored from {name}",
                config=restored,
            ).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message=f"Backup file '{name}' not found",
            ).model_dump(),
        )
    except json.JSONDecodeError as e:
        return _error_response(
            500, "JSONDecodeError", "Backup file contains invalid JSON", e
        )
    except ValueError as e:
        return _error_response(
            400, "ValueError", "Invalid backup name", e
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# DELETE /api/backups/{name} — delete a backup
# ---------------------------------------------------------------------------


@router.delete("/backups/{name}")
async def delete_backup(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Delete a single backup file."""
    logger.debug("delete_backup entry: name=%s", name)
    try:
        svc.backup_delete(name)
        logger.debug("delete_backup exit: name=%s, success", name)
        return JSONResponse(content={"message": "Backup deleted"})
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message=f"Backup file '{name}' not found",
            ).model_dump(),
        )
    except ValueError as e:
        return _error_response(
            400, "ValueError", "Invalid backup name", e
        )


# ---------------------------------------------------------------------------
# PUT /api/config — replace full config
# ---------------------------------------------------------------------------


@router.put("/config")
async def put_config(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace the full configuration.

    The request body must be a valid JSON object matching the config schema.
    Secret fields (password, private_key, key_hash) are stripped before
    writing.  The config is validated using ConfigManager._validate().
    """
    logger.debug("put_config entry")
    # Enforce body size limit (1 MB) — check Content-Length first
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 1_048_576:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=ErrorResponse(
                error_type="PayloadTooLarge",
                message="Request body must not exceed 1 MB",
            ).model_dump(),
        )

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    if not isinstance(body, dict):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message="Request body must be a JSON object",
            ).model_dump(),
        )

    try:
        validated = svc.write_config(body)
        logger.debug("put_config exit: success, config_keys=%s", list(validated.keys()) if isinstance(validated, dict) else "non-dict")
        return JSONResponse(content=validated)
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )
    except OSError as e:
        return _error_response(
            500, "OSError", "Failed to write configuration", e,
            log_level=logging.ERROR,
        )


# ---------------------------------------------------------------------------
# GET /api/config/{section} — single section
# ---------------------------------------------------------------------------


@router.get("/config/{section}")
async def get_config_section(
    section: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read a single top-level config section.

    Valid sections: ssh_targets, block_patterns, allowed_commands, settings.
    """
    logger.debug("get_config_section entry: section=%s", section)
    try:
        data = svc.read_section(section)
        # Strip secrets from ssh_targets section for API consumers
        if section == "ssh_targets":
            data = svc._strip_secrets({"ssh_targets": data})["ssh_targets"]
        logger.debug("get_config_section exit: section=%s, data_keys=%s", section, list(data.keys()) if isinstance(data, dict) else "non-dict")
        return JSONResponse(
            content=ConfigSectionResponse(
                section=section, data=data,
            ).model_dump(),
        )
    except ValueError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="ValueError",
                message=(
                    f"Invalid section '{section}'. "
                    f"Valid sections: {', '.join(sorted(svc.VALID_SECTIONS))}"
                ),
            ).model_dump(),
        )
    except KeyError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="KeyError",
                message=f"Section '{section}' not found in config",
            ).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config file not found",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# PUT /api/config/{section} — replace single section
# ---------------------------------------------------------------------------


@router.put("/config/{section}")
async def put_config_section(
    section: str,
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace a single config section.

    Reads the current full config, replaces the specified section with the
    request body, validates the merged config, and atomically writes.
    """
    logger.debug("put_config_section entry: section=%s", section)
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message="Request body must be valid JSON",
            ).model_dump(),
        )

    try:
        validated = svc.write_section(section, body)
        logger.debug("put_config_section exit: section=%s, success", section)
        return JSONResponse(
            content=ConfigSectionResponse(
                section=section,
                data=validated.get(section, body),
            ).model_dump(),
        )
    except ValueError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="ValueError",
                message=(
                    f"Invalid section '{section}'. "
                    f"Valid sections: {', '.join(sorted(svc.VALID_SECTIONS))}"
                ),
            ).model_dump(),
        )
    except ConfigValidationError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ConfigValidationError",
                message=str(e),
                field=getattr(e, "field", None),
            ).model_dump(),
        )
    except FileNotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                error_type="FileNotFoundError",
                message="Config file not found",
            ).model_dump(),
        )
    except OSError as e:
        return _error_response(
            500, "OSError", "Failed to write configuration", e,
            log_level=logging.ERROR,
        )


# ---------------------------------------------------------------------------
# POST /api/auth/login — token login, sets session cookie
# ---------------------------------------------------------------------------


@auth_router.post("/login")
async def login(request: Request) -> JSONResponse:
    """Validate a raw API token and create a session cookie.

    Accepts a JSON body ``{"token": "<raw_token>"}`` and validates it
    against the configured token using timing-safe comparison.  On success
    an HttpOnly session cookie is set on the response.

    Args:
        request: The incoming request containing the JSON body.

    Returns:
        JSONResponse with ``{"status": "ok"}`` on success.

    Raises:
        JSONResponse: 401 if the token is invalid.
    """
    logger.debug("login entry")
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": True, "message": "Invalid token"},
        )

    token = body.get("token") if isinstance(body, dict) else None
    if not token or not isinstance(token, str):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": True, "message": "Invalid token"},
        )

    try:
        expected = get_token()
    except RuntimeError:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": True, "message": "Invalid token"},
        )

    if not hmac.compare_digest(expected, token):
        logger.debug("login: token mismatch")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": True, "message": "Invalid token"},
        )

    session_id = create_session()
    response = JSONResponse(content={"status": "ok"})
    response.set_cookie(
        key=CONFIG_API_SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=CONFIG_API_SESSION_COOKIE_SAMESITE,  # type: ignore[arg-type]
        max_age=CONFIG_API_SESSION_MAX_AGE_SECONDS,
        path="/api",
    )
    logger.debug("login exit: session created")
    return response


# ---------------------------------------------------------------------------
# POST /api/auth/logout — clear cookie and revoke session
# ---------------------------------------------------------------------------


@auth_router.post("/logout")
async def logout(
    request: Request,
    token: str = Depends(verify_token),  # noqa: ARG001
) -> JSONResponse:
    """Clear the session cookie and revoke the current session.

    Requires a valid session cookie or Bearer token.  Removes the session
    from the in-memory store and clears the cookie on the response.

    Args:
        request: The incoming request (used to read the session cookie).
        token: Verified token from the auth dependency (unused).

    Returns:
        JSONResponse with ``{"status": "ok"}``.
    """
    logger.debug("logout entry")
    session_id = request.cookies.get(CONFIG_API_SESSION_COOKIE_NAME)
    if session_id:
        revoke_session(session_id)

    response = JSONResponse(content={"status": "ok"})
    response.delete_cookie(
        key=CONFIG_API_SESSION_COOKIE_NAME,
        path="/api",
    )
    logger.debug("logout exit: session cleared")
    return response


# ---------------------------------------------------------------------------
# GET /api/auth/session — lightweight session validity check
# ---------------------------------------------------------------------------


@auth_router.get("/session")
async def session_check(
    token: str = Depends(verify_token),  # noqa: ARG001
) -> JSONResponse:
    """Check whether the current session or token is valid.

    Accepts either a valid session cookie or Bearer token.  Returns
    ``{"authenticated": true}`` when the request is authenticated.

    Args:
        token: Verified token from the auth dependency (unused).

    Returns:
        JSONResponse with ``{"authenticated": true}``.
    """
    logger.debug("session_check exit: authenticated")
    return JSONResponse(content={"authenticated": True})
