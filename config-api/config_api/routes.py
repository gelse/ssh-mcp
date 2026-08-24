"""FastAPI route handlers for config endpoints.

Defines an ``APIRouter`` with all config management endpoints.  Each route
handler authenticates via ``Depends(verify_token)`` (except ``/health``),
delegates to ``ConfigService`` for file operations, and returns structured
JSON responses with appropriate HTTP status codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from config_api.auth import verify_token
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
from lib.crypto import hash_api_key
from lib.exceptions import ConfigValidationError

router = APIRouter()

# ---------------------------------------------------------------------------
# Config service singleton
# ---------------------------------------------------------------------------

_config_service: ConfigService | None = None


def init_config_service(config_dir: str | None = None) -> ConfigService:
    """Initialize the config service singleton.  Called once at startup."""
    global _config_service
    _config_service = ConfigService(config_dir)
    return _config_service


def get_config_service() -> ConfigService:
    """FastAPI dependency that returns the config service singleton."""
    if _config_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Config service not initialized",
        )
    return _config_service


# ---------------------------------------------------------------------------
# Health endpoint (no auth)
# ---------------------------------------------------------------------------


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe.  No authentication required."""
    return HealthResponse(status="ok")


# ---------------------------------------------------------------------------
# GET /api/config — full config
# ---------------------------------------------------------------------------


@router.get("/api/config")
async def get_config(
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read the full on-disk configuration.

    Returns the raw JSON content of the config file without any
    secret merging or environment variable overrides.
    """
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message=f"Config file contains invalid JSON: {e}",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# POST /api/hash-key — hash a plaintext API key
# ---------------------------------------------------------------------------


@router.post("/api/hash-key")
async def hash_key(
    request: Request,
    token: str = Depends(verify_token),
) -> JSONResponse:
    """Hash a plaintext API key using PBKDF2-HMAC-SHA256.

    Returns the PBKDF2 hash string suitable for storing in the config.
    """
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
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                error_type="ValidationError",
                message=str(exc),
            ).model_dump(),
        )

    result = hash_api_key(parsed.key)
    return JSONResponse(
        content=HashKeyResponse(key_hash=result).model_dump(),
    )


# ---------------------------------------------------------------------------
# GET /api/config/schema — JSON Schema (no auth)
# ---------------------------------------------------------------------------

_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "config.schema.json"
_schema_cache: dict | None = None


@router.get("/api/config/schema")
async def get_config_schema() -> JSONResponse:
    """Return the config JSON Schema.  No authentication required."""
    global _schema_cache  # noqa: PLW0603
    if _schema_cache is None:
        with _SCHEMA_PATH.open("r", encoding="utf-8") as f:
            _schema_cache = json.load(f)
    return JSONResponse(content=_schema_cache)


# ---------------------------------------------------------------------------
# POST /api/config/validate — validate config without writing
# ---------------------------------------------------------------------------


@router.post("/api/config/validate")
async def validate_config(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Validate a config dict without writing it to disk.

    Returns the validated config with defaults applied on success,
    or an error response if validation fails.
    """
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


@router.get("/api/config/ssh_targets/{name}")
async def get_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read a single SSH target by name (secrets stripped)."""
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


@router.put("/api/config/ssh_targets/{name}")
async def put_ssh_target(
    name: str,
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Create or replace a single SSH target."""
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
        return JSONResponse(content=result)
    except ValueError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ValueError",
                message=str(e),
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
# DELETE /api/config/ssh_targets/{name} — delete SSH target
# ---------------------------------------------------------------------------


@router.delete("/api/config/ssh_targets/{name}")
async def delete_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Delete a single SSH target."""
    try:
        svc.delete_ssh_target(name)
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


@router.post("/api/config/ssh_targets/{name}/check")
async def check_ssh_target(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Execute the checkcommand on an SSH target to verify connectivity.

    Returns a JSON object with success, output, error, exit_code,
    and checkcommand fields.
    """
    try:
        result = svc.check_ssh_target(name)
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error_type="SSHCheckError",
                message=f"Connection check failed: {e}",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# POST /api/config/block_patterns — append a block pattern
# ---------------------------------------------------------------------------


@router.post("/api/config/block_patterns")
async def append_block_pattern(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Append a new block pattern to the list."""
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


@router.put("/api/config/block_patterns")
async def replace_block_patterns(
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace the entire block_patterns list."""
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


@router.put("/api/config/block_patterns/{index}")
async def put_block_pattern(
    index: int,
    request: Request,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Replace a single block pattern at the given index."""
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


@router.delete("/api/config/block_patterns/{index}")
async def delete_block_pattern(
    index: int,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Remove a single block pattern at the given index."""
    try:
        result = svc.delete_block_pattern(index)
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


@router.get("/api/backups")
async def list_backups(
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """List all config backup files, sorted newest first."""
    try:
        raw_backups = svc.backup_list()
        backups = [BackupInfo(**b) for b in raw_backups]
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


@router.post("/api/backups/{name}/restore")
async def restore_backup(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Restore configuration from a backup file."""
    try:
        restored = svc.backup_restore(name)
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error_type="JSONDecodeError",
                message=f"Backup file contains invalid JSON: {e}",
            ).model_dump(),
        )
    except ValueError as e:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ValueError",
                message=str(e),
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
# DELETE /api/backups/{name} — delete a backup
# ---------------------------------------------------------------------------


@router.delete("/api/backups/{name}")
async def delete_backup(
    name: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Delete a single backup file."""
    try:
        svc.backup_delete(name)
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
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                error_type="ValueError",
                message=str(e),
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# PUT /api/config — replace full config
# ---------------------------------------------------------------------------


@router.put("/api/config")
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error_type="OSError",
                message=f"Failed to write config: {e}",
            ).model_dump(),
        )


# ---------------------------------------------------------------------------
# GET /api/config/{section} — single section
# ---------------------------------------------------------------------------


@router.get("/api/config/{section}")
async def get_config_section(
    section: str,
    token: str = Depends(verify_token),
    svc: ConfigService = Depends(get_config_service),
) -> JSONResponse:
    """Read a single top-level config section.

    Valid sections: ssh_targets, block_patterns, allowed_commands, settings.
    """
    try:
        data = svc.read_section(section)
        # Strip secrets from ssh_targets section for API consumers
        if section == "ssh_targets":
            data = svc._strip_secrets({"ssh_targets": data})["ssh_targets"]
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


@router.put("/api/config/{section}")
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
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error_type="OSError",
                message=f"Failed to write config: {e}",
            ).model_dump(),
        )
