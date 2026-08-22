"""FastAPI route handlers for config endpoints.

Defines an ``APIRouter`` with all config management endpoints.  Each route
handler authenticates via ``Depends(verify_token)`` (except ``/health``),
delegates to ``ConfigService`` for file operations, and returns structured
JSON responses with appropriate HTTP status codes.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from config_api.auth import verify_token
from config_api.config_service import ConfigService
from config_api.models import (
    ConfigSectionResponse,
    ErrorResponse,
    HealthResponse,
)
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
        return JSONResponse(content=config)
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
