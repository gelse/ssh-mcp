"""FastAPI application factory for the config API.

Creates and configures the FastAPI application with all routes,
middleware, and dependencies.  No module-level side effects —
everything is initialized inside create_app().
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from config_api.auth import load_token
from config_api.config_service import ConfigService
from config_api.routes import init_config_service, router


# ---------------------------------------------------------------------------
# Lifespan & background tasks
# ---------------------------------------------------------------------------


async def _periodic_cleanup(svc: ConfigService) -> None:
    """Run backup cleanup every hour."""
    while True:
        await asyncio.sleep(3600)  # 1 hour
        try:
            deleted = svc.cleanup_old_backups()
            if deleted:
                logging.getLogger("config_api").info(
                    "Cleaned up %d old backup(s)", deleted
                )
        except Exception:
            logging.getLogger("config_api").exception(
                "Backup cleanup failed"
            )


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    """Manage background tasks during app lifecycle."""
    # Start background cleanup task
    svc: ConfigService = app.state.config_service
    task = asyncio.create_task(_periodic_cleanup(svc))
    yield
    # Cancel on shutdown
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app(
    config_dir: str | None = None,
    *,
    ssh_client_manager: object | None = None,
    ssh_config_manager: object | None = None,
    ssh_key_path: str | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config_dir: Path to the config directory.  If None, uses the
                    CONFIG_DIR env var or defaults to /config.
        ssh_client_manager: Optional SSHClientManager for unified mode.
        ssh_config_manager: Optional ConfigManager for unified mode.
        ssh_key_path: Optional path to the SSH key for unified mode.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title="MCP SSH Config API",
        description="REST API for managing SSH MCP server configuration",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Load Bearer token from environment (required for auth).
    # create_app() is the entry point so we must load here.
    from config_api.auth import load_token  # noqa: PLC0415

    try:
        load_token()
    except RuntimeError:
        # Token is optional — if not set, auth-protected routes will
        # reject requests at call time rather than crashing at startup.
        pass

    # Initialize config service
    svc = init_config_service(
        config_dir,
        ssh_client_manager=ssh_client_manager,
        ssh_config_manager=ssh_config_manager,
        ssh_key_path=ssh_key_path,
    )

    # Mount routes
    app.include_router(router)

    # Store service reference for shutdown/cleanup
    app.state.config_service = svc

    # Mount SPA static files — must be AFTER router so API routes take priority
    _ui_dir = Path(__file__).resolve().parent / "ui"
    if _ui_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(_ui_dir), html=True), name="ui")

    return app
