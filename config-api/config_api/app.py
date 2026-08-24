"""FastAPI application factory for the config API.

Creates and configures the FastAPI application with all routes,
middleware, and dependencies.  No module-level side effects —
everything is initialized inside create_app() or main().
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
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


def create_app(config_dir: str | None = None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        config_dir: Path to the config directory.  If None, uses the
                    CONFIG_DIR env var or defaults to /config.

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

    # Initialize config service
    svc = init_config_service(config_dir)

    # Mount routes
    app.include_router(router)

    # Store service reference for shutdown/cleanup
    app.state.config_service = svc

    # Mount SPA static files — must be AFTER router so API routes take priority
    _ui_dir = Path(__file__).resolve().parent / "ui"
    if _ui_dir.is_dir():
        app.mount("/ui", StaticFiles(directory=str(_ui_dir), html=True), name="ui")

    return app


def main() -> None:
    """CLI entry point for the config API server.

    Environment variables:
        CONFIG_API_TOKEN: Required. Bearer token for API authentication.
        CONFIG_DIR: Config directory path (default: /config).
        CONFIG_API_PORT: Port to listen on (default: 8081).
        CONFIG_API_HOST: Bind address (default: 0.0.0.0).
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logger = logging.getLogger("config_api")

    # Load token (raises RuntimeError if not set)
    try:
        load_token()
    except RuntimeError as e:
        logger.error("Startup failed: %s", e)
        sys.exit(1)

    # Read settings from environment
    config_dir = os.environ.get("CONFIG_DIR", "/config")
    host = os.environ.get("CONFIG_API_HOST", "0.0.0.0")
    port = int(os.environ.get("CONFIG_API_PORT", "8081"))

    logger.info("Starting config API on %s:%d", host, port)
    logger.info("Config directory: %s", config_dir)

    # Create app
    app = create_app(config_dir)

    # Run with uvicorn
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
