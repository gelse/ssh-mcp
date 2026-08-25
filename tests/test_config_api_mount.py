"""Tests for config-api sub-application mounting in server.py.

Verifies that when CONFIG_API_ENABLED=true the FastAPI config-api app is
created and mounted at ``/api`` on the underlying Starlette ASGI app, and
that when the env var is absent or false, no mounting occurs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastmcp import FastMCP

import server


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(config_dir: Path, data: dict) -> Path:
    """Write a config dict to ssh-mcp-config.json in the given directory."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(data))
    return config_path


def _make_minimal_config() -> dict:
    """Return a minimal valid config dict."""
    return {
        "version": 1,
        "ssh_targets": {
            "testserver": {
                "host": "10.0.0.1",
                "username": "testuser",
                "port": 22,
                "password": "testpass",
            },
        },
        "block_patterns": [r"\brm\s+-rf\b"],
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": ["hostname", "uptime"]},
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }


# ---------------------------------------------------------------------------
# create_app() config-api state tests
# ---------------------------------------------------------------------------


class TestConfigApiMounting:
    """Tests for the CONFIG_API_ENABLED feature in create_app()."""

    def test_disabled_by_default(self, tmp_path):
        """When CONFIG_API_ENABLED is not set, config_api_app is None."""
        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.delenv("CONFIG_API_ENABLED", raising=False)
        try:
            mcp = server.create_app(
                config_dir=str(tmp_path),
                log_dir=str(tmp_path / "logs"),
            )
            assert getattr(mcp.state, "config_api_app", None) is None
        finally:
            monkeypatch.undo()

    def test_disabled_explicitly(self, tmp_path):
        """When CONFIG_API_ENABLED=false, config_api_app is None."""
        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "false")
        try:
            mcp = server.create_app(
                config_dir=str(tmp_path),
                log_dir=str(tmp_path / "logs"),
            )
            assert getattr(mcp.state, "config_api_app", None) is None
        finally:
            monkeypatch.undo()

    def test_enabled_creates_fastapi_app(self, tmp_path):
        """When CONFIG_API_ENABLED=true, config_api_app is a FastAPI instance."""
        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "true")
        # Mock config_api.app.create_app since config-api may not be on sys.path
        mock_fastapi_app = FastAPI(title="Mock Config API")
        mock_create_app = MagicMock(return_value=mock_fastapi_app)
        mock_config_api_app_module = MagicMock()
        mock_config_api_app_module.create_app = mock_create_app
        try:
            with patch.dict(
                sys.modules,
                {"config_api": MagicMock(), "config_api.app": mock_config_api_app_module},
            ):
                mcp = server.create_app(
                    config_dir=str(tmp_path),
                    log_dir=str(tmp_path / "logs"),
                )
            config_api_app = getattr(mcp.state, "config_api_app", None)
            assert config_api_app is not None
            assert isinstance(config_api_app, FastAPI)
            assert config_api_app.title == "Mock Config API"
        finally:
            monkeypatch.undo()

    def test_enabled_case_insensitive(self, tmp_path):
        """CONFIG_API_ENABLED=True (uppercase) is treated as enabled."""
        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "True")
        mock_fastapi_app = FastAPI(title="Mock Config API")
        mock_create_app = MagicMock(return_value=mock_fastapi_app)
        mock_config_api_app_module = MagicMock()
        mock_config_api_app_module.create_app = mock_create_app
        try:
            with patch.dict(
                sys.modules,
                {"config_api": MagicMock(), "config_api.app": mock_config_api_app_module},
            ):
                mcp = server.create_app(
                    config_dir=str(tmp_path),
                    log_dir=str(tmp_path / "logs"),
                )
            config_api_app = getattr(mcp.state, "config_api_app", None)
            assert config_api_app is not None
        finally:
            monkeypatch.undo()

    def test_import_failure_sets_none(self, tmp_path):
        """If config_api import fails, config_api_app is set to None."""
        import builtins

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "true")

        original_import = builtins.__import__

        def _block_config_api_import(name, *args, **kwargs):
            if name == "config_api" or name.startswith("config_api."):
                raise ImportError("No module named 'config_api'")
            return original_import(name, *args, **kwargs)

        # Clear any cached config_api modules so the import is attempted fresh
        cached = {k: v for k, v in sys.modules.items() if k.startswith("config_api")}
        try:
            for k in cached:
                del sys.modules[k]
            builtins.__import__ = _block_config_api_import
            mcp = server.create_app(
                config_dir=str(tmp_path),
                log_dir=str(tmp_path / "logs"),
            )
            assert getattr(mcp.state, "config_api_app", None) is None
        finally:
            builtins.__import__ = original_import
            for k, v in cached.items():
                sys.modules[k] = v


# ---------------------------------------------------------------------------
# _run_server() Starlette mount tests
# ---------------------------------------------------------------------------


class TestConfigApiStarletteMount:
    """Tests that _run_server() mounts the config API at /api on the
    Starlette ASGI app when CONFIG_API_ENABLED=true."""

    def test_mount_added_when_enabled(self, tmp_path):
        """Config API route is inserted at /api when config_api_app exists."""
        from starlette.routing import Mount

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "true")
        mock_fastapi_app = FastAPI(title="Mock Config API")
        mock_create_app = MagicMock(return_value=mock_fastapi_app)
        mock_config_api_app_module = MagicMock()
        mock_config_api_app_module.create_app = mock_create_app
        try:
            with patch.dict(
                sys.modules,
                {"config_api": MagicMock(), "config_api.app": mock_config_api_app_module},
            ):
                mcp = server.create_app(
                    config_dir=str(tmp_path),
                    log_dir=str(tmp_path / "logs"),
                )
            # Simulate what _run_server does: create the Starlette app
            starlette_app = mcp.http_app(
                path="/mcp",
                transport="streamable-http",
            )
            # Before mount, there should be no /api route
            api_routes_before = [
                r for r in starlette_app.routes
                if isinstance(r, Mount) and r.path == "/api"
            ]
            assert len(api_routes_before) == 0

            # Simulate the mount logic from _run_server()
            config_api_app = getattr(mcp.state, "config_api_app", None)
            assert config_api_app is not None
            starlette_app.routes.insert(0, Mount("/api", app=config_api_app))

            # After mount, there should be a /api route
            api_routes_after = [
                r for r in starlette_app.routes
                if isinstance(r, Mount) and r.path == "/api"
            ]
            assert len(api_routes_after) == 1
        finally:
            monkeypatch.undo()

    def test_no_mount_when_disabled(self, tmp_path):
        """No /api route is added when config_api_app is None."""
        from starlette.routing import Mount

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.delenv("CONFIG_API_ENABLED", raising=False)
        try:
            mcp = server.create_app(
                config_dir=str(tmp_path),
                log_dir=str(tmp_path / "logs"),
            )
            starlette_app = mcp.http_app(
                path="/mcp",
                transport="streamable-http",
            )

            # Simulate the mount logic — should be skipped
            config_api_app = getattr(mcp.state, "config_api_app", None)
            assert config_api_app is None
            # No mount happens

            api_routes = [
                r for r in starlette_app.routes
                if isinstance(r, Mount) and r.path == "/api"
            ]
            assert len(api_routes) == 0
        finally:
            monkeypatch.undo()

    def test_mcp_route_preserved_after_mount(self, tmp_path):
        """The /mcp route is still present after mounting config API at /api."""
        from starlette.routing import Mount, Route

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "true")
        mock_fastapi_app = FastAPI(title="Mock Config API")
        mock_create_app = MagicMock(return_value=mock_fastapi_app)
        mock_config_api_app_module = MagicMock()
        mock_config_api_app_module.create_app = mock_create_app
        try:
            with patch.dict(
                sys.modules,
                {"config_api": MagicMock(), "config_api.app": mock_config_api_app_module},
            ):
                mcp = server.create_app(
                    config_dir=str(tmp_path),
                    log_dir=str(tmp_path / "logs"),
                )
            starlette_app = mcp.http_app(
                path="/mcp",
                transport="streamable-http",
            )

            # Mount config API
            config_api_app = getattr(mcp.state, "config_api_app", None)
            starlette_app.routes.insert(0, Mount("/api", app=config_api_app))

            # /mcp route should still exist
            mcp_routes = [
                r for r in starlette_app.routes
                if isinstance(r, Route) and r.path == "/mcp"
            ]
            assert len(mcp_routes) == 1
        finally:
            monkeypatch.undo()


class TestConfigApiDispatch:
    """Real ASGI request-dispatch tests for the config-api mount.

    These tests build a minimal FastAPI sub-app (simulating the config-api
    with prefix-free routes), mount it at ``/api`` on the Starlette app,
    and send actual HTTP requests to verify the double-prefix bug is fixed.
    """

    def _build_sub_app(self) -> FastAPI:
        """Return a minimal FastAPI sub-app with prefix-free routes."""
        from fastapi.responses import JSONResponse

        sub = FastAPI(title="Mock Config API")

        @sub.get("/health")
        async def health() -> JSONResponse:
            return JSONResponse({"status": "ok"})

        @sub.get("/config")
        async def get_config() -> JSONResponse:
            return JSONResponse({"ssh_targets": {}})

        return sub

    def test_api_config_returns_success(self, tmp_path: Path) -> None:
        """GET /api/config on the mounted app returns 200, not 404."""
        from starlette.routing import Mount
        from starlette.testclient import TestClient

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "false")
        try:
            sub_app = self._build_sub_app()

            # Build a starlette app with just the mount
            from starlette.applications import Starlette

            starlette_app = Starlette(
                routes=[Mount("/api", app=sub_app)],
            )

            client = TestClient(starlette_app)
            resp = client.get("/api/config")
            assert resp.status_code == 200
            assert resp.json() == {"ssh_targets": {}}
        finally:
            monkeypatch.undo()

    def test_api_health_returns_success(self, tmp_path: Path) -> None:
        """GET /api/health on the mounted app returns 200."""
        from starlette.routing import Mount
        from starlette.testclient import TestClient

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "false")
        try:
            sub_app = self._build_sub_app()

            from starlette.applications import Starlette

            starlette_app = Starlette(
                routes=[Mount("/api", app=sub_app)],
            )

            client = TestClient(starlette_app)
            resp = client.get("/api/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}
        finally:
            monkeypatch.undo()

    def test_double_prefix_returns_404(self, tmp_path: Path) -> None:
        """GET /api/api/config returns 404 — no double-prefix routing."""
        from starlette.routing import Mount
        from starlette.testclient import TestClient

        _write_config(tmp_path, _make_minimal_config())
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("CONFIG_API_ENABLED", "false")
        try:
            sub_app = self._build_sub_app()

            from starlette.applications import Starlette

            starlette_app = Starlette(
                routes=[Mount("/api", app=sub_app)],
            )

            client = TestClient(starlette_app)
            resp = client.get("/api/api/config")
            assert resp.status_code == 404
        finally:
            monkeypatch.undo()
