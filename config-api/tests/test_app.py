"""Tests for config_api.app — application factory."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from config_api.app import create_app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(config_dir: Path, config: dict) -> Path:
    """Write a config dict to the standard config file location."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def _minimal_config() -> dict:
    """Return a minimal valid config dict."""
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


# ---------------------------------------------------------------------------
# create_app() tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons():  # noqa: ANN201
    """Reset module-level singletons between tests."""
    from config_api import auth as auth_mod
    from config_api import routes as routes_mod

    auth_mod._token = None
    routes_mod._config_service = None
    yield
    auth_mod._token = None
    routes_mod._config_service = None


class TestCreateApp:
    """Tests for the create_app() factory function."""

    def test_returns_fastapi_instance(self, tmp_path: Path) -> None:
        """create_app() returns a FastAPI instance."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        assert isinstance(app, FastAPI)

    def test_app_metadata(self, tmp_path: Path) -> None:
        """App has correct title, description, and version."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        assert app.title == "MCP SSH Config API"
        assert app.description == "REST API for managing SSH MCP server configuration"
        assert app.version == "1.0.0"

    def test_docs_endpoints_enabled(self, tmp_path: Path) -> None:
        """/docs and /redoc endpoints are available."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        assert app.docs_url == "/docs"
        assert app.redoc_url == "/redoc"

    def test_config_service_stored_on_app_state(
        self, tmp_path: Path
    ) -> None:
        """The config service is stored on app.state.config_service."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        assert hasattr(app.state, "config_service")
        assert app.state.config_service is not None

    def test_health_endpoint_works(self, tmp_path: Path) -> None:
        """The /health endpoint returns 200 with status ok."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    def test_api_config_endpoint_requires_auth(self, tmp_path: Path) -> None:
        """The /config endpoint requires Bearer token auth."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        response = client.get("/config")
        assert response.status_code == 401  # HTTPBearer returns 401 when missing

    def test_api_config_endpoint_with_valid_token(self, tmp_path: Path) -> None:
        """The /config endpoint returns config with a valid token."""
        _write_config(tmp_path, _minimal_config())
        # Set token in the auth module
        from config_api import auth as auth_mod

        auth_mod._token = "test-token-123"

        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        response = client.get(
            "/config",
            headers={"Authorization": "Bearer test-token-123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "ssh_targets" in data

        # Cleanup
        auth_mod._token = None

    def test_config_dir_from_env_var(self, tmp_path: Path) -> None:
        """create_app() uses CONFIG_DIR env var when config_dir is None."""
        _write_config(tmp_path, _minimal_config())
        with patch.dict(os.environ, {"CONFIG_DIR": str(tmp_path)}):
            app = create_app(config_dir=None)
        assert isinstance(app, FastAPI)
        assert hasattr(app.state, "config_service")

    def test_router_mounted(self, tmp_path: Path) -> None:
        """The routes from routes.py are mounted on the app."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        # /health should respond without auth
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        # /config should exist (returns 401 without token)
        config_resp = client.get("/config")
        assert config_resp.status_code == 401

    def test_ui_spa_served_at_slash_ui(self, tmp_path: Path) -> None:
        """/ui/ serves the SPA index.html without requiring auth."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/ui/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<title>" in resp.text
        assert "tailwindcss" in resp.text

    def test_ui_index_html_direct(self, tmp_path: Path) -> None:
        """/ui/index.html serves the same SPA content."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/ui/index.html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<title>" in resp.text

    def test_api_routes_not_intercepted_by_ui(self, tmp_path: Path) -> None:
        """/config still requires auth — the UI mount does not shadow it."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/config")
        assert resp.status_code == 401
