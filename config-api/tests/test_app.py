"""Tests for config_api.app — application factory and CLI entry point."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from config_api.app import create_app, main


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
        """The /api/config endpoint requires Bearer token auth."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        response = client.get("/api/config")
        assert response.status_code == 401  # HTTPBearer returns 401 when missing

    def test_api_config_endpoint_with_valid_token(self, tmp_path: Path) -> None:
        """The /api/config endpoint returns config with a valid token."""
        _write_config(tmp_path, _minimal_config())
        # Set token in the auth module
        from config_api import auth as auth_mod

        auth_mod._token = "test-token-123"

        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        response = client.get(
            "/api/config",
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
        # /api/config should exist (returns 401 without token)
        config_resp = client.get("/api/config")
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
        """/api/config still requires auth — the UI mount does not shadow it."""
        _write_config(tmp_path, _minimal_config())
        app = create_app(config_dir=str(tmp_path))
        client = TestClient(app)
        resp = client.get("/api/config")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# main() tests
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for the main() CLI entry point."""

    def test_exits_when_token_not_set(self, tmp_path: Path) -> None:
        """main() exits with code 1 when CONFIG_API_TOKEN is not set."""
        env = {
            "CONFIG_DIR": str(tmp_path),
            "CONFIG_API_HOST": "127.0.0.1",
            "CONFIG_API_PORT": "9999",
        }
        # Ensure CONFIG_API_TOKEN is not set
        env_clean = {k: v for k, v in env.items() if k != "CONFIG_API_TOKEN"}

        with patch.dict(os.environ, env_clean, clear=True):
            with patch("config_api.app.uvicorn") as mock_uvicorn:
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1
                mock_uvicorn.run.assert_not_called()

    @patch("config_api.app.uvicorn")
    def test_starts_uvicorn_with_correct_args(
        self, mock_uvicorn: MagicMock, tmp_path: Path
    ) -> None:
        """main() starts uvicorn with the correct host and port."""
        _write_config(tmp_path, _minimal_config())
        env = {
            "CONFIG_API_TOKEN": "test-token",
            "CONFIG_DIR": str(tmp_path),
            "CONFIG_API_HOST": "127.0.0.1",
            "CONFIG_API_PORT": "9999",
        }
        with patch.dict(os.environ, env, clear=True):
            main()

        mock_uvicorn.run.assert_called_once()
        call_kwargs = mock_uvicorn.run.call_args
        assert call_kwargs.kwargs["host"] == "127.0.0.1"
        assert call_kwargs.kwargs["port"] == 9999
        assert call_kwargs.kwargs["log_level"] == "info"
        assert call_kwargs.kwargs["access_log"] is True

    @patch("config_api.app.uvicorn")
    def test_default_host_and_port(
        self, mock_uvicorn: MagicMock, tmp_path: Path
    ) -> None:
        """main() defaults to 0.0.0.0:8081 when env vars are not set."""
        _write_config(tmp_path, _minimal_config())
        env = {
            "CONFIG_API_TOKEN": "test-token",
            "CONFIG_DIR": str(tmp_path),
        }
        with patch.dict(os.environ, env, clear=True):
            main()

        call_kwargs = mock_uvicorn.run.call_args.kwargs
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 8081

    @patch("config_api.app.uvicorn")
    def test_default_config_dir(
        self, mock_uvicorn: MagicMock, tmp_path: Path
    ) -> None:
        """main() defaults CONFIG_DIR to /config when not set."""
        _write_config(tmp_path, _minimal_config())
        env = {
            "CONFIG_API_TOKEN": "test-token",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("config_api.app.create_app") as mock_create:
                mock_create.return_value = MagicMock()
                main()

        mock_create.assert_called_once_with("/config")

    @patch("config_api.app.uvicorn")
    def test_passes_fastapi_app_to_uvicorn(
        self, mock_uvicorn: MagicMock, tmp_path: Path
    ) -> None:
        """main() passes the FastAPI app as the first argument to uvicorn.run()."""
        _write_config(tmp_path, _minimal_config())
        env = {
            "CONFIG_API_TOKEN": "test-token",
            "CONFIG_DIR": str(tmp_path),
        }
        with patch.dict(os.environ, env, clear=True):
            main()

        call_args = mock_uvicorn.run.call_args
        app = call_args.args[0] if call_args.args else call_args.kwargs.get("app")
        assert isinstance(app, FastAPI)

    @patch("config_api.app.uvicorn")
    def test_load_token_called_before_create_app(
        self, mock_uvicorn: MagicMock, tmp_path: Path
    ) -> None:
        """load_token() is called before create_app() in main()."""
        _write_config(tmp_path, _minimal_config())
        env = {
            "CONFIG_API_TOKEN": "test-token",
            "CONFIG_DIR": str(tmp_path),
        }
        call_order = []
        with patch.dict(os.environ, env, clear=True):
            with patch(
                "config_api.app.load_token",
                side_effect=lambda: call_order.append("load_token"),
            ):
                with patch(
                    "config_api.app.create_app",
                    side_effect=lambda *a, **kw: (
                        call_order.append("create_app"),
                        MagicMock(),
                    )[1],
                ):
                    main()

        assert call_order.index("load_token") < call_order.index("create_app")
