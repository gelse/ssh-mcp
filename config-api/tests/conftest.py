"""Shared test fixtures.

Provides a minimal ``lib`` package shim so that test modules can import
``lib.constants``, ``lib.config``, and ``lib.exceptions`` without pulling
in heavy runtime dependencies (paramiko, FastMCP, etc.) that are not
installed in the config-api virtualenv.

The shim works by pre-registering a stub ``lib`` module in ``sys.modules``
*before* any ``from lib.X import Y`` statement executes.  Python then
skips ``lib/__init__.py`` (which re-exports everything including paramiko)
and goes straight to the requested submodule.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Pre-register a minimal 'lib' package so lib/__init__.py is never executed.
# This MUST happen before any config_api imports, because config_api.config_service
# imports lib.config which triggers lib/__init__.py (which imports paramiko).
# ---------------------------------------------------------------------------

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
_LIB_DIR = str(Path(_PROJECT_ROOT) / "lib")

# Ensure the project root is on sys.path so 'lib' submodules are findable.
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Register a stub 'lib' package with __path__ pointing to the real lib dir.
# This prevents Python from executing lib/__init__.py (which imports paramiko).
if "lib" not in sys.modules:
    _lib_pkg = types.ModuleType("lib")
    _lib_pkg.__path__ = [_LIB_DIR]  # type: ignore[attr-defined]
    _lib_pkg.__package__ = "lib"
    sys.modules["lib"] = _lib_pkg

# Now safe to import config_api modules (they depend on lib.*).
from config_api.app import create_app  # noqa: E402
from config_api.auth import load_token  # noqa: E402
from config_api.config_service import ConfigService  # noqa: E402


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


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


@pytest.fixture()
def tmp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary config directory with a minimal valid config."""
    config_path = tmp_path / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(_minimal_config(), indent=2))
    config_path.chmod(0o600)
    return tmp_path


@pytest.fixture()
def config_service(tmp_config_dir: Path) -> ConfigService:
    """Create a ConfigService pointing at the temp config directory."""
    return ConfigService(config_dir=str(tmp_config_dir))


@pytest.fixture()
def test_token() -> str:
    """Return a test bearer token."""
    return "test-token-12345"


@pytest.fixture()
def app(tmp_config_dir: Path, test_token: str):  # noqa: ANN201
    """Create a FastAPI test app with a known token."""
    from config_api import auth as auth_mod
    from config_api import routes as routes_mod

    auth_mod._token = None
    routes_mod._config_service = None

    with patch.dict(os.environ, {"CONFIG_API_TOKEN": test_token}):
        load_token()
        application = create_app(config_dir=str(tmp_config_dir))
        yield application

    # Cleanup
    auth_mod._token = None
    routes_mod._config_service = None


@pytest.fixture()
def client(app) -> TestClient:  # noqa: ANN001
    """Create a FastAPI test client."""
    return TestClient(app)


@pytest.fixture()
def auth_headers(test_token: str) -> dict[str, str]:
    """Return headers with a valid Bearer token."""
    return {"Authorization": f"Bearer {test_token}"}
