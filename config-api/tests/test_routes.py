"""Tests for config API routes — all 5 endpoints with success and error paths.

Covers:
- GET /health
- GET /api/config
- PUT /api/config
- GET /api/config/{section}
- PUT /api/config/{section}
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Tests for GET /health."""

    def test_returns_ok(self, client: TestClient) -> None:
        """/health returns 200 with status ok."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_no_auth_required(self, client: TestClient) -> None:
        """/health does not require authentication."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_response_model_shape(self, client: TestClient) -> None:
        """/health response matches HealthResponse model."""
        data = client.get("/health").json()
        assert "status" in data
        assert isinstance(data["status"], str)


# ---------------------------------------------------------------------------
# GET /api/config
# ---------------------------------------------------------------------------


class TestGetConfig:
    """Tests for GET /api/config."""

    def test_returns_config_with_valid_token(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Authenticated GET returns the full config."""
        response = client.get("/api/config", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "ssh_targets" in data
        assert "block_patterns" in data
        assert "allowed_commands" in data
        assert "settings" in data

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """GET without Authorization header returns 401."""
        response = client.get("/api/config")
        assert response.status_code == 401

    def test_rejects_invalid_token(self, client: TestClient) -> None:
        """GET with wrong token returns 401."""
        response = client.get(
            "/api/config",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_returns_json_content_type(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Response Content-Type is application/json."""
        response = client.get("/api/config", headers=auth_headers)
        assert response.headers["content-type"] == "application/json"

    def test_config_contains_expected_structure(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Returned config has the expected top-level keys."""
        data = client.get("/api/config", headers=auth_headers).json()
        assert isinstance(data["ssh_targets"], dict)
        assert isinstance(data["block_patterns"], list)
        assert isinstance(data["allowed_commands"], dict)
        assert isinstance(data["settings"], dict)


# ---------------------------------------------------------------------------
# PUT /api/config
# ---------------------------------------------------------------------------


class TestPutConfig:
    """Tests for PUT /api/config."""

    def _valid_config(self) -> dict:
        """Return a valid config dict for PUT requests."""
        return {
            "version": 1,
            "ssh_targets": {
                "new-server": {
                    "host": "10.0.0.1",
                    "username": "admin",
                    "password": "secret123",
                },
            },
            "block_patterns": [],
            "allowed_commands": {
                "default": [{"targets": ["*"], "commands": ["echo"]}],
                "api_keys": [],
                "networks": [],
            },
            "settings": {
                "max_output_length": 50000,
                "command_timeout_max": 120,
            },
        }

    def test_writes_valid_config(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with valid config returns 200 and the written config."""
        response = client.put(
            "/api/config", json=self._valid_config(), headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "new-server" in data["ssh_targets"]

    def test_rejects_invalid_config(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with invalid config returns 400 with error details."""
        response = client.put(
            "/api/config",
            json={"invalid": True},
            headers=auth_headers,
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ConfigValidationError"

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """PUT without auth returns 401."""
        response = client.put("/api/config", json={"ssh_targets": {}})
        assert response.status_code == 401

    def test_rejects_invalid_json(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with malformed JSON body returns 422."""
        response = client.put(
            "/api/config",
            content="not json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "JSONDecodeError"

    def test_rejects_non_object_json(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with JSON array instead of object returns 422."""
        response = client.put(
            "/api/config",
            json=[1, 2, 3],
            headers=auth_headers,
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error_type"] == "ValidationError"

    def test_strips_secrets_before_write(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT strips password/private_key from the written config."""
        config = self._valid_config()
        config["ssh_targets"]["new-server"]["password"] = "secret"
        config["ssh_targets"]["new-server"]["private_key"] = "key-data"
        client.put("/api/config", json=config, headers=auth_headers)

        # Read back and verify secrets are stripped
        response = client.get("/api/config", headers=auth_headers)
        target = response.json()["ssh_targets"]["new-server"]
        assert "password" not in target
        assert "private_key" not in target

    def test_written_config_persists(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Config written via PUT is returned by subsequent GET."""
        config = self._valid_config()
        client.put("/api/config", json=config, headers=auth_headers)
        response = client.get("/api/config", headers=auth_headers)
        data = response.json()
        assert data["ssh_targets"]["new-server"]["host"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# GET /api/config/{section}
# ---------------------------------------------------------------------------


class TestGetConfigSection:
    """Tests for GET /api/config/{section}."""

    def test_returns_ssh_targets(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET ssh_targets returns section data."""
        response = client.get("/api/config/ssh_targets", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "ssh_targets"
        assert isinstance(data["data"], dict)

    def test_returns_settings(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET settings returns section data."""
        response = client.get("/api/config/settings", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "settings"

    def test_returns_block_patterns(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET block_patterns returns section data."""
        response = client.get(
            "/api/config/block_patterns", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert isinstance(data["data"], list)

    def test_returns_allowed_commands(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET allowed_commands returns section data."""
        response = client.get(
            "/api/config/allowed_commands", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "allowed_commands"

    def test_rejects_invalid_section(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET with unknown section name returns 404."""
        response = client.get("/api/config/invalid", headers=auth_headers)
        assert response.status_code == 404
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ValueError"

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """GET section without auth returns 401."""
        response = client.get("/api/config/ssh_targets")
        assert response.status_code == 401

    def test_rejects_invalid_token(
        self, client: TestClient,
    ) -> None:
        """GET section with wrong token returns 401."""
        response = client.get(
            "/api/config/ssh_targets",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/config/{section}
# ---------------------------------------------------------------------------


class TestPutConfigSection:
    """Tests for PUT /api/config/{section}."""

    def test_replaces_ssh_targets(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT ssh_targets replaces the section."""
        new_targets = {
            "replaced-server": {
                "host": "10.0.0.2",
                "username": "root",
                "password": "secret123",
            },
        }
        response = client.put(
            "/api/config/ssh_targets",
            json=new_targets,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "ssh_targets"

    def test_replaces_settings(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT settings replaces the section."""
        new_settings = {
            "log_level": "DEBUG",
            "max_output_length": 50000,
            "command_timeout_max": 120,
        }
        response = client.put(
            "/api/config/settings",
            json=new_settings,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "settings"

    def test_rejects_invalid_section(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with unknown section name returns 404."""
        response = client.put(
            "/api/config/bad_section",
            json={},
            headers=auth_headers,
        )
        assert response.status_code == 404
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ValueError"

    def test_validates_merged_config(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT ssh_targets with empty dict fails validation (ssh_targets required)."""
        response = client.put(
            "/api/config/ssh_targets",
            json={},
            headers=auth_headers,
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ConfigValidationError"

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """PUT section without auth returns 401."""
        response = client.put(
            "/api/config/ssh_targets",
            json={
                "s1": {
                    "host": "1.2.3.4",
                    "username": "u",
                    "password": "secret123",
                },
            },
        )
        assert response.status_code == 401

    def test_rejects_invalid_json(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT section with malformed JSON returns 422."""
        response = client.put(
            "/api/config/settings",
            content="not json",
            headers={**auth_headers, "Content-Type": "application/json"},
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "JSONDecodeError"

    def test_section_write_persists(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Section written via PUT is returned by subsequent GET."""
        new_targets = {
            "persist-server": {
                "host": "10.0.0.3",
                "username": "admin",
                "password": "secret123",
            },
        }
        client.put(
            "/api/config/ssh_targets",
            json=new_targets,
            headers=auth_headers,
        )
        response = client.get("/api/config/ssh_targets", headers=auth_headers)
        data = response.json()
        assert "persist-server" in data["data"]
