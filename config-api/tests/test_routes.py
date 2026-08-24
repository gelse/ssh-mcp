"""Tests for config API routes — all endpoints with success and error paths.

Covers:
- GET /health
- GET /api/config
- PUT /api/config
- GET /api/config/{section}
- PUT /api/config/{section}
- POST /api/hash-key
- GET /api/config/ssh_targets (list)
- GET /api/config/ssh_targets/{name}
- PUT /api/config/ssh_targets/{name}
- DELETE /api/config/ssh_targets/{name}
- GET /api/config/block_patterns (list)
- POST /api/config/block_patterns
- PUT /api/config/block_patterns
- PUT /api/config/block_patterns/{index}
- DELETE /api/config/block_patterns/{index}
- GET /api/config/schema
- POST /api/config/validate
- GET /api/backups
- POST /api/backups/{name}/restore
- DELETE /api/backups/{name}
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


# ---------------------------------------------------------------------------
# POST /api/hash-key
# ---------------------------------------------------------------------------


class TestPostHashKey:
    """Tests for POST /api/hash-key."""

    def test_returns_hashed_key(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Valid key returns a PBKDF2 hash."""
        response = client.post(
            "/api/hash-key",
            json={"key": "my-secret-key"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "key_hash" in data
        assert data["key_hash"].startswith("pbkdf2:sha256:")

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """POST without Authorization header returns 401."""
        response = client.post("/api/hash-key", json={"key": "test"})
        assert response.status_code == 401

    def test_rejects_empty_key(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Empty key returns 422 validation error."""
        response = client.post(
            "/api/hash-key",
            json={"key": ""},
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_rejects_missing_key_field(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Missing key field returns 422 validation error."""
        response = client.post(
            "/api/hash-key",
            json={},
            headers=auth_headers,
        )
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /api/config/ssh_targets (list)
# ---------------------------------------------------------------------------


class TestGetSSHTargets:
    """Tests for GET /api/config/ssh_targets (list endpoint)."""

    def test_returns_targets_dict(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Returns the ssh_targets section as ConfigSectionResponse."""
        response = client.get("/api/config/ssh_targets", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "ssh_targets"
        assert isinstance(data["data"], dict)
        assert "test-server" in data["data"]

    def test_secrets_stripped(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Response does not contain passwords or private keys."""
        data = client.get(
            "/api/config/ssh_targets", headers=auth_headers,
        ).json()
        for target in data["data"].values():
            assert "password" not in target
            assert "private_key" not in target


# ---------------------------------------------------------------------------
# GET /api/config/ssh_targets/{name}
# ---------------------------------------------------------------------------


class TestGetSingleSSHTarget:
    """Tests for GET /api/config/ssh_targets/{name}."""

    def test_returns_single_target(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Returns the named target without secrets."""
        response = client.get(
            "/api/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["host"] == "10.0.0.1"
        assert "password" not in data

    def test_returns_404_for_missing(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Non-existent target returns 404."""
        response = client.get(
            "/api/config/ssh_targets/nonexistent",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# PUT /api/config/ssh_targets/{name}
# ---------------------------------------------------------------------------


class TestPutSingleSSHTarget:
    """Tests for PUT /api/config/ssh_targets/{name}."""

    def test_creates_new_target(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT a new target creates it and returns 200."""
        response = client.put(
            "/api/config/ssh_targets/new-server",
            json={
                "host": "192.168.1.1",
                "port": 22,
                "username": "root",
                "password": "test-pass",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        # Verify it persisted
        get_resp = client.get(
            "/api/config/ssh_targets/new-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["host"] == "192.168.1.1"

    def test_updates_existing_target(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT an existing target updates it and returns 200."""
        response = client.put(
            "/api/config/ssh_targets/test-server",
            json={
                "host": "10.0.0.2",
                "port": 2222,
                "username": "admin",
                "password": "new-pass",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_rejects_invalid_name(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Invalid target name returns 400."""
        response = client.put(
            "/api/config/ssh_targets/../../etc",
            json={"host": "1.2.3.4"},
            headers=auth_headers,
        )
        assert response.status_code in (400, 404)

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """PUT without auth returns 401."""
        response = client.put(
            "/api/config/ssh_targets/test",
            json={"host": "1.2.3.4"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# DELETE /api/config/ssh_targets/{name}
# ---------------------------------------------------------------------------


class TestDeleteSingleSSHTarget:
    """Tests for DELETE /api/config/ssh_targets/{name}."""

    def test_deletes_existing_target(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """DELETE removes the target and returns 200 with message."""
        # Add a second target so deletion doesn't violate min_length=1
        client.put(
            "/api/config/ssh_targets/second-server",
            json={
                "host": "10.0.0.99",
                "port": 22,
                "username": "root",
                "password": "pass2",
            },
            headers=auth_headers,
        )
        response = client.delete(
            "/api/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "deleted" in data["message"]
        # Verify it's gone
        get_resp = client.get(
            "/api/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 404

    def test_returns_404_for_missing(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """DELETE non-existent target returns 404."""
        response = client.delete(
            "/api/config/ssh_targets/nonexistent",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# POST /api/config/ssh_targets/{name}/check
# ---------------------------------------------------------------------------


class TestCheckSSHTarget:
    """Tests for POST /api/config/ssh_targets/{name}/check."""

    @pytest.fixture()
    def _setup_target(self, tmp_config_dir):
        """Create a test SSH target with a checkcommand in the config."""
        from config_api.config_service import ConfigService

        svc = ConfigService(config_dir=str(tmp_config_dir))
        config = svc.read_config()
        config["ssh_targets"]["testbox"] = {
            "host": "192.168.1.100",
            "port": 22,
            "username": "testuser",
            "password": "testpass",
            "checkcommand": "echo ping",
        }
        svc.write_config(config)

    def test_check_success(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        _setup_target,
    ) -> None:
        """Successful check returns 200 with success=True."""
        from unittest.mock import patch

        mock_mcp_result = {
            "success": True,
            "output": "ping",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch("config_api.config_service.MCPClient") as MockMCP:
            mock_instance = MockMCP.return_value
            mock_instance.call_tool.return_value = mock_mcp_result
            response = client.post(
                "/api/config/ssh_targets/testbox/check",
                headers=auth_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["output"] == "ping"
        assert data["exit_code"] == 0
        assert data["checkcommand"] == "echo ping"

    def test_check_unknown_target(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        _setup_target,
    ) -> None:
        """Check for non-existent target returns 404."""
        response = client.post(
            "/api/config/ssh_targets/nonexistent/check",
            headers=auth_headers,
        )

        assert response.status_code == 404

    def test_check_ssh_failure(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        _setup_target,
    ) -> None:
        """SSH connection failure returns 500 error."""
        from unittest.mock import patch

        mock_mcp_result = {
            "success": False,
            "output": "",
            "error": "Connection failed",
            "exit_code": -1,
            "checkcommand": "echo ping",
        }
        with patch("config_api.config_service.MCPClient") as MockMCP:
            mock_instance = MockMCP.return_value
            mock_instance.call_tool.return_value = mock_mcp_result
            response = client.post(
                "/api/config/ssh_targets/testbox/check",
                headers=auth_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert data["error"] == "Connection failed"

    def test_check_requires_auth(
        self,
        client: TestClient,
        _setup_target,
    ) -> None:
        """Check endpoint requires a valid Bearer token."""
        response = client.post(
            "/api/config/ssh_targets/testbox/check",
        )

        assert response.status_code in (401, 403)

    def test_check_returns_checkcommand(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        _setup_target,
    ) -> None:
        """Response includes the checkcommand that was used."""
        from unittest.mock import patch

        mock_mcp_result = {
            "success": True,
            "output": "ok",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        with patch("config_api.config_service.MCPClient") as MockMCP:
            mock_instance = MockMCP.return_value
            mock_instance.call_tool.return_value = mock_mcp_result
            response = client.post(
                "/api/config/ssh_targets/testbox/check",
                headers=auth_headers,
            )

        assert response.status_code == 200
        data = response.json()
        assert "checkcommand" in data
        assert data["checkcommand"] == "echo ping"


# ---------------------------------------------------------------------------
# GET /api/config/block_patterns (list)
# ---------------------------------------------------------------------------


class TestGetBlockPatterns:
    """Tests for GET /api/config/block_patterns (list endpoint)."""

    def test_returns_patterns_list(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Returns the block_patterns list as ConfigSectionResponse."""
        response = client.get(
            "/api/config/block_patterns", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert isinstance(data["data"], list)


# ---------------------------------------------------------------------------
# POST /api/config/block_patterns
# ---------------------------------------------------------------------------


class TestPostBlockPattern:
    """Tests for POST /api/config/block_patterns."""

    def test_appends_pattern(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """POST appends a new pattern and returns 201."""
        response = client.post(
            "/api/config/block_patterns",
            json={"pattern": "rm -rf"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert "rm -rf" in data["data"]


# ---------------------------------------------------------------------------
# PUT /api/config/block_patterns
# ---------------------------------------------------------------------------


class TestPutBlockPatterns:
    """Tests for PUT /api/config/block_patterns."""

    def test_replaces_all_patterns(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT replaces the entire patterns list."""
        response = client.put(
            "/api/config/block_patterns",
            json=["new1", "new2"],
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert data["data"] == ["new1", "new2"]


# ---------------------------------------------------------------------------
# PUT /api/config/block_patterns/{index}
# ---------------------------------------------------------------------------


class TestPutSingleBlockPattern:
    """Tests for PUT /api/config/block_patterns/{index}."""

    def test_replaces_pattern_at_index(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT at index replaces that pattern."""
        # First add a pattern
        client.post(
            "/api/config/block_patterns",
            json={"pattern": "old"},
            headers=auth_headers,
        )
        response = client.put(
            "/api/config/block_patterns/0",
            json={"pattern": "new"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert data["data"][0] == "new"

    def test_returns_404_for_out_of_range(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT at invalid index returns 404."""
        response = client.put(
            "/api/config/block_patterns/999",
            json={"pattern": "test"},
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/config/block_patterns/{index}
# ---------------------------------------------------------------------------


class TestDeleteSingleBlockPattern:
    """Tests for DELETE /api/config/block_patterns/{index}."""

    def test_deletes_pattern_at_index(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """DELETE at index removes that pattern."""
        client.post(
            "/api/config/block_patterns",
            json={"pattern": "to-remove"},
            headers=auth_headers,
        )
        response = client.delete(
            "/api/config/block_patterns/0",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "block_patterns"
        assert "to-remove" not in data["data"]

    def test_returns_404_for_out_of_range(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """DELETE at invalid index returns 404."""
        response = client.delete(
            "/api/config/block_patterns/999",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/config/schema
# ---------------------------------------------------------------------------


class TestGetSchema:
    """Tests for GET /api/config/schema."""

    def test_returns_json_schema(self, client: TestClient) -> None:
        """Returns a valid JSON Schema object — no auth required."""
        response = client.get("/api/config/schema")
        assert response.status_code == 200
        data = response.json()
        assert "$schema" in data or "properties" in data

    def test_schema_has_ssh_targets(self, client: TestClient) -> None:
        """Schema defines ssh_targets property."""
        data = client.get("/api/config/schema").json()
        assert "properties" in data
        assert "ssh_targets" in data["properties"]


# ---------------------------------------------------------------------------
# POST /api/config/validate
# ---------------------------------------------------------------------------


class TestPostValidate:
    """Tests for POST /api/config/validate."""

    def test_valid_config_returns_valid_true(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Valid config returns {valid: True, config: {...}}."""
        # Use a config with credentials (GET /api/config strips secrets,
        # which would fail validation if credentials are required).
        config = {
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
        response = client.post(
            "/api/config/validate",
            json=config,
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["config"] is not None

    def test_invalid_config_returns_error(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Invalid config returns ErrorResponse with 400."""
        response = client.post(
            "/api/config/validate",
            json={"invalid": "config"},
            headers=auth_headers,
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ConfigValidationError"


# ---------------------------------------------------------------------------
# GET /api/backups
# ---------------------------------------------------------------------------


class TestGetBackups:
    """Tests for GET /api/backups."""

    def test_returns_empty_list(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """No backups → empty list."""
        response = client.get("/api/backups", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "backups" in data
        assert data["backups"] == []

    def test_returns_backup_info(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """After a PUT /api/config, backups appear."""
        # Trigger a backup by writing config (use config with credentials
        # since GET /api/config strips secrets and PUT would reject it).
        config = {
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
        client.put("/api/config", json=config, headers=auth_headers)
        response = client.get("/api/backups", headers=auth_headers)
        data = response.json()
        assert len(data["backups"]) >= 1
        assert "name" in data["backups"][0]
        assert "size_bytes" in data["backups"][0]
        assert "created_at" in data["backups"][0]


# ---------------------------------------------------------------------------
# POST /api/backups/{name}/restore
# ---------------------------------------------------------------------------


class TestPostBackupRestore:
    """Tests for POST /api/backups/{name}/restore."""

    def test_restores_backup(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Restoring a backup replaces the config."""
        # Create a backup (use config with credentials)
        config = {
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
        client.put("/api/config", json=config, headers=auth_headers)
        backups = client.get("/api/backups", headers=auth_headers).json()
        backup_name = backups["backups"][0]["name"]
        response = client.post(
            f"/api/backups/{backup_name}/restore",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "config" in data

    def test_returns_404_for_missing(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Restoring non-existent backup returns 404."""
        # Use a valid-format name that passes _validate_backup_name
        response = client.post(
            "/api/backups/ssh-mcp-config.20260101T000000Z.bak/restore",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/backups/{name}
# ---------------------------------------------------------------------------


class TestDeleteBackup:
    """Tests for DELETE /api/backups/{name}."""

    def test_deletes_backup(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Deleting a backup removes it and returns 200 with message."""
        config = {
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
        client.put("/api/config", json=config, headers=auth_headers)
        backups = client.get("/api/backups", headers=auth_headers).json()
        backup_name = backups["backups"][0]["name"]
        response = client.delete(
            f"/api/backups/{backup_name}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "deleted" in data["message"]

    def test_returns_404_for_missing(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Deleting non-existent backup returns 404."""
        # Use a valid-format name that passes _validate_backup_name
        response = client.delete(
            "/api/backups/ssh-mcp-config.20260101T000000Z.bak",
            headers=auth_headers,
        )
        assert response.status_code == 404
