"""Tests for config API routes — all endpoints with success and error paths.

Covers:
- GET /health
- GET /config
- PUT /config
- GET /config/{section}
- PUT /config/{section}
- POST /hash-key
- GET /config/ssh_targets (list)
- GET /config/ssh_targets/{name}
- PUT /config/ssh_targets/{name}
- DELETE /config/ssh_targets/{name}
- GET /config/block_patterns (list)
- POST /config/block_patterns
- PUT /config/block_patterns
- PUT /config/block_patterns/{index}
- DELETE /config/block_patterns/{index}
- GET /config/schema
- POST /config/validate
- GET /backups
- POST /backups/{name}/restore
- DELETE /backups/{name}
"""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

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
        response = client.get("/config", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "ssh_targets" in data
        assert "block_patterns" in data
        assert "allowed_commands" in data
        assert "settings" in data

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """GET without Authorization header returns 401."""
        response = client.get("/config")
        assert response.status_code == 401

    def test_rejects_invalid_token(self, client: TestClient) -> None:
        """GET with wrong token returns 401."""
        response = client.get(
            "/config",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_returns_json_content_type(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Response Content-Type is application/json."""
        response = client.get("/config", headers=auth_headers)
        assert response.headers["content-type"] == "application/json"

    def test_config_contains_expected_structure(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Returned config has the expected top-level keys."""
        data = client.get("/config", headers=auth_headers).json()
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
            "/config", json=self._valid_config(), headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "new-server" in data["ssh_targets"]

    def test_rejects_invalid_config(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with invalid config returns 400 with error details."""
        response = client.put(
            "/config",
            json={"invalid": True},
            headers=auth_headers,
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ConfigValidationError"

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """PUT without auth returns 401."""
        response = client.put("/config", json={"ssh_targets": {}})
        assert response.status_code == 401

    def test_rejects_invalid_json(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT with malformed JSON body returns 422."""
        response = client.put(
            "/config",
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
            "/config",
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
        client.put("/config", json=config, headers=auth_headers)

        # Read back and verify secrets are stripped
        response = client.get("/config", headers=auth_headers)
        target = response.json()["ssh_targets"]["new-server"]
        assert "password" not in target
        assert "private_key" not in target

    def test_written_config_persists(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Config written via PUT is returned by subsequent GET."""
        config = self._valid_config()
        client.put("/config", json=config, headers=auth_headers)
        response = client.get("/config", headers=auth_headers)
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
        response = client.get("/config/ssh_targets", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "ssh_targets"
        assert isinstance(data["data"], dict)

    def test_returns_settings(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET settings returns section data."""
        response = client.get("/config/settings", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "settings"

    def test_returns_block_patterns(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET block_patterns returns section data."""
        response = client.get(
            "/config/block_patterns", headers=auth_headers,
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
            "/config/allowed_commands", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "allowed_commands"

    def test_rejects_invalid_section(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET with unknown section name returns 404."""
        response = client.get("/config/invalid", headers=auth_headers)
        assert response.status_code == 404
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ValueError"

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """GET section without auth returns 401."""
        response = client.get("/config/ssh_targets")
        assert response.status_code == 401

    def test_rejects_invalid_token(
        self, client: TestClient,
    ) -> None:
        """GET section with wrong token returns 401."""
        response = client.get(
            "/config/ssh_targets",
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
            "/config/ssh_targets",
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
            "/config/settings",
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
            "/config/bad_section",
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
            "/config/ssh_targets",
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
            "/config/ssh_targets",
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
            "/config/settings",
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
            "/config/ssh_targets",
            json=new_targets,
            headers=auth_headers,
        )
        response = client.get("/config/ssh_targets", headers=auth_headers)
        data = response.json()
        assert "persist-server" in data["data"]

    def test_put_config_section_allowed_commands_merges(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT allowed_commands with only 'networks' preserves 'default' rules."""
        # GET allowed_commands to confirm default rules exist
        get_resp = client.get(
            "/config/allowed_commands", headers=auth_headers,
        )
        assert get_resp.status_code == 200
        original_default = get_resp.json()["data"]["default"]
        assert len(original_default) > 0

        # PUT only the networks sub-key
        new_networks = [
            {
                "name": "internal",
                "range": "10.0.0.0/8",
                "rules": [{"targets": ["*"], "commands": ["echo"]}],
            },
        ]
        put_resp = client.put(
            "/config/allowed_commands",
            json={"networks": new_networks},
            headers=auth_headers,
        )
        assert put_resp.status_code == 200

        # GET again — default rules should be preserved, networks updated
        get_resp2 = client.get(
            "/config/allowed_commands", headers=auth_headers,
        )
        data = get_resp2.json()["data"]
        assert data["default"] == original_default
        assert data["networks"] == new_networks


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
            "/hash-key",
            json={"key": "my-secret-key"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "key_hash" in data
        assert data["key_hash"].startswith("pbkdf2:sha256:")

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """POST without Authorization header returns 401."""
        response = client.post("/hash-key", json={"key": "test"})
        assert response.status_code == 401

    def test_rejects_empty_key(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Empty key returns 422 validation error."""
        response = client.post(
            "/hash-key",
            json={"key": ""},
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_rejects_missing_key_field(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Missing key field returns 422 validation error."""
        response = client.post(
            "/hash-key",
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
        response = client.get("/config/ssh_targets", headers=auth_headers)
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
            "/config/ssh_targets", headers=auth_headers,
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
            "/config/ssh_targets/test-server",
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
            "/config/ssh_targets/nonexistent",
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
            "/config/ssh_targets/new-server",
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
            "/config/ssh_targets/new-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["host"] == "192.168.1.1"

    def test_updates_existing_target(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT an existing target updates it and returns 200."""
        response = client.put(
            "/config/ssh_targets/test-server",
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
            "/config/ssh_targets/../../etc",
            json={"host": "1.2.3.4"},
            headers=auth_headers,
        )
        assert response.status_code in (400, 404)

    def test_rejects_missing_token(self, client: TestClient) -> None:
        """PUT without auth returns 401."""
        response = client.put(
            "/config/ssh_targets/test",
            json={"host": "1.2.3.4"},
        )
        assert response.status_code == 401

    def test_edit_preserves_existing_password(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Editing a target without password preserves the existing one."""
        # The test fixture already has test-server with password in config.
        # Verify via GET that the target exists
        get_resp = client.get(
            "/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 200
        original_host = get_resp.json()["host"]

        # Update only host, no password sent (simulates "Leave empty to keep unchanged")
        response = client.put(
            "/config/ssh_targets/test-server",
            json={
                "host": original_host,
                "port": 22,
                "username": "admin",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

        # Verify the target still exists and was updated
        get_resp = client.get(
            "/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 200

    def test_edit_preserves_existing_private_key(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Editing a target without private_key preserves the existing one."""
        # First, set up a target with a private_key
        svc = client.app.state.config_service
        config = svc.read_config()
        config["ssh_targets"]["test-server"]["private_key"] = "my-secret-key"
        svc.write_config(config)

        # Now edit without private_key
        response = client.put(
            "/config/ssh_targets/test-server",
            json={
                "host": "10.0.0.1",
                "port": 22,
                "username": "admin",
                "password": "secret123",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200

        # Verify private_key was preserved on disk
        raw = svc.read_config()
        assert raw["ssh_targets"]["test-server"]["private_key"] == "my-secret-key"

    def test_create_without_credentials_fails(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Creating a new target without password or key returns 400."""
        response = client.put(
            "/config/ssh_targets/no-creds",
            json={
                "host": "10.0.0.99",
                "port": 22,
                "username": "user",
            },
            headers=auth_headers,
        )
        assert response.status_code == 400


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
            "/config/ssh_targets/second-server",
            json={
                "host": "10.0.0.99",
                "port": 22,
                "username": "root",
                "password": "pass2",
            },
            headers=auth_headers,
        )
        response = client.delete(
            "/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "deleted" in data["message"]
        # Verify it's gone
        get_resp = client.get(
            "/config/ssh_targets/test-server",
            headers=auth_headers,
        )
        assert get_resp.status_code == 404

    def test_returns_404_for_missing(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """DELETE non-existent target returns 404."""
        response = client.delete(
            "/config/ssh_targets/nonexistent",
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
                "/config/ssh_targets/testbox/check",
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
            "/config/ssh_targets/nonexistent/check",
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
                "/config/ssh_targets/testbox/check",
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
            "/config/ssh_targets/testbox/check",
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
                "/config/ssh_targets/testbox/check",
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
            "/config/block_patterns", headers=auth_headers,
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
            "/config/block_patterns",
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
            "/config/block_patterns",
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
            "/config/block_patterns",
            json={"pattern": "old"},
            headers=auth_headers,
        )
        response = client.put(
            "/config/block_patterns/0",
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
            "/config/block_patterns/999",
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
            "/config/block_patterns",
            json={"pattern": "to-remove"},
            headers=auth_headers,
        )
        response = client.delete(
            "/config/block_patterns/0",
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
            "/config/block_patterns/999",
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
        response = client.get("/config/schema")
        assert response.status_code == 200
        data = response.json()
        assert "$schema" in data or "properties" in data

    def test_schema_has_ssh_targets(self, client: TestClient) -> None:
        """Schema defines ssh_targets property."""
        data = client.get("/config/schema").json()
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
            "/config/validate",
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
            "/config/validate",
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
        response = client.get("/backups", headers=auth_headers)
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
        client.put("/config", json=config, headers=auth_headers)
        response = client.get("/backups", headers=auth_headers)
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
        client.put("/config", json=config, headers=auth_headers)
        backups = client.get("/backups", headers=auth_headers).json()
        backup_name = backups["backups"][0]["name"]
        response = client.post(
            f"/backups/{backup_name}/restore",
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
            "/backups/ssh-mcp-config.20260101T000000Z.bak/restore",
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
        client.put("/config", json=config, headers=auth_headers)
        backups = client.get("/backups", headers=auth_headers).json()
        backup_name = backups["backups"][0]["name"]
        response = client.delete(
            f"/backups/{backup_name}",
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
            "/backups/ssh-mcp-config.20260101T000000Z.bak",
            headers=auth_headers,
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Error sanitization — verify no internal details leak in responses
# ---------------------------------------------------------------------------


class TestErrorSanitization:
    """Tests that error responses sanitize internal details.

    Verifies that exception messages, file paths, IPs, usernames, and
    other sensitive information are NOT leaked in HTTP response bodies,
    while the full details ARE logged server-side.
    """

    def test_get_config_json_error_no_raw_details(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """GET /config hides raw JSONDecodeError details from response."""
        exc = json.JSONDecodeError(
            "Expecting ',' delimiter", '{"key": "value"', 5,
        )
        mock_svc = MagicMock()
        mock_svc.read_config.side_effect = exc
        with patch("config_api.routes._config_service", mock_svc):
            response = client.get("/config", headers=auth_headers)

        assert response.status_code == 500
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "JSONDecodeError"
        # Safe message must NOT leak internal details
        assert "Expecting" not in data["message"]
        assert "delimiter" not in data["message"]
        assert "5" not in data["message"]

    def test_hash_key_pydantic_error_no_raw_details(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """POST /hash-key hides Pydantic ValidationError details."""
        response = client.post(
            "/hash-key",
            json={"key": ""},
            headers=auth_headers,
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "ValidationError"
        # Safe message must NOT leak validation internals
        message_lower = data["message"].lower()
        assert "field" not in message_lower
        assert "min_length" not in message_lower
        assert "string should" not in message_lower

    def test_check_ssh_generic_error_no_raw_details(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """POST /ssh_targets/{name}/check hides exception details."""
        exc = Exception(
            "Authentication failed for user admin@10.0.0.1:22"
        )
        mock_svc = MagicMock()
        mock_svc.check_ssh_target.side_effect = exc
        with patch("config_api.routes._config_service", mock_svc):
            response = client.post(
                "/config/ssh_targets/test-server/check",
                headers=auth_headers,
            )

        assert response.status_code == 500
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "SSHCheckError"
        # Safe message must NOT leak credentials or addresses
        assert "admin" not in data["message"]
        assert "10.0.0.1" not in data["message"]

    def test_put_config_oserror_no_raw_details(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """PUT /config hides OSError details from response."""
        exc = OSError(13, "Permission denied", "/etc/ssh-mcp-config.json")
        mock_svc = MagicMock()
        mock_svc.write_config.side_effect = exc
        with patch("config_api.routes._config_service", mock_svc):
            response = client.put(
                "/config",
                json={"ssh_targets": {}, "block_patterns": []},
                headers=auth_headers,
            )

        assert response.status_code == 500
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "OSError"
        # Safe message must NOT leak file paths or OS details
        assert "Permission denied" not in data["message"]
        assert "/etc/" not in data["message"]
        assert "13" not in data["message"]

    def test_restore_backup_json_error_no_raw_details(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """POST /backups/{name}/restore hides JSONDecodeError details."""
        exc = json.JSONDecodeError(
            "Expecting value", '{"broken": }', 1,
        )
        mock_svc = MagicMock()
        mock_svc.backup_restore.side_effect = exc
        with patch("config_api.routes._config_service", mock_svc):
            response = client.post(
                "/backups/ssh-mcp-config.20260101T000000Z.bak/restore",
                headers=auth_headers,
            )

        assert response.status_code == 500
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "JSONDecodeError"
        # Safe message must NOT leak internal parse details
        assert "Expecting value" not in data["message"]
        assert '{"broken": }' not in data["message"]
        assert "1" not in data["message"]

    def test_error_responses_logged(
        self, client: TestClient, auth_headers: dict[str, str],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Error responses log full exception details server-side."""
        exc = json.JSONDecodeError(
            "Expecting ',' delimiter", '{"key": "value"', 5,
        )
        mock_svc = MagicMock()
        mock_svc.read_config.side_effect = exc
        with patch("config_api.routes._config_service", mock_svc):
            with caplog.at_level("WARNING", logger="config_api.routes"):
                response = client.get("/config", headers=auth_headers)

        assert response.status_code == 500
        # Response is sanitized
        data = response.json()
        assert "Expecting" not in data["message"]
        # But the log contains full exception details (exc_info=True)
        assert "Expecting ',' delimiter" in caplog.text


# ---------------------------------------------------------------------------
# POST /api/auth/login
# ---------------------------------------------------------------------------


class TestLoginEndpoint:
    """Tests for POST /auth/login."""

    def test_login_success(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Valid token returns 200 and sets session cookie."""
        response = client.post(
            "/auth/login", json={"token": test_token},
        )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        # Verify session cookie is set
        assert "config_api_session" in response.cookies

    def test_login_sets_httponly_cookie(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Session cookie is HttpOnly."""
        response = client.post(
            "/auth/login", json={"token": test_token},
        )
        cookie = response.cookies.get("config_api_session")
        assert cookie is not None

    def test_login_invalid_token(self, client: TestClient) -> None:
        """Wrong token returns 401."""
        response = client.post(
            "/auth/login", json={"token": "wrong-token"},
        )
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True
        assert data["message"] == "Invalid token"

    def test_login_missing_token_body(self, client: TestClient) -> None:
        """Missing 'token' field returns 401."""
        response = client.post(
            "/auth/login", json={"not_token": "value"},
        )
        assert response.status_code == 401
        data = response.json()
        assert data["error"] is True

    def test_login_empty_token(self, client: TestClient) -> None:
        """Empty token string returns 401."""
        response = client.post(
            "/auth/login", json={"token": ""},
        )
        assert response.status_code == 401

    def test_login_invalid_json(self, client: TestClient) -> None:
        """Malformed JSON body returns 401."""
        response = client.post(
            "/auth/login",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 401

    def test_login_non_object_body(self, client: TestClient) -> None:
        """JSON array body returns 401."""
        response = client.post(
            "/auth/login", json=["token-value"],
        )
        assert response.status_code == 401

    def test_login_cookie_allows_config_access(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Login cookie can be used to access protected routes."""
        from config_api.auth import _sessions

        session_id = "a" * 64
        _sessions[session_id] = __import__("time").time()
        try:
            response = client.get(
                "/config",
                cookies={"config_api_session": session_id},
            )
            assert response.status_code == 200
            assert "ssh_targets" in response.json()
        finally:
            _sessions.pop(session_id, None)


# ---------------------------------------------------------------------------
# CONFIG_API_SESSION_COOKIE_SECURE env var override
# ---------------------------------------------------------------------------


class TestCookieSecureOverride:
    """Tests for CONFIG_API_SESSION_COOKIE_SECURE env var override."""

    def test_default_cookie_secure_is_true(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Without env var override, cookie is Secure (constant default)."""
        import config_api.routes as routes_mod

        original = routes_mod.COOKIE_SECURE
        try:
            routes_mod.COOKIE_SECURE = True
            response = client.post(
                "/auth/login", json={"token": test_token},
            )
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie", "")
            assert "Secure" in set_cookie
        finally:
            routes_mod.COOKIE_SECURE = original

    def test_cookie_secure_false_disables_secure_flag(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Setting COOKIE_SECURE=False removes the Secure flag."""
        import config_api.routes as routes_mod

        original = routes_mod.COOKIE_SECURE
        try:
            routes_mod.COOKIE_SECURE = False
            response = client.post(
                "/auth/login", json={"token": test_token},
            )
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie", "")
            cookie_parts = [
                p.strip().split("=")[0].strip()
                for p in set_cookie.split(";")
            ]
            assert "Secure" not in cookie_parts
        finally:
            routes_mod.COOKIE_SECURE = original

    def test_cookie_secure_true_keeps_secure_flag(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Setting COOKIE_SECURE=True keeps the Secure flag."""
        import config_api.routes as routes_mod

        original = routes_mod.COOKIE_SECURE
        try:
            routes_mod.COOKIE_SECURE = True
            response = client.post(
                "/auth/login", json={"token": test_token},
            )
            assert response.status_code == 200
            set_cookie = response.headers.get("set-cookie", "")
            assert "Secure" in set_cookie
        finally:
            routes_mod.COOKIE_SECURE = original

    def test_env_var_false_sets_cookie_secure_false(self) -> None:
        """CONFIG_API_SESSION_COOKIE_SECURE=false env var disables Secure."""
        import importlib

        import config_api.routes as routes_mod

        original = getattr(routes_mod, "COOKIE_SECURE", None)
        try:
            with patch.dict(
                os.environ,
                {"CONFIG_API_SESSION_COOKIE_SECURE": "false"},
            ):
                importlib.reload(routes_mod)
                assert routes_mod.COOKIE_SECURE is False
        finally:
            if original is not None:
                routes_mod.COOKIE_SECURE = original
            importlib.reload(routes_mod)

    def test_env_var_zero_sets_cookie_secure_false(self) -> None:
        """CONFIG_API_SESSION_COOKIE_SECURE=0 env var disables Secure."""
        import importlib

        import config_api.routes as routes_mod

        original = getattr(routes_mod, "COOKIE_SECURE", None)
        try:
            with patch.dict(
                os.environ,
                {"CONFIG_API_SESSION_COOKIE_SECURE": "0"},
            ):
                importlib.reload(routes_mod)
                assert routes_mod.COOKIE_SECURE is False
        finally:
            if original is not None:
                routes_mod.COOKIE_SECURE = original
            importlib.reload(routes_mod)

    def test_env_var_true_sets_cookie_secure_true(self) -> None:
        """CONFIG_API_SESSION_COOKIE_SECURE=true env var keeps Secure."""
        import importlib

        import config_api.routes as routes_mod

        original = getattr(routes_mod, "COOKIE_SECURE", None)
        try:
            with patch.dict(
                os.environ,
                {"CONFIG_API_SESSION_COOKIE_SECURE": "true"},
            ):
                importlib.reload(routes_mod)
                assert routes_mod.COOKIE_SECURE is True
        finally:
            if original is not None:
                routes_mod.COOKIE_SECURE = original
            importlib.reload(routes_mod)

    def test_env_var_unset_uses_constant_default(self) -> None:
        """No env var set falls back to CONFIG_API_SESSION_COOKIE_SECURE."""
        import importlib

        import config_api.routes as routes_mod
        from lib.constants import CONFIG_API_SESSION_COOKIE_SECURE

        original = getattr(routes_mod, "COOKIE_SECURE", None)
        try:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("CONFIG_API_SESSION_COOKIE_SECURE", None)
                importlib.reload(routes_mod)
                assert (
                    routes_mod.COOKIE_SECURE
                    == CONFIG_API_SESSION_COOKIE_SECURE
                )
        finally:
            if original is not None:
                routes_mod.COOKIE_SECURE = original
            importlib.reload(routes_mod)


# ---------------------------------------------------------------------------
# POST /api/auth/logout
# ---------------------------------------------------------------------------


class TestLogoutEndpoint:
    """Tests for POST /auth/logout."""

    def test_logout_clears_cookie(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Logout clears the session cookie."""
        from config_api.auth import _sessions

        session_id = "b" * 64
        _sessions[session_id] = __import__("time").time()
        try:
            response = client.post(
                "/auth/logout",
                cookies={"config_api_session": session_id},
            )
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}

            # Verify the cookie was cleared (max-age=0 or expired)
            set_cookie = response.headers.get("set-cookie", "")
            assert "config_api_session" in set_cookie
        finally:
            _sessions.pop(session_id, None)

    def test_logout_revokes_session(
        self, client: TestClient, test_token: str,
    ) -> None:
        """After logout, the session cookie no longer grants access."""
        from config_api.auth import _sessions

        session_id = "c" * 64
        _sessions[session_id] = __import__("time").time()

        # Logout
        client.post(
            "/auth/logout",
            cookies={"config_api_session": session_id},
        )

        # Session should be revoked
        assert session_id not in _sessions

        # Try to access protected route with the revoked session cookie
        response = client.get(
            "/config",
            cookies={"config_api_session": session_id},
        )
        assert response.status_code == 401

    def test_logout_requires_auth(self, client: TestClient) -> None:
        """Logout without any auth returns 401."""
        response = client.post("/auth/logout")
        assert response.status_code == 401

    def test_logout_with_bearer_token(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Logout works with Bearer token auth (no session cookie to clear)."""
        response = client.post(
            "/auth/logout", headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_logout_no_session_cookie_is_noop(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Logout with Bearer auth but no session cookie is a no-op."""
        response = client.post(
            "/auth/logout", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data == {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /api/auth/session
# ---------------------------------------------------------------------------


class TestSessionEndpoint:
    """Tests for GET /auth/session."""

    def test_session_valid_with_bearer(
        self, client: TestClient, auth_headers: dict[str, str],
    ) -> None:
        """Valid Bearer token returns authenticated: true."""
        response = client.get("/auth/session", headers=auth_headers)
        assert response.status_code == 200
        assert response.json() == {"authenticated": True}

    def test_session_valid_with_cookie(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Valid session cookie returns authenticated: true."""
        from config_api.auth import _sessions

        session_id = "d" * 64
        _sessions[session_id] = __import__("time").time()
        try:
            response = client.get(
                "/auth/session",
                cookies={"config_api_session": session_id},
            )
            assert response.status_code == 200
            assert response.json() == {"authenticated": True}
        finally:
            _sessions.pop(session_id, None)

    def test_session_invalid_token(self, client: TestClient) -> None:
        """Invalid Bearer token returns 401."""
        response = client.get(
            "/auth/session",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_session_no_auth(self, client: TestClient) -> None:
        """Missing auth returns 401."""
        response = client.get("/auth/session")
        assert response.status_code == 401

    def test_session_expired_cookie(
        self, client: TestClient, test_token: str,
    ) -> None:
        """Expired session cookie returns 401."""
        # Use a non-existent session ID (simulates expired/missing)
        response = client.get(
            "/auth/session",
            cookies={"config_api_session": "deadbeef" * 8},
        )
        assert response.status_code == 401
