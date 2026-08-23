"""Integration tests for the config API using real Docker containers.

These tests require:
- Docker daemon running
- The config API image built: make config-integrationtest (or manually:
  docker build -f Dockerfile.config-api -t mcp-ssh-config-api:test .)
- The docker Python SDK (in requirements-dev.txt)

Skip gracefully if Docker is unavailable.
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

try:
    import docker

    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

pytestmark = pytest.mark.skipif(
    not HAS_DOCKER or not HAS_REQUESTS,
    reason="Docker SDK and requests required for integration tests",
)

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

TEST_TOKEN = "integration-test-token-67890"
TEST_NETWORK = "mcp-ssh-config-api-test-net"
CONFIG_API_IMAGE = "mcp-ssh-config-api:test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_valid_config(**overrides):
    """Build a fully valid config dict, optionally overriding sections.

    Uses ``build_default_config()`` as the base so every required field
    (settings, allowed_commands keys, ssh_targets auth, etc.) is present.
    Pass keyword arguments to replace top-level sections entirely, e.g.
    ``_make_valid_config(ssh_targets={...})``.
    """
    from lib.config import build_default_config

    config = build_default_config()
    for key, value in overrides.items():
        config[key] = value
    return config


def _wait_for_health(container, timeout: int = 60):
    """Wait for the container to be ready (health check or running).

    Checks two readiness signals:
    1. Docker HEALTHCHECK reports "healthy"
    2. Container is running and the /health endpoint responds

    Raises RuntimeError with container logs on failure.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            container.reload()
        except docker.errors.NotFound:
            raise RuntimeError(
                "Container was removed before becoming healthy"
            )
        state = container.attrs.get("State", {})
        # Detect early exit (crash)
        if state.get("Status") == "exited":
            logs = container.logs(tail=50).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Container exited prematurely (exit code "
                f"{state.get('ExitCode')}):\n{logs}"
            )
        # Check Docker HEALTHCHECK status
        health = state.get("Health", {}).get("Status")
        if health == "healthy":
            return
        if health == "unhealthy":
            logs = container.logs(tail=50).decode(
                "utf-8", errors="replace"
            )
            raise RuntimeError(
                f"Container became unhealthy:\n{logs}"
            )
        # If running, try hitting the health endpoint directly
        # (don't wait for Docker's slow HEALTHCHECK interval)
        if state.get("Status") == "running":
            try:
                ports = container.attrs.get("NetworkSettings", {}).get(
                    "Ports", {}
                )
                host_port = ports.get("8081/tcp", [None])[0]
                if host_port:
                    import urllib.request

                    url = f"http://localhost:{host_port['HostPort']}/health"
                    resp = urllib.request.urlopen(url, timeout=2)
                    if resp.status == 200:
                        return
            except Exception:
                pass  # Server not ready yet, keep polling
        time.sleep(1)
    # Timeout — dump logs for debugging
    try:
        logs = container.logs(tail=50).decode("utf-8", errors="replace")
    except Exception:
        logs = "(could not retrieve logs)"
    raise RuntimeError(
        f"Container did not become healthy within {timeout}s:\n{logs}"
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def docker_client():
    """Create a Docker client."""
    return docker.from_env()


@pytest.fixture(scope="module")
def test_network(docker_client):
    """Create a dedicated Docker network for tests."""
    # Remove stale network if it exists
    try:
        old = docker_client.networks.get(TEST_NETWORK)
        old.remove()
    except docker.errors.NotFound:
        pass

    network = docker_client.networks.create(TEST_NETWORK, driver="bridge")
    yield network
    try:
        network.remove()
    except Exception:
        pass


@pytest.fixture(scope="module")
def config_dir(tmp_path_factory):
    """Create a temporary config directory with a valid config.

    Uses build_default_config() to get a valid config, then overrides
    ssh_targets with a test-specific target. The directory is chmod 0o777
    so the container's UID 1000 can write backup files and new configs.
    """
    from lib.config import build_default_config

    tmp_dir = tmp_path_factory.mktemp("config")
    config = build_default_config()
    config["ssh_targets"] = {
        "test-server": {
            "host": "192.168.1.100",
            "port": 22,
            "username": "testuser",
            "private_key": "/dev/null",
        }
    }
    config["allowed_commands"]["default"] = [
        {"targets": ["test-server"], "commands": ["ls", "uptime"]}
    ]
    config_path = tmp_dir / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(config, indent=2))
    config_path.chmod(0o600)
    # The container runs as UID 1000; make the directory world-writable
    # so the container can create backup files and write new configs.
    tmp_dir.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
    return tmp_dir


@pytest.fixture(scope="module")
def config_api_container(docker_client, test_network, config_dir):
    """Start the config API container."""
    container_name = "test-config-api"
    # Remove stale container if it exists
    try:
        old = docker_client.containers.get(container_name)
        old.stop(timeout=2)
        old.remove(force=True)
    except docker.errors.NotFound:
        pass

    container = docker_client.containers.run(
        CONFIG_API_IMAGE,
        name=container_name,
        environment={
            "CONFIG_API_TOKEN": TEST_TOKEN,
            "CONFIG_DIR": "/config",
            "CONFIG_API_PORT": "8081",
            "CONFIG_API_HOST": "0.0.0.0",
        },
        volumes={
            str(config_dir): {"bind": "/config", "mode": "rw"},
        },
        ports={"8081/tcp": None},  # Random host port
        network=TEST_NETWORK,
        detach=True,
        # Do NOT use remove=True — the container would be auto-removed
        # on crash before _wait_for_health can read its logs.
    )

    try:
        # Wait for the container to be healthy
        _wait_for_health(container)

        # Get the assigned host port
        container.reload()
        port = container.attrs["NetworkSettings"]["Ports"]["8081/tcp"][0][
            "HostPort"
        ]

        yield container, int(port)
    finally:
        try:
            container.stop(timeout=5)
        except Exception:
            pass
        try:
            container.remove(force=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Integration test: GET /health."""

    def test_health_returns_ok(self, config_api_container):
        _, port = config_api_container
        response = requests.get(
            f"http://localhost:{port}/health", timeout=5
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestGetConfig:
    """Integration test: GET /api/config."""

    def test_get_config_returns_full_config(self, config_api_container):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        response = requests.get(
            f"http://localhost:{port}/api/config",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200
        data = response.json()
        assert "ssh_targets" in data
        assert "test-server" in data["ssh_targets"]

    def test_get_config_rejects_bad_token(self, config_api_container):
        _, port = config_api_container
        headers = {"Authorization": "Bearer wrong-token"}
        response = requests.get(
            f"http://localhost:{port}/api/config",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 401

    def test_get_config_rejects_no_token(self, config_api_container):
        _, port = config_api_container
        response = requests.get(
            f"http://localhost:{port}/api/config", timeout=5
        )
        assert response.status_code in (401, 403)


class TestPutConfig:
    """Integration test: PUT /api/config."""

    def test_put_config_writes_and_verifies(
        self, config_api_container, config_dir
    ):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        new_config = _make_valid_config(
            ssh_targets={
                "integration-server": {
                    "host": "10.0.0.1",
                    "port": 2222,
                    "username": "admin",
                    "private_key": "/dev/null",
                }
            },
            block_patterns=["rm -rf"],
            allowed_commands={
                "default": [
                    {
                        "targets": ["integration-server"],
                        "commands": ["ls"],
                    }
                ],
                "api_keys": [],
                "networks": [],
            },
            settings={"log_level": "DEBUG", "max_output_length": 50000, "command_timeout_max": 120},
        )

        response = requests.put(
            f"http://localhost:{port}/api/config",
            json=new_config,
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200
        data = response.json()
        assert "integration-server" in data["ssh_targets"]

        # Verify on disk
        config_path = config_dir / "ssh-mcp-config.json"
        on_disk = json.loads(config_path.read_text())
        assert "integration-server" in on_disk["ssh_targets"]
        assert on_disk["settings"]["log_level"] == "DEBUG"

    def test_put_config_creates_backup(
        self, config_api_container, config_dir
    ):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        config = _make_valid_config(
            ssh_targets={
                "s1": {
                    "host": "1.2.3.4",
                    "username": "u",
                    "private_key": "/dev/null",
                }
            },
        )

        requests.put(
            f"http://localhost:{port}/api/config",
            json=config,
            headers=headers,
            timeout=5,
        )

        backups = list(config_dir.glob("*.bak"))
        assert len(backups) >= 1

    def test_put_config_rejects_invalid(self, config_api_container):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        response = requests.put(
            f"http://localhost:{port}/api/config",
            json={"invalid": True},
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error_type"] == "ConfigValidationError"

    def test_put_config_strips_secrets(
        self, config_api_container, config_dir
    ):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        config = _make_valid_config(
            ssh_targets={
                "s1": {
                    "host": "1.2.3.4",
                    "username": "u",
                    "password": "should-not-appear",
                }
            },
        )

        requests.put(
            f"http://localhost:{port}/api/config",
            json=config,
            headers=headers,
            timeout=5,
        )

        # Secrets must be present on disk (needed for SSH connections)
        config_path = config_dir / "ssh-mcp-config.json"
        on_disk = json.loads(config_path.read_text())
        assert "password" in on_disk["ssh_targets"]["s1"]

        # API response must strip secrets for consumers
        resp = requests.get(
            f"http://localhost:{port}/api/config/ssh_targets/s1",
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200
        assert "password" not in resp.json()


class TestGetConfigSection:
    """Integration test: GET /api/config/{section}."""

    def test_get_ssh_targets(self, config_api_container):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        response = requests.get(
            f"http://localhost:{port}/api/config/ssh_targets",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["section"] == "ssh_targets"

    def test_get_invalid_section(self, config_api_container):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        response = requests.get(
            f"http://localhost:{port}/api/config/nonexistent",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 404


class TestPutConfigSection:
    """Integration test: PUT /api/config/{section}."""

    def test_put_settings(self, config_api_container, config_dir):
        """Test updating settings via PUT /api/config/{section}."""
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        # 1. GET current settings via the section endpoint
        response = requests.get(
            f"http://localhost:{port}/api/config/settings",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200
        settings = response.json()["data"]

        # 2. Modify settings
        settings["log_level"] = "WARNING"
        settings["command_timeout_max"] = 60

        # 3. PUT the modified settings via the section endpoint
        response = requests.put(
            f"http://localhost:{port}/api/config/settings",
            json=settings,
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200

        # 4. Verify settings were updated via GET
        response = requests.get(
            f"http://localhost:{port}/api/config/settings",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["log_level"] == "WARNING"
        assert data["data"]["command_timeout_max"] == 60


class TestFilePermissions:
    """Integration test: verify file permissions on disk."""

    def test_config_file_is_600(
        self, config_api_container, config_dir
    ):
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}

        config = _make_valid_config(
            ssh_targets={
                "s1": {
                    "host": "1.2.3.4",
                    "username": "u",
                    "private_key": "/dev/null",
                }
            },
        )

        requests.put(
            f"http://localhost:{port}/api/config",
            json=config,
            headers=headers,
            timeout=5,
        )

        config_path = config_dir / "ssh-mcp-config.json"
        mode = os.stat(config_path).st_mode & 0o777
        assert mode == 0o600


class TestIntegrationSSHTargetCRUD:
    """Integration tests for SSH target CRUD lifecycle."""

    def test_create_read_update_delete_cycle(self, config_api_container):
        """Full CRUD lifecycle for an SSH target."""
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        base = f"http://localhost:{port}"
        name = "integration-crud-test"

        # Create (must include at least one credential)
        resp = requests.put(
            f"{base}/api/config/ssh_targets/{name}",
            json={
                "host": "10.0.0.99", "port": 22,
                "username": "test", "password": "secret",
            },
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200

        # Read
        resp = requests.get(
            f"{base}/api/config/ssh_targets/{name}",
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["host"] == "10.0.0.99"
        assert data["username"] == "test"

        # Update (must include at least one credential)
        resp = requests.put(
            f"{base}/api/config/ssh_targets/{name}",
            json={
                "host": "10.0.0.100", "port": 2222,
                "username": "test", "password": "new-secret",
            },
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200

        # Verify update persisted
        resp = requests.get(
            f"{base}/api/config/ssh_targets/{name}",
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200
        assert resp.json()["host"] == "10.0.0.100"
        assert resp.json()["port"] == 2222

        # Delete
        resp = requests.delete(
            f"{base}/api/config/ssh_targets/{name}",
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 200

        # Verify gone
        resp = requests.get(
            f"{base}/api/config/ssh_targets/{name}",
            headers=headers,
            timeout=5,
        )
        assert resp.status_code == 404


class TestIntegrationBackupLifecycle:
    """Integration tests for backup lifecycle."""

    def test_backup_appears_after_config_write(self, config_api_container):
        """Writing config creates a backup that appears in the list."""
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        base = f"http://localhost:{port}"

        config = requests.get(
            f"{base}/api/config", headers=headers, timeout=5
        ).json()
        requests.put(
            f"{base}/api/config", json=config, headers=headers, timeout=5
        )
        resp = requests.get(
            f"{base}/api/backups", headers=headers, timeout=5
        )
        assert resp.status_code == 200
        assert len(resp.json()["backups"]) >= 1

    def test_backup_restore_cycle(self, config_api_container):
        """Write → backup → modify → restore returns to original."""
        _, port = config_api_container
        headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
        base = f"http://localhost:{port}"

        # Get original config
        original = requests.get(
            f"{base}/api/config", headers=headers, timeout=5
        ).json()

        # Write to create backup
        requests.put(
            f"{base}/api/config", json=original, headers=headers, timeout=5
        )

        # Modify
        modified = original.copy()
        modified["block_patterns"] = ["integration-test-pattern"]
        requests.put(
            f"{base}/api/config", json=modified, headers=headers, timeout=5
        )

        # Get backups and restore
        backups = requests.get(
            f"{base}/api/backups", headers=headers, timeout=5
        ).json()
        assert len(backups["backups"]) >= 1
        requests.post(
            f"{base}/api/backups/{backups['backups'][0]['name']}/restore",
            headers=headers,
            timeout=5,
        )

        # Verify restored — the integration-test-pattern should be gone
        restored = requests.get(
            f"{base}/api/config", headers=headers, timeout=5
        ).json()
        assert "integration-test-pattern" not in restored.get(
            "block_patterns", []
        )
