"""Integration tests for the MCP SSH server.

These tests spin up real Docker containers:
- An SSH server (linuxserver/openssh-server) as the test target
- The MCP SSH server (mcp-ssh:test) as the application under test

Requires the ``docker`` Python package and a working Docker daemon.
"""

from __future__ import annotations

import io
import json
import socket
import tarfile
import time
import urllib.request
import urllib.error

import pytest

# Skip all tests if the docker package is not installed
docker = pytest.importorskip("docker")
from docker.errors import NotFound, APIError as DockerError  # noqa: E402


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SSH_IMAGE = "linuxserver/openssh-server"
SSH_CONTAINER = "mcp-ssh-test-ssh"
MCP_CONTAINER = "mcp-ssh-test-app"
TEST_NETWORK = "mcp-ssh-test-net"
SSH_PORT = 2222
MCP_PORT = 8080

TEST_SSH_SERVERS = {
    "testbox": {
        "host": SSH_CONTAINER,
        "port": SSH_PORT,
        "username": "testuser",
        "password": "testpass",
    }
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_tcp(host: str, port: int, timeout: float = 30.0) -> None:
    """Poll a TCP socket until a successful connect or *timeout*.

    Raises :class:`TimeoutError` if the port never becomes reachable.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    raise TimeoutError(
        f"Timed out after {timeout:.0f}s waiting for TCP {host}:{port}"
    )


def _wait_for_http(url: str, timeout: float = 30.0) -> None:
    """Poll an HTTP GET endpoint until 200 or *timeout*.

    Raises :class:`TimeoutError` if the endpoint never returns 200.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.5)
    raise TimeoutError(
        f"Timed out after {timeout:.0f}s waiting for HTTP {url}"
    )


def _mcp_request(url: str, method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC 2.0 request to the MCP endpoint and return the parsed result.

    Handles both plain JSON and SSE-wrapped (``data: `` lines) responses.

    Parameters
    ----------
    url : str
        Base URL of the MCP server (e.g. ``http://10.0.0.5:8080``).
    method : str
        The JSON-RPC method name (e.g. ``tools/list``).
    params : dict or None
        Optional parameters for the method.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/mcp",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=15.0) as resp:
        body = resp.read().decode("utf-8")

    # Check for SSE-wrapped response (lines prefixed with "data: ")
    lines = body.splitlines()
    data_lines = [line for line in lines if line.startswith("data: ")]
    if data_lines:
        # Concatenate JSON from all data: lines
        json_text = "".join(line.removeprefix("data: ") for line in data_lines)
        return json.loads(json_text)

    # Plain JSON response
    return json.loads(body)


def _inject_json_file(container, dest_path: str, data: dict) -> None:
    """Write a JSON dict into *container* at *dest_path* using ``put_archive()``.

    Creates a tar archive in memory containing a single file.
    """
    import os as _os

    dirname = _os.path.dirname(dest_path)
    basename = _os.path.basename(dest_path)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        content = json.dumps(data, indent=2).encode("utf-8")
        info = tarfile.TarInfo(name=basename)
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))

    buf.seek(0)
    container.put_archive(path=dirname or "/", data=buf.read())


# ---------------------------------------------------------------------------
# Fixtures (session-scoped)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_client():
    """Return a Docker client, skipping all tests if Docker is unavailable."""
    try:
        return docker.from_env()
    except DockerError as exc:
        pytest.skip(f"Docker unavailable: {exc}")


@pytest.fixture(scope="session")
def test_network(docker_client):
    """Create a bridge network for integration tests.

    Cleans up the network after all tests finish.
    """
    # Remove any leftover network from a previous run
    try:
        old = docker_client.networks.get(TEST_NETWORK)
        old.remove()
    except NotFound:
        pass

    network = docker_client.networks.create(TEST_NETWORK, driver="bridge")
    try:
        yield network
    finally:
        try:
            network.remove()
        except NotFound:
            pass


@pytest.fixture(scope="session")
def ssh_container(docker_client, test_network):
    """Start an OpenSSH server container for testing.

    The container is removed after the session ends.
    """
    # Clean up leftover container from a previous run
    try:
        old = docker_client.containers.get(SSH_CONTAINER)
        old.remove(force=True)
    except NotFound:
        pass

    # Pull the image if not present
    try:
        docker_client.images.get(SSH_IMAGE)
    except docker.errors.NotFound:
        docker_client.images.pull(SSH_IMAGE)

    container = docker_client.containers.run(
        SSH_IMAGE,
        name=SSH_CONTAINER,
        network=TEST_NETWORK,
        environment={
            "PUID": "1000",
            "PGID": "1000",
            "TZ": "Etc/UTC",
            "USER_NAME": "testuser",
            "USER_PASSWORD": "testpass",
            "SUDO_ACCESS": "false",
            "PASSWORD_ACCESS": "true",
        },
        ports={f"{SSH_PORT}/tcp": SSH_PORT},
        auto_remove=False,
        detach=True,
    )

    try:
        # Wait for SSH to be ready
        _wait_for_tcp("127.0.0.1", SSH_PORT, timeout=45.0)
        yield container
    finally:
        try:
            container.stop(timeout=5)
            container.remove(force=True, v=True)
        except NotFound:
            pass


def _make_valid_config(servers: dict) -> dict:
    """Build a valid ssh-mcp-config.json from a servers dictionary."""
    return {
        "version": 1,
        "ssh_targets": servers,
        "block_patterns": [],
        "allowed_commands": {
            "default": [{"targets": ["*"], "commands": ["*"]}],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }


@pytest.fixture(scope="session")
def mcp_container(docker_client, test_network, ssh_container):
    """Start the MCP SSH server container for testing.

    Requires the ``mcp-ssh:test`` image to be pre-built (see Makefile's
    ``integrationtest`` target).  After the container starts and health
    passes, injects the ``TEST_SSH_SERVERS`` config so the hot-reload
    watcher picks it up.
    """
    # Clean up leftover container from a previous run
    try:
        old = docker_client.containers.get(MCP_CONTAINER)
        old.remove(force=True)
    except NotFound:
        pass

    container = docker_client.containers.run(
        "mcp-ssh:test",
        name=MCP_CONTAINER,
        network=TEST_NETWORK,
        environment={
            "CONFIG_DIR": "/config",
            "LOG_DIR": "/logs",
        },
        ports={f"{MCP_PORT}/tcp": MCP_PORT},
        auto_remove=False,
        detach=True,
    )

    try:
        # Wait for the health endpoint to respond
        _wait_for_http(f"http://127.0.0.1:{MCP_PORT}/health", timeout=30.0)

        # Inject the SSH servers config — the hot-reload watcher will pick
        # it up within its polling interval (15s default).  We write to
        # /config/ssh-mcp-config.json since CONFIG_DIR=/config.
        _inject_json_file(
            container,
            "/config/ssh-mcp-config.json",
            _make_valid_config(TEST_SSH_SERVERS),
        )

        # Give the watcher a moment to detect the change
        time.sleep(1.0)

        yield container
    finally:
        try:
            container.stop(timeout=5)
            container.remove(force=True)
        except NotFound:
            pass


@pytest.fixture(scope="session")
def mcp_url(docker_client, mcp_container):
    """Return the base URL of the running MCP server."""
    # Reload container info to get the assigned IP
    container = docker_client.containers.get(MCP_CONTAINER)
    networks = container.attrs["NetworkSettings"]["Networks"]
    net_info = networks.get(TEST_NETWORK, {})
    ip = net_info.get("IPAddress", "")
    if not ip:
        # Fallback: try to inspect the network
        for net_name, info in networks.items():
            candidate = info.get("IPAddress", "")
            if candidate:
                ip = candidate
                break
    if not ip:
        raise RuntimeError(
            f"Could not determine IP address for container '{MCP_CONTAINER}'"
        )
    return f"http://{ip}:{MCP_PORT}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_returns_ok(self, mcp_url: str):
        """GET /health returns 200 with {"status": "ok"}."""
        req = urllib.request.Request(f"{mcp_url}/health")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode())
            assert body == {"status": "ok"}


class TestMcpTools:
    """Tests for the MCP JSON-RPC tools endpoint."""

    def test_tools_list_returns_all_tools(self, mcp_url: str):
        """POST /mcp tools/list returns all 4 tool definitions."""
        result = _mcp_request(mcp_url, "tools/list")

        # Handle both possible response structures:
        # {"tools": [...]}  (direct)
        # {"result": {"tools": [...]}}  (JSON-RPC wrapped)
        if "result" in result:
            result = result["result"]

        tools = result.get("tools", [])
        tool_names = {t["name"] for t in tools}
        expected = {
            "ssh_list_servers",
            "ssh_execute_command",
            "ssh_download_file",
            "ssh_upload_file",
        }
        assert tool_names == expected

    def test_ssh_list_servers_shows_testbox(self, mcp_url: str):
        """POST /mcp tools/call ssh_list_servers shows testbox."""
        result = _mcp_request(
            mcp_url, "tools/call", {"name": "ssh_list_servers", "arguments": {}}
        )

        # Unwrap JSON-RPC if needed
        if "result" in result:
            result = result["result"]

        content = result.get("content", [])
        text = "".join(item.get("text", "") for item in content)
        assert "testbox" in text
        assert f"testuser@{SSH_CONTAINER}:{SSH_PORT}" in text

    def test_ssh_execute_hostname_on_testbox(self, mcp_url: str):
        """POST /mcp tools/call ssh_execute_command hostname on testbox."""
        result = _mcp_request(
            mcp_url,
            "tools/call",
            {
                "name": "ssh_execute_command",
                "arguments": {
                    "server_name": "testbox",
                    "command": "hostname",
                },
            },
        )

        # Unwrap JSON-RPC if needed
        if "result" in result:
            result = result["result"]

        content = result.get("content", [])
        text = "".join(item.get("text", "") for item in content)

        # The hostname should be the SSH container's hostname (a hex string
        # from Docker), so it should be non-empty.
        assert len(text.strip()) > 0, f"Expected non-empty hostname output, got: {text!r}"

        # It should not contain error indicators
        assert "error" not in text.lower() and "Error" not in text, (
            f"Unexpected error in output: {text!r}"
        )
