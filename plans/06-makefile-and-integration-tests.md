# Plan 06: Makefile & Integration Tests

## Scope

Add a `Makefile` with four targets (`build`, `up`, `test`, `integrationtest`) and a Python-based integration test module that spins up Docker containers directly (no compose) to validate the full MCP SSH stack end-to-end.

---

## Design Decisions (from user clarification)

| Decision | Choice |
|----------|--------|
| SSH auth for test container | Password: `testuser` / `testpass` |
| Test scope | `/health` endpoint + MCP JSON-RPC calls |
| Container orchestration | Python `docker` SDK, **no** compose for integration tests |
| Test image tag | `mcp-ssh:test` |
| Config reload test | Write `ssh-servers.json` **after** container start to test auto-reload |

---

## Files to Create / Modify

| File | Action | Purpose |
|------|--------|---------|
| [`Makefile`](Makefile) | **Create** | Build, run, test, and integration-test targets |
| [`tests/integration/__init__.py`](tests/integration/__init__.py) | **Create** | Package marker |
| [`tests/integration/test_integration.py`](tests/integration/test_integration.py) | **Create** | Integration test module |

No existing files are modified.

---

## 1. Makefile Design

```makefile
.PHONY: build up test integrationtest

build:
    docker compose build

up:
    docker compose up -d

test:
    python -m pytest tests/ -v --ignore=tests/integration/

integrationtest:
    python -m pytest tests/integration/ -v
```

**Rationale:**
- `build` and `up` delegate to `docker compose` (existing `compose.yaml`)
- `test` runs unit tests only, explicitly ignoring the integration directory so `test` works without Docker
- `integrationtest` runs only the integration module; the integration module itself handles container lifecycle

---

## 2. Integration Test Module Design

### 2.1 Architecture Overview

The test module uses [`docker`](https://pypi.org/project/docker/) Python SDK to:
1. Build `mcp-ssh:test` image from the project root
2. Start a minimal OpenSSH container (`linuxserver/openssh-server`) with `testuser:testpass`
3. Create a dedicated Docker network for the two containers to communicate
4. Start the `mcp-ssh:test` container with an **empty** `ssh-servers.json` initially
5. Write the `ssh-servers.json` config into the running container (tests auto-reload)
6. Wait for the config watcher to pick up the change (polling interval + buffer)
7. Execute HTTP requests against the MCP container to validate `/health` and JSON-RPC tools

### 2.2 Container Topology

```
┌──────────────────────────────────────────────────┐
│  Docker Network: mcp-ssh-test (bridge)            │
│                                                    │
│  ┌─────────────────────┐  ┌────────────────────┐  │
│  │ mcp-ssh-test-app    │  │ mcp-ssh-test-ssh   │  │
│  │ (mcp-ssh:test)      │  │ (linuxserver/      │  │
│  │ port 8080 internal  │  │  openssh-server)   │  │
│  │                     │  │ port 2222 internal  │  │
│  │ config reload:      │  │                     │  │
│  │ monitors            │  │ user: testuser      │  │
│  │ ssh-servers.json    │  │ pass: testpass      │  │
│  └─────────────────────┘  └────────────────────┘  │
│                                                    │
│  Test host ──HTTP──> mcp-ssh-test-app:8080          │
│  mcp-ssh-test-app ──SSH──> mcp-ssh-test-ssh:2222   │
└──────────────────────────────────────────────────┘
```

### 2.3 `ssh-servers.json` for the Test

Written into the running container's `/app/ssh-servers.json` **after** launch:

```json
{
  "testbox": {
    "host": "mcp-ssh-test-ssh",
    "port": 2222,
    "username": "testuser",
    "password": "testpass"
  }
}
```

This implicitly validates the hot-reload config watcher — the file didn't exist when the container started, but the watcher should detect it within one polling cycle.

### 2.4 Test Cases

#### Test 1: Health Endpoint
- **Given** the mcp-ssh container is running
- **When** GET `http://<container>:8080/health`
- **Then** response status is 200 and body contains `{"status": "ok"}`

#### Test 2: MCP `tools/list` — Server Discovery
- **Given** the mcp-ssh container is running with ssh-servers.json injected
- **When** POST `http://<container>:8080/mcp` with JSON-RPC `tools/list`
- **Then** response contains tool definitions for `ssh_list_servers`, `ssh_execute_command`, `ssh_download_file`, `ssh_upload_file`

#### Test 3: MCP `tools/call` — `ssh_list_servers`
- **Given** the test ssh-servers.json is loaded
- **When** POST `http://<container>:8080/mcp` with JSON-RPC `tools/call` for `ssh_list_servers`
- **Then** response includes `testbox: testuser@mcp-ssh-test-ssh:2222`

#### Test 4: MCP `tools/call` — `ssh_execute_command` (hostname)
- **Given** the OpenSSH container is reachable
- **When** POST `http://<container>:8080/mcp` with JSON-RPC `tools/call` for `ssh_execute_command` with `server_name="testbox"`, `command="hostname"`
- **Then** response contains the hostname of the OpenSSH container (a hex container ID)

### 2.5 Lifecycle Management

Uses `pytest` fixtures with `session` scope:

```python
@pytest.fixture(scope="session")
def docker_client():
    """Return a docker.DockerClient connected to the local daemon."""
    ...

@pytest.fixture(scope="session")
def test_network(docker_client):
    """Create a dedicated bridge network, tear down after all tests."""
    ...

@pytest.fixture(scope="session")
def ssh_container(docker_client, test_network):
    """Start linuxserver/openssh-server with test credentials."""
    ...

@pytest.fixture(scope="session")
def mcp_container(docker_client, test_network, ssh_container):
    """Build mcp-ssh:test, start it, inject ssh-servers.json, wait for reload."""
    ...

@pytest.fixture(scope="session")
def mcp_url(mcp_container):
    """Return the base URL for the MCP container."""
    ...
```

Key lifecycle details:
- **Network**: Created first, removed last (the `test_network` fixture depends on nothing except `docker_client`)
- **SSH container**: Started second; waits until port 2222 is accepting connections
- **MCP container**: Built from project root (`docker build -t mcp-ssh:test .`), started with an empty `ssh-servers.json` (`{}`), waits for `/health` to return 200
- **Config injection**: After MCP container is healthy, use `docker cp` or `put_archive` to write the test `ssh-servers.json` into `/app/ssh-servers.json` inside the container
- **Wait for reload**: Sleep `polling_interval + 5s` (the watcher defaults to 15s, so ~20s) before running tests that depend on the config
- **Teardown**: Fixtures clean up in reverse order — MCP container stopped/removed, SSH container stopped/removed, network removed

### 2.6 Dependencies

The integration test requires `docker` Python package. Add to `requirements-dev.txt` or document that it must be installed.

Options:
1. Add a `requirements-dev.txt` with `pytest` and `docker`
2. Document the requirement in the Makefile (add a check or install step)
3. Have the integration test module check for the `docker` package at import time and skip with a clear message if absent

**Preference**: Option 3 (graceful skip) + document in Makefile comments. Keeps it self-contained.

### 2.7 MCP JSON-RPC Protocol Details

The FastMCP streamable HTTP transport uses standard JSON-RPC 2.0:

**`tools/list` request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

**`tools/call` request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "ssh_list_servers",
    "arguments": {}
  }
}
```

The response contains `"result"` with the tool output. The `id` field is used to correlate requests/responses.

**Note**: FastMCP streamable HTTP may use SSE (Server-Sent Events) for streaming responses. The test module should handle both plain JSON responses and SSE-wrapped responses. The simplest approach is to read the full response body and parse it — FastMCP typically returns a single JSON-RPC response for tool calls.

### 2.8 Error Handling & Retry

- Container startup: retry `/health` check up to 30 seconds (5s intervals)
- SSH container readiness: retry TCP connect to port 2222 up to 30 seconds
- Config reload: poll the `ssh_list_servers` call every 5 seconds for up to 30 seconds instead of a fixed sleep (more robust)

### 2.9 Test Module Structure

```python
"""Integration tests for the MCP SSH server.

Requires Docker daemon and the ``docker`` Python package.
These tests spin up real containers and validate end-to-end behavior.
"""

import json
import socket
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

# Try to import docker; skip all tests if not available
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not DOCKER_AVAILABLE,
    reason="docker Python package not installed; run: pip install docker"
)

# Constants
PROJECT_ROOT = Path(__file__).parent.parent.parent
SSH_IMAGE = "linuxserver/openssh-server"
SSH_CONTAINER_NAME = "mcp-ssh-test-ssh"
MCP_CONTAINER_NAME = "mcp-ssh-test-app"
TEST_NETWORK_NAME = "mcp-ssh-test-net"
SSH_PORT = 2222
MCP_PORT = 8080

# ... fixtures and tests ...
```

---

## 3. OpenSSH Container Configuration

Using `linuxserver/openssh-server` image with environment variables:

| Env Var | Value |
|---------|-------|
| `PUID` | `1000` |
| `PGID` | `1000` |
| `TZ` | `Etc/UTC` |
| `USER_NAME` | `testuser` |
| `USER_PASSWORD` | `testpass` |
| `SUDO_ACCESS` | `false` |
| `PASSWORD_ACCESS` | `true` |
| `PORT` | `2222` |

Container ports: expose `2222` on the test network only (no host port binding needed).

---

## 4. MCP Test Container Configuration

Built from the project root:
```bash
docker build -t mcp-ssh:test .
```

Started with:
- `CONFIG_DIR=/config` (as in compose.yaml)
- No volume mounts (self-contained test)
- An initial empty `ssh-servers.json`: `{"version": 1, "ssh_targets": {}, ...}` — **actually**, looking at `server.py`, it uses the old `ssh-servers.json` format, not the new `ConfigManager`. The `server.py` still reads `ssh-servers.json` directly via `load_servers()`.

**Important discovery**: `server.py` uses the legacy `ssh-servers.json` format (flat `{name: {host, port, username, password/privateKey}}`), NOT the new `ssh-mcp-config.json` format validated by `ConfigManager`. The hot-reload watcher monitors `ssh-mcp-config.json`, but `server.py`'s `load_servers()` reads `ssh-servers.json` directly on every call.

This means:
- Config injection should write the legacy-format `ssh-servers.json` to `/app/ssh-servers.json`
- The watcher/reload feature being tested is actually about the `ssh-servers.json` being read fresh on each `load_servers()` call (no caching in `server.py`)
- The actual "hot reload" being tested is: write a new `ssh-servers.json` → `server.py` picks it up on next tool call because `load_servers()` re-reads the file each time

**Correction**: Since `server.py` reads `ssh-servers.json` on every tool call (no caching), "hot reload" is implicit. The test validates that the server can dynamically pick up new server configs without restart. This is simpler than the ConfigManager watcher and works immediately.

---

## 5. Integration Test Flow (Step by Step)

```
1. Create Docker network: mcp-ssh-test-net
2. Pull linuxserver/openssh-server image (if not cached)
3. Start SSH container:
   - Name: mcp-ssh-test-ssh
   - Network: mcp-ssh-test-net
   - Env: USER_NAME=testuser, USER_PASSWORD=testpass, PASSWORD_ACCESS=true, PORT=2222
   - Wait for port 2222 to accept connections (TCP)
4. Build mcp-ssh:test image from project root (docker build -t mcp-ssh:test .)
5. Start MCP container:
   - Name: mcp-ssh-test-app
   - Network: mcp-ssh-test-net
   - Env: CONFIG_DIR=/config, LOG_DIR=/logs
   - Wait for /health to return 200 (retry up to 30s)
6. Write test ssh-servers.json to MCP container:
   {
     "testbox": {
       "host": "mcp-ssh-test-ssh",
       "port": 2222,
       "username": "testuser",
       "password": "testpass"
     }
   }
   - Use docker SDK: container.put_archive() or exec_run + echo
7. Wait 2 seconds (no watcher delay needed — server.py reads on every call)
8. Run test: GET /health → 200
9. Run test: POST /mcp tools/list → verify tool names
10. Run test: POST /mcp tools/call ssh_list_servers → verify testbox appears
11. Run test: POST /mcp tools/call ssh_execute_command(server_name="testbox", command="hostname") → verify output
12. Cleanup (fixture teardown):
    - Stop & remove mcp-ssh-test-app
    - Stop & remove mcp-ssh-test-ssh
    - Remove mcp-ssh-test-net
```

---

## 6. Makefile — Detailed Design

```makefile
.PHONY: build up test integrationtest clean-test

build:  ## Build the Docker image using docker compose
    docker compose build

up:  ## Start the service with docker compose (detached)
    docker compose up -d

test:  ## Run unit tests only (excludes integration tests)
    python -m pytest tests/ -v --ignore=tests/integration/

integrationtest:  ## Build :test image and run integration tests
    docker build -t mcp-ssh:test .
    python -m pytest tests/integration/ -v

clean-test:  ## Remove test containers and network (if left over)
    -docker rm -f mcp-ssh-test-app mcp-ssh-test-ssh 2>/dev/null || true
    -docker network rm mcp-ssh-test-net 2>/dev/null || true
```

**Note on `integrationtest`**: The image build happens in the Makefile target, not in the Python module. The Python module expects `mcp-ssh:test` to already exist. This keeps the module simpler and follows the user's instruction: "builds a new image with :test tag, starts that image".

**Note on `clean-test`**: Helper target to clean up leftovers from failed/cancelled test runs.

---

## 7. Implementation Steps (for Code mode)

1. Create the `Makefile` at project root
2. Create `tests/integration/__init__.py` (empty)
3. Create `tests/integration/test_integration.py` with:
   - Skip marker if `docker` package not installed
   - Session-scoped fixtures for network, SSH container, MCP container
   - Config injection helper
   - Four test functions (health, tools/list, ssh_list_servers call, ssh_execute_command call)
   - Proper cleanup in fixture teardown
4. Add `docker` to test requirements
5. Verify: `make test` runs unit tests, `make integrationtest` runs integration tests

---

## 8. Self-Test Criteria

- [ ] `make build` runs `docker compose build` successfully
- [ ] `make up` starts containers via docker compose
- [ ] `make test` runs existing unit tests without Docker
- [ ] `make integrationtest` builds `mcp-ssh:test`, starts SSH + MCP containers, runs tests, cleans up
- [ ] Test: `/health` returns 200 with `{"status": "ok"}`
- [ ] Test: `tools/list` returns all 4 tool definitions
- [ ] Test: `tools/call` `ssh_list_servers` shows testbox
- [ ] Test: `tools/call` `ssh_execute_command` with `hostname` returns valid output
- [ ] Containers and network are cleaned up after tests (pass or fail)
- [ ] `make clean-test` handles dangling containers
- [ ] Integration tests skip gracefully if `docker` Python package is missing
