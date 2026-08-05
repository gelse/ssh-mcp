# Plan 02e: Makefile & Integration Tests

> **⚠️ SELF-EVALUATION**: Before using this plan, evaluate whether it still matches the current state of the codebase. Check that:
> - [`server.py`](server.py) still reads `ssh-servers.json` via `load_servers()` on every tool call (no caching)
> - [`Dockerfile`](Dockerfile) still builds with `python:3.13-alpine`, `fastmcp`, `paramiko`
> - [`compose.yaml`](compose.yaml) still uses `mcp-ssh:local` image tag and external `traefik` network
> - [`lib/config.py`](lib/config.py) still has `ConfigManager` with watcher, `start_watcher()`, `stop_watcher()`
> - [`tests/test_config.py`](tests/test_config.py) still exists and tests the ConfigManager
> - No other plans (02c, 02d, 03, 04, 05) have been implemented that change these interfaces
>
> **If any of the above have changed**, update this plan accordingly before proceeding.

## Parent: [Plan 02 — External Config File with Watching](plans/02-config-file.md)
## Dependencies: Plan 02a (ConfigManager core), Plan 02b (hot-reload watcher) — both DONE

---

## Scope

Add a `Makefile` with `build`, `up`, `down`, `test`, and `integrationtest` targets, plus a Python-based integration test module that orchestrates Docker containers directly (no compose) to validate the MCP SSH stack end-to-end.

---

## Current State Assessment

### What exists

| File | Role |
|------|------|
| [`server.py`](server.py) | FastMCP server. Uses legacy `ssh-servers.json` format. `load_servers()` reads the file **fresh on every tool call** — no caching, implicit "hot reload". |
| [`Dockerfile`](Dockerfile) | Builds `python:3.13-alpine` image with `fastmcp` + `paramiko`. Exposes port 8080. Has `/health` HEALTHCHECK. |
| [`compose.yaml`](compose.yaml) | Production compose: `mcp-ssh:local` image, mounts `./config`, `./logs`, `./ssh_key`, `./ssh_key.pub`, `./ssh-servers.json`. Uses external `traefik` network. |
| [`lib/config.py`](lib/config.py) | `ConfigManager` with `load()`, `reload()`, `start_watcher()`, `stop_watcher()`, validation. Reads `ssh-mcp-config.json` format. **Not yet integrated into server.py.** |
| [`lib/health.py`](lib/health.py) | Attaches `/health` endpoint to FastMCP's Starlette app. Returns `{"status": "ok"}`. |
| [`tests/test_config.py`](tests/test_config.py) | Unit tests for ConfigManager (validation, reload, watcher, thread safety). |
| [`ssh-servers.json`](ssh-servers.json) | Legacy flat format with 13 server entries. Used by `server.py` directly. |
| [`default-config.json`](default-config.json) | Bundled default for ConfigManager (new schema). Not yet used by `server.py`. |
| [`ssh_key`](ssh_key) / [`ssh_key.pub`](ssh_key.pub) | SSH keypair for production connections. |

### Key architectural fact

`server.py` calls `load_servers()` on every `ssh_list_servers()` and `ssh_execute_command()` call. This means:

- **No watcher needed for test**: Writing a new `ssh-servers.json` into the running container takes effect on the next tool call — zero delay.
- **Integration test uses legacy format**: The test injects the flat `ssh-servers.json` format (matching what `server.py` currently expects), not the new `ssh-mcp-config.json` schema.

### What's missing

- No `Makefile` exists
- No integration tests exist
- No `tests/integration/` directory

---

## Design Decisions (from user clarification)

| Decision | Choice |
|----------|--------|
| SSH auth for test container | Password: `testuser` / `testpass` |
| Test scope | `/health` endpoint + MCP JSON-RPC calls (`tools/list`, `tools/call`) |
| Container orchestration | Python `docker` SDK — **no** compose for integration tests |
| Test image tag | `mcp-ssh:test` |
| Config reload test | Write `ssh-servers.json` into container **after** startup; verify `server.py` picks it up on next call |
| Makefile targets | `build`, `up`, `down`, `test`, `integrationtest` |

---

## 1. Makefile Design

**File**: [`Makefile`](Makefile) (create new at project root)

```makefile
.PHONY: build up down test integrationtest clean-test

build:  ## Build the Docker image using docker compose
	docker compose build

up:  ## Start the service with docker compose (detached)
	docker compose up -d

down:  ## Stop and remove containers, networks
	docker compose down

test:  ## Run unit tests only (excludes integration tests)
	python -m pytest tests/ -v --ignore=tests/integration/

integrationtest:  ## Build :test image and run integration tests
	docker build -t mcp-ssh:test .
	python -m pytest tests/integration/ -v

clean-test:  ## Remove leftover test containers and network
	-docker rm -f mcp-ssh-test-app mcp-ssh-test-ssh 2>/dev/null || true
	-docker network rm mcp-ssh-test-net 2>/dev/null || true
```

**Rationale**:
- `build` and `up` delegate to `docker compose` (existing [`compose.yaml`](compose.yaml))
- `down` adds `docker compose down` per user request
- `test` runs unit tests only, explicitly ignoring `tests/integration/` so it works without Docker
- `integrationtest` builds the `:test` image first, then runs integration tests via pytest. The image build lives in the Makefile (not in Python), per user instruction: "builds a new image with :test tag, starts that image"
- `clean-test` is a helper for leftover containers/networks from cancelled/failed runs

---

## 2. Integration Test Module

**File**: [`tests/integration/__init__.py`](tests/integration/__init__.py) (empty package marker)

**File**: [`tests/integration/test_integration.py`](tests/integration/test_integration.py)

### 2.1 Container Topology

```
┌──────────────────────────────────────────────────────────────┐
│  Docker Network: mcp-ssh-test-net (bridge)                    │
│                                                              │
│  ┌───────────────────────────┐  ┌─────────────────────────┐  │
│  │ mcp-ssh-test-app          │  │ mcp-ssh-test-ssh        │  │
│  │ image: mcp-ssh:test       │  │ image: linuxserver/     │  │
│  │                           │  │        openssh-server   │  │
│  │ port 8080 (internal only) │  │ port 2222 (internal)    │  │
│  │                           │  │                         │  │
│  │ ssh-servers.json injected │  │ USER_NAME=testuser      │  │
│  │ AFTER container start     │  │ USER_PASSWORD=testpass  │  │
│  │                           │  │ PASSWORD_ACCESS=true    │  │
│  └───────────────────────────┘  └─────────────────────────┘  │
│           ▲                            ▲                     │
│           │ HTTP (from test host)      │ SSH (from mcp app)  │
│           │                            │                     │
│  ┌────────┴────────┐                  │                     │
│  │  pytest runner  │──────────────────┘                     │
│  │  (test host)    │  HTTP to MCP container on port 8080    │
│  └─────────────────┘                                        │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Pytest Fixtures (session-scoped)

All fixtures use `scope="session"` so containers are created once and reused across all tests.

```
fixture dependency chain:
  docker_client
      └── test_network
              ├── ssh_container
              │       └── mcp_container (depends on ssh_container being ready)
              │               └── mcp_url
              └── (no other children)
```

| Fixture | Responsibility |
|---------|---------------|
| `docker_client` | Returns `docker.DockerClient.from_env()`. Skips all tests if Docker unavailable. |
| `test_network` | Creates bridge network `mcp-ssh-test-net`. Removes on teardown. |
| `ssh_container` | Pulls `linuxserver/openssh-server`, starts with test credentials, waits for TCP port 2222. Removes on teardown. |
| `mcp_container` | Builds `mcp-ssh:test` (expects it to exist from Makefile), starts with empty `{}` as initial `ssh-servers.json`, waits for `/health` 200, then injects the real `ssh-servers.json`. Removes on teardown. |
| `mcp_url` | Returns `http://<mcp_container_ip>:8080` for HTTP requests. |

### 2.3 Config Injection (ssh-servers.json)

Written into the MCP container **after** it's healthy:

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

Injection method: use `docker` SDK `container.put_archive()` to write the file to `/app/ssh-servers.json`.

Since `server.py` reads `ssh-servers.json` fresh on every tool call (no caching), the new config takes effect immediately — no sleep/wait needed. This implicitly validates that the server can dynamically pick up new server configurations without restart.

### 2.4 Test Cases

#### Test 1: `test_health_endpoint`
- **Given**: MCP container is running
- **When**: `GET /health`
- **Then**: Status 200, body `{"status": "ok"}`

#### Test 2: `test_mcp_tools_list`
- **Given**: MCP container is running with `ssh-servers.json` injected
- **When**: `POST /mcp` with JSON-RPC `tools/list`
- **Then**: Response contains tool definitions for `ssh_list_servers`, `ssh_execute_command`, `ssh_download_file`, `ssh_upload_file`

#### Test 3: `test_ssh_list_servers`
- **Given**: Test `ssh-servers.json` is loaded
- **When**: `POST /mcp` with JSON-RPC `tools/call` for `ssh_list_servers`
- **Then**: Response includes `testbox: testuser@mcp-ssh-test-ssh:2222`

#### Test 4: `test_ssh_execute_hostname`
- **Given**: OpenSSH container is reachable
- **When**: `POST /mcp` with JSON-RPC `tools/call` for `ssh_execute_command` with `server_name="testbox"`, `command="hostname"`
- **Then**: Response contains the hostname of the OpenSSH container (a hex container ID string)

### 2.5 MCP JSON-RPC Protocol

FastMCP streamable HTTP uses standard JSON-RPC 2.0:

**`tools/list` request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

**`tools/call` request**:
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

The response is a standard JSON-RPC response with `"result"` containing the tool's return value as a JSON object with a `"content"` array.

**SSE note**: FastMCP streamable HTTP may wrap responses in SSE. The test module reads the full response body and handles both cases:
1. Plain JSON-RPC response
2. SSE-wrapped (lines starting with `data: `)

### 2.6 Error Handling & Retries

| Scenario | Strategy |
|----------|----------|
| Docker daemon unavailable | Skip all tests (`pytest.skip`) |
| SSH container not ready | Retry TCP connect to port 2222 up to 30s (5s intervals) |
| MCP container not healthy | Retry `GET /health` up to 30s (3s intervals) |
| Config not loaded | No delay needed — `server.py` reads file on every call |
| Test cleanup (teardown always runs) | Use `try/finally` in fixtures; `docker rm -f` for force removal |

### 2.7 OpenSSH Container Configuration

Using `linuxserver/openssh-server` image:

| Environment Variable | Value | Purpose |
|---------------------|-------|---------|
| `PUID` | `1000` | User ID |
| `PGID` | `1000` | Group ID |
| `TZ` | `Etc/UTC` | Timezone |
| `USER_NAME` | `testuser` | SSH username |
| `USER_PASSWORD` | `testpass` | SSH password |
| `SUDO_ACCESS` | `false` | No sudo needed |
| `PASSWORD_ACCESS` | `true` | Enable password auth |
| `PORT` | `2222` | SSH listens on 2222 |

No host port binding — both containers communicate over the internal Docker network only.

### 2.8 MCP Test Container Configuration

Built from project root via Makefile: `docker build -t mcp-ssh:test .`

Started with:
- Environment: `CONFIG_DIR=/config`, `LOG_DIR=/logs`
- Network: `mcp-ssh-test-net`
- No volume mounts (self-contained)
- Initial `ssh-servers.json`: empty `{}` (so `load_servers()` returns `{}`, `ssh_list_servers` returns "No servers configured")
- After health check passes: inject real `ssh-servers.json` with testbox entry

### 2.9 Test Module Structure (Pseudo-code)

```python
"""Integration tests for the MCP SSH server.

Requires Docker daemon and the ``docker`` Python package.
Spins up real containers to validate end-to-end behavior.
"""

import json
import socket
import time
import urllib.request
import urllib.error
import tarfile
import io
from pathlib import Path

import pytest

# Graceful skip if docker package missing
docker = pytest.importorskip("docker", reason="docker Python package not installed")

# ---- Constants ----
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


def _wait_for_tcp(host: str, port: int, timeout: float = 30.0) -> None:
    """Poll TCP connect until successful or timeout."""
    ...


def _wait_for_http(url: str, timeout: float = 30.0) -> None:
    """Poll HTTP GET until 200 or timeout."""
    ...


def _mcp_request(url: str, method: str, params: dict | None = None) -> dict:
    """Send a JSON-RPC request to the MCP endpoint and return the parsed response."""
    ...


def _inject_json_file(container, dest_path: str, data: dict) -> None:
    """Write a JSON dict to a file inside a container using put_archive."""
    ...


# ---- Fixtures ----

@pytest.fixture(scope="session")
def docker_client():
    """Return a connected Docker client."""
    return docker.from_env()


@pytest.fixture(scope="session")
def test_network(docker_client):
    """Create and clean up the test bridge network."""
    ...


@pytest.fixture(scope="session")
def ssh_container(docker_client, test_network):
    """Start the OpenSSH test container, wait for readiness."""
    ...


@pytest.fixture(scope="session")
def mcp_container(docker_client, test_network, ssh_container):
    """Build and start the MCP container, inject config, wait for readiness."""
    ...


@pytest.fixture(scope="session")
def mcp_url(mcp_container):
    """Return base URL for the MCP container."""
    ...


# ---- Tests ----

class TestHealthEndpoint:
    def test_health_returns_ok(self, mcp_url):
        ...


class TestMcpTools:
    def test_tools_list_returns_all_tools(self, mcp_url):
        ...

    def test_ssh_list_servers_shows_testbox(self, mcp_url):
        ...

    def test_ssh_execute_hostname_on_testbox(self, mcp_url):
        ...
```

---

## 3. Integration Test Flow (Step by Step)

```
1. Docker SDK: create bridge network "mcp-ssh-test-net"
2. Docker SDK: pull "linuxserver/openssh-server" (if not cached)
3. Docker SDK: start SSH container
   - Name: mcp-ssh-test-ssh
   - Network: mcp-ssh-test-net
   - Env: USER_NAME=testuser, USER_PASSWORD=testpass, PASSWORD_ACCESS=true, PORT=2222, ...
   - Wait for TCP port 2222 to accept connections (retry up to 30s)
4. Docker SDK: start MCP container
   - Name: mcp-ssh-test-app
   - Image: mcp-ssh:test (pre-built by Makefile)
   - Network: mcp-ssh-test-net
   - Env: CONFIG_DIR=/config, LOG_DIR=/logs
   - Wait for GET /health to return 200 (retry up to 30s)
5. Docker SDK: inject ssh-servers.json into /app/ssh-servers.json
   - Uses put_archive() with a tar containing the JSON file
6. Run test: GET /health → assert 200 + {"status": "ok"}
7. Run test: POST /mcp tools/list → assert 4 tool names present
8. Run test: POST /mcp tools/call ssh_list_servers → assert "testbox" in result
9. Run test: POST /mcp tools/call ssh_execute_command(server_name="testbox", command="hostname") → assert valid output
10. Fixture teardown (runs even if tests fail):
    - Stop & remove mcp-ssh-test-app
    - Stop & remove mcp-ssh-test-ssh
    - Remove mcp-ssh-test-net
```

---

## 4. SSH Key for Host Key Verification

The `server.py` uses `paramiko.AutoAddPolicy()` which auto-accepts unknown host keys. This is already the production behavior, so the integration test doesn't need to handle host key verification — it works out of the box.

---

## 5. Target File Structure After Implementation

```
mcp-ssh/
├── Makefile                         # NEW
├── Dockerfile                       # (unchanged)
├── .dockerignore                    # (unchanged)
├── compose.yaml                     # (unchanged)
├── server.py                        # (unchanged)
├── ssh_key                          # (unchanged)
├── ssh_key.pub                      # (unchanged)
├── ssh-servers.json                 # (unchanged — still used by server.py)
├── default-config.json              # (unchanged)
├── lib/                             # (unchanged)
│   ├── __init__.py
│   ├── config.py
│   └── health.py
├── tests/
│   ├── __init__.py                  # (unchanged)
│   ├── test_config.py               # (unchanged)
│   └── integration/                 # NEW
│       ├── __init__.py              # NEW
│       └── test_integration.py      # NEW
├── config/                          # (unchanged, runtime)
├── logs/                            # (unchanged, runtime)
└── plans/
    └── 02e-makefile-integration.md  # NEW (this file)
```

---

## 6. Files to Create

| File | Action | Purpose |
|------|--------|---------|
| [`Makefile`](Makefile) | **Create** | Build, run, test, and integration-test targets |
| [`tests/integration/__init__.py`](tests/integration/__init__.py) | **Create** | Package marker |
| [`tests/integration/test_integration.py`](tests/integration/test_integration.py) | **Create** | Integration test module with 4 test cases |
| [`plans/02e-makefile-integration.md`](plans/02e-makefile-integration.md) | **Create** | This plan document |

**No existing files are modified.**

---

## 7. Implementation Steps (for Code mode)

1. Create [`Makefile`](Makefile) at project root with `build`, `up`, `down`, `test`, `integrationtest`, `clean-test` targets
2. Create [`tests/integration/__init__.py`](tests/integration/__init__.py) (empty)
3. Create [`tests/integration/test_integration.py`](tests/integration/test_integration.py) with:
   - `pytest.importorskip("docker")` at module level
   - Helper functions: `_wait_for_tcp()`, `_wait_for_http()`, `_mcp_request()`, `_inject_json_file()`
   - Session-scoped fixtures: `docker_client`, `test_network`, `ssh_container`, `mcp_container`, `mcp_url`
   - Test class `TestHealthEndpoint` with `test_health_returns_ok`
   - Test class `TestMcpTools` with `test_tools_list_returns_all_tools`, `test_ssh_list_servers_shows_testbox`, `test_ssh_execute_hostname_on_testbox`
   - Fixture teardown that always runs (stop/remove containers and network)
4. Copy this plan document to [`plans/02e-makefile-integration.md`](plans/02e-makefile-integration.md)

---

## 8. Self-Test Criteria

- [ ] `make build` runs `docker compose build` successfully
- [ ] `make up` starts containers via docker compose
- [ ] `make down` stops and removes containers via docker compose
- [ ] `make test` runs existing unit tests without Docker
- [ ] `make integrationtest` builds `mcp-ssh:test`, starts SSH + MCP containers, runs 4 tests, cleans up
- [ ] Test: `/health` returns 200 with `{"status": "ok"}`
- [ ] Test: `tools/list` returns all 4 tool definitions
- [ ] Test: `tools/call` `ssh_list_servers` shows testbox
- [ ] Test: `tools/call` `ssh_execute_command` with `hostname` returns valid output on testbox
- [ ] Containers and network are cleaned up after tests (pass or fail)
- [ ] `make clean-test` handles dangling containers/networks
- [ ] Integration tests skip gracefully if `docker` Python package is missing
- [ ] Plan's self-evaluation section at the top accurately reflects the codebase
