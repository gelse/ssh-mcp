# AGENTS.md — AI Development Guide for mcp-ssh

**Contents:**
- [Project Overview](#project-overview) · [Project Layout](#project-layout) · [Plans & CI](#plans--ci)
- [Testing](#testing) · [Development Workflow](#development-workflow)
- [Coding Conventions](#coding-conventions) · [Authorization Model](#authorization-model)
- [Definition of Done](#definition-of-done) · [Dependency Management](#dependency-management)
- [Docker / Deployment](#docker--deployment) · [Security](#security-sensitive-areas)
- [Adding a Tool](#adding-a-tool) · [File-Touch Checklist](#file-touch-checklist)

## Project Overview

**mcp-ssh** is a [Model Context Protocol](https://modelcontextprotocol.io/) server exposing SSH command execution and SFTP file transfer as MCP tools. Runs as Docker behind Traefik, speaking streamable HTTP on port `8080` at `/mcp`.

**Stack:** Python 3.13, [FastMCP](https://gofastmcp.com/) 3.4.x, [paramiko](https://www.paramiko.org/) 5.0, Starlette 1.4, Prometheus client, watchdog

**Six tools:** `ssh_list_servers`, `ssh_list_allowed_commands`, `ssh_execute_command`, `ssh_check_connection`, `ssh_download_file`, `ssh_upload_file` — see [`README.md`](README.md).

**Key patterns:** App-factory (`create_app()`, zero I/O at import), closure DI for tools, thread-pool for SSH I/O, per-target connection pooling, layered auth chain, config hot-reload (15 s poll / 2 s debounce), circuit breaker + exponential-backoff, sliding-window rate limiter, JSONL logging with rotation/gzip.

## Project Layout

```
mcp-ssh/
├── server.py                  # FastMCP app factory + CLI entry point
├── lib/                       # 25 modules (plus __init__.py re-exports)
│   ├── auth.py                # AuthorizationManager, layered allow-list chain
│   ├── circuit_breaker.py     # Per-target failure threshold + recovery timeout
│   ├── command_security.py    # Command segmentation, dangerous-pattern detection, redirector stripping
│   ├── config.py              # ConfigManager — JSON load/validate/hot-reload
│   ├── config_migration.py    # Config schema migration (v1→v2)
│   ├── config_watcher.py      # Filesystem watcher (polling or watchdog)
│   ├── connection_pool.py     # Per-target SSH connection pooling
│   ├── constants.py           # ALL magic numbers, strings, defaults (single source of truth)
│   ├── crypto.py              # PBKDF2-HMAC-SHA256 API-key hashing + constant-time verify
│   ├── exceptions.py          # MCPSSHError hierarchy
│   ├── file_transfer.py       # SFTP download/upload with 7-layer path validation
│   ├── health.py              # GET /health endpoint
│   ├── log_handler.py         # JSONLHandler — stdlib logging → FileLogger bridge
│   ├── loggers.py             # FileLogger (JSONL rotation/truncation/gzip)
│   ├── metrics.py             # Prometheus metrics + GET /metrics endpoint
│   ├── rate_limiter.py        # Sliding-window per-IP rate limiter
│   ├── redos_protection.py    # Safe regex compilation and ReDoS-resistant matching
│   ├── request_context.py     # Starlette middleware: request_id, client IP, API key
│   ├── sanitize.py            # Input sanitization helpers
│   ├── secrets.py             # SecretsManager for secrets.json + env var merging
│   ├── size_utils.py          # parse_size_bytes() for size-string settings
│   ├── ssh_client.py          # SSHClientManager — connect, retry, circuit-break, pool
│   ├── ssh_operations.py      # Standalone SSH functions (check, connect, execute)
│   ├── sudo.py                # SudoHandler — validate, wrap sudo command, password injection
│   └── types.py               # TypedDict models for tool results
├── config-api/                 # Config API + Web Dashboard (GUI)
│   ├── config_api/app.py, auth.py, config_service.py, models.py, routes.py
│   └── config_api/ui/index.html  # SPA dashboard (Tailwind CSS)
├── tests/
│   ├── test_*.py              # 29 unit-test files
│   └── integration/test_mcp_ssh_integration.py  # Real Docker containers
├── docs/SECURITY.md           # Full security model
├── Dockerfile, compose.yaml, Makefile
├── requirements{,-build,-dev}.{in,txt}
├── default-config.json, config.schema.json
└── README.md
```

## Plans & CI

- **Plans:** No `plans/` directory — implemented work lives in code. Keep future design docs as lightweight `.md` at repo root.
- **CI:** Single `pip-audit` job in [`.forgejo/workflows/audit.yml`](.forgejo/workflows/audit.yml). No lint, no type-check, no test — run `make test` and `make integrationtest` locally before opening a PR.
- **Renovate:** [`renovate.json`](renovate.json) extends `config:recommended` with dependency dashboard, Docker digest pinning.

## Testing

### Unit Tests

```bash
make test   # pytest tests/ -v --ignore=tests/integration/
```

- 29 test files; all 24 `lib/*.py` modules have dedicated tests
- Write configs to tmpdirs — never mutate shared files (use `_write_config` helper, see [`tests/test_auth.py`](tests/test_auth.py))
- Mock only true I/O boundaries (`paramiko.SSHClient`, `create_app`, `asyncio.run`)
- Always use `pytest.raises()` for expected exceptions

### Integration Tests

```bash
make integrationtest   # builds mcp-ssh:test image, runs tests/integration/
make clean-test        # cleanup
```

- Real Docker containers on dedicated bridge network (`mcp-ssh-test-net`)
- Validates end-to-end: auth, command authorization, execution, file transfer, concurrency
- Requires `docker` Python SDK (in `requirements-dev.txt`)

### Fast Inner Loop

```bash
.venv/bin/python -m pytest tests/test_<module>.py -x
```

No lint or type-check tooling exists. `.editorconfig` provides formatting defaults.

## Development Workflow

1. **Analyze** — review relevant modules via dependency flow diagram; check existing tests; identify config-schema impact
2. **Implement** — follow module boundaries; closure DI for tools; no module-level side effects; constants in [`lib/constants.py`](lib/constants.py); exceptions in [`lib/exceptions.py`](lib/exceptions.py); re-export from [`lib/__init__.py`](lib/__init__.py)
3. **Unit test** — `tests/test_<module>.py`; cover success + error paths
4. **Integration test** — add scenarios to [`tests/integration/test_mcp_ssh_integration.py`](tests/integration/test_mcp_ssh_integration.py) if touching SSH/auth/rate-limiting/HTTP
5. **Commit** — immediate, short imperative-mood message, one commit per task
6. **PR** — feature branch → PR against `main`; never push directly to `main`; delete branch after merge

## Coding Conventions

| Rule | Detail |
|------|--------|
| **No side effects at import** | App-factory; no I/O, threads, or network at module level |
| **Constants** | All magic values in [`lib/constants.py`](lib/constants.py) with docstrings |
| **Exceptions** | Subclass `MCPSSHError` → specialised types; never raise bare `Exception` |
| **Type hints** | Full annotations on public functions and methods |
| **Docstrings** | Google-style (Args/Returns/Raises); every public function |
| **Closure DI** | Tool handlers capture from `_register_tools()` params, not globals |
| **Config access** | Always `config_manager.data.get("settings", {})` with fallback |
| **Logging** | `file_logger.log(dict)` — include `request_id`, `event`, `log_level`, `log_format_version` |
| **Metrics** | Increment `REQUESTS_TOTAL` per tool call; observe `COMMAND_DURATION_SECONDS` for SSH |
| **Line length** | 88 chars (followed in practice) |
| **Imports** | `from __future__ import annotations` in all files; stdlib → third-party → local |

## Authorization Model

The chain is **layered and ordered** — each layer runs against every command segment:

1. **target validation** — unknown target → DENY
2. **block_patterns** — command matches regex → DENY
3. **dangerous patterns** — `$()`, backticks, newlines → DENY
4. **redirection-target guard** — targets into protected pseudofilesystem paths → DENY
5. **command segmentation + redirector stripping** — split on chaining operators; each segment runs the full chain
6. **default rules** — allow/deny for all clients
7. **API key rules** — authenticated key matching rules decides
8. **network rules** — client IP matches CIDR rules decides
9. **deny** — implicit fallback

`matched_via` in `AuthResult` tracks which layer decided. When modifying authorization, consider ALL layers.

## Definition of Done

Before considering a task complete, verify:

- [ ] **Constants centralized** — all new magic values in [`lib/constants.py`](lib/constants.py)
- [ ] **Config schema updated** — [`ConfigManager.validate()`](lib/config.py) and [`default-config.json`](default-config.json) reflect changes
- [ ] **Public API re-exported** — new symbols in [`lib/__init__.py`](lib/__init__.py)
- [ ] **Exception hierarchy** — new types subclass [`MCPSSHError`](lib/exceptions.py)
- [ ] **`make test` passes** — zero regressions
- [ ] **New code tested** — `tests/test_<module>.py` with success + error paths, `_write_config` pattern, `pytest.raises()`
- [ ] **`make integrationtest` passes** — new scenarios added if touching SSH/auth/HTTP
- [ ] **README updated** — new settings, tools, config keys documented
- [ ] **Security consulted** — if touching crypto/auth/command_security/file_transfer/sudo/request_context/secrets/sanitize, read [`docs/SECURITY.md`](docs/SECURITY.md)
- [ ] **Commit created** — short imperative-mood message
- [ ] **PR opened** — targeting `main` (never push directly)

## Dependency Management

- **Direct deps:** [`requirements.in`](requirements.in) → hash-locked [`requirements.txt`](requirements.txt) via `pip-compile --generate-hashes`
- **Dev/test deps:** [`requirements-dev.in`](requirements-dev.in) → [`requirements-dev.txt`](requirements-dev.txt)
- **Regenerate:** `pip-compile --generate-hashes --no-reuse-hashes requirements.in` inside `python:3.13-alpine`
- **No `pyproject.toml`** — raw pip + requirements files
- **SBOM:** `cyclonedx-bom` in Docker `sbom` stage; `pip-audit` via `requirements-build.txt`

## Docker / Deployment

- Runtime: `python:3.13-alpine` (hash-pinned), non-root `mcpssh` user
- Config: `/config/ssh-mcp-config.json` (mounted from `./config`)
- Logs: `/logs/` (mounted from `./logs`), SSH key: `/app/ssh_key` (read-only)
- Config API: enabled via `CONFIG_API_ENABLED=true`, mounted at `/api`
- Health: `wget --spider http://localhost:8080/health`

## Security-Sensitive Areas

Consult [`docs/SECURITY.md`](docs/SECURITY.md) before modifying these modules: [`lib/crypto.py`](lib/crypto.py), [`lib/auth.py`](lib/auth.py), [`lib/command_security.py`](lib/command_security.py), [`lib/file_transfer.py`](lib/file_transfer.py), [`lib/sudo.py`](lib/sudo.py), [`lib/request_context.py`](lib/request_context.py), [`lib/secrets.py`](lib/secrets.py), [`lib/sanitize.py`](lib/sanitize.py).

**Key rules:**
- Never log raw API keys, passwords, or private key material
- `key_hash` is the ONLY form of API keys stored in config
- Upload paths must ALWAYS start with `/tmp/` or `/home/`
- Error responses must not leak internal paths, stack traces, or credentials

## Adding a Tool

Follow the [File-Touch Checklist](#file-touch-checklist) for any new tool. Key handler patterns (see [`ssh_execute_command`](server.py:861) for reference):

- Follow the `ssh_<verb>_<noun>` naming convention — see [Tool Naming Convention](README.md#tool-naming-convention)
- `@mcp.tool()` decorator; return type `-> str`
- Capture dependencies from closure — never use module globals
- `get_client_ip()` from [`lib/request_context.py`](lib/request_context.py) for source IP
- `_authorize_command()` → check `auth_result.allowed` before executing
- Blocking SSH I/O in closure, submitted via `ssh_executor.submit(...).result()`
- Catch `MCPSSHError`, log via `_finish_log_entry`, return JSON via `_format_error` — never raise from tool handlers
- `_finish_log_entry()` records timing, exit code, output
- `_format_execution_result()` produces combined stdout/stderr string

### Writing Tests

1. Write config with `_write_config()` or `_make_minimal_config()` (see [`tests/test_server.py`](tests/test_server.py:49))
2. Call tool with mock SSH client (patch `paramiko.SSHClient`)
3. Assert JSON response shape — success includes expected text; error returns `{"error": true, ...}`
4. Model after `class TestSshListServers` in [`tests/test_server.py`](tests/test_server.py)

## File-Touch Checklist

| # | File | Action | Skip if |
|---|------|--------|---------|
| 1 | [`lib/constants.py`](lib/constants.py) | Add new defaults with docstrings | No new magic values |
| 2 | [`lib/types.py`](lib/types.py) | Add TypedDict for return type | Tool returns simple `str` JSON |
| 3 | [`lib/__init__.py`](lib/__init__.py) | Re-export new public symbols | Nothing new in steps 1–2 |
| 4 | [`server.py`](server.py) | Add `@mcp.tool()` handler | Never skipped |
| 5 | `tests/test_<module>.py` | Add unit test (success + error) | Never skipped |
| 6 | — | Run `make test` and `make integrationtest` | Never skipped |
| 7 | — | Git commit | Never skipped |
