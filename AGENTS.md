# AGENTS.md — AI Development Guide for mcp-ssh

**Contents:**
- [Project Overview](#project-overview) · [Quick Facts](#quick-facts) · [Repository Layout](#repository-layout)
- [Documentation Map](#documentation-map) · [Build & Run](#build--run) · [Testing](#testing)
- [Development Workflow](#development-workflow) · [Coding Conventions](#coding-conventions)
- [Configuration Model](#configuration-model) · [Authorization Model](#authorization-model)
- [Sudo](#sudo) · [Config API & Dashboard](#config-api--dashboard)
- [Security-Sensitive Areas](#security-sensitive-areas) · [Adding a Tool](#adding-a-tool)
- [File-Touch Checklist](#file-touch-checklist) · [Definition of Done](#definition-of-done)
- [Dependency Management](#dependency-management) · [Docker / Deployment](#docker--deployment)
- [Known Traps](#known-traps)

## Project Overview

**mcp-ssh** is a [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes SSH command
execution and SFTP file transfer as MCP tools. It speaks streamable HTTP on port `8080` at `/mcp` and ships as a Docker
container with no TLS of its own — put a TLS-terminating reverse proxy in front.

**Stack:** Python 3.13 (runtime image and CI), [FastMCP](https://gofastmcp.com/) 3.4.6,
[paramiko](https://www.paramiko.org/) 5.0, Starlette 1.4, Prometheus client 0.26, watchdog 6. The config API adds
FastAPI 0.141 / pydantic 2 / httpx.

**Six tools**, all returning a JSON string (`{"error": true, "error_type": …, "message": …}` on failure):

| Tool | Purpose |
|------|---------|
| `ssh_list_servers()` | Targets from config (host/port/user, never secrets) |
| `ssh_list_allowed_commands(server_name)` | Effective rules for one target |
| `ssh_execute_command(server_name, command, timeout=30, sudo=False)` | Run a command; `sudo` gated per rule |
| `ssh_check_connection(server_name, timeout=10)` | Connectivity probe |
| `ssh_download_file(server_name, remote_path)` | SFTP download, base64 in the response |
| `ssh_upload_file(server_name, remote_path, content, permissions="0644")` | SFTP upload |

**Key patterns:** app-factory (`create_app()`, zero I/O at import), closure DI for tool handlers, thread-pool for SSH
I/O, per-target connection pooling, layered auth chain, config hot-reload (15 s poll / 2 s debounce), circuit breaker +
exponential backoff, sliding-window rate limiter, pluggable log targets with JSONL rotation/gzip, and a pure
sudoers-drop-in generator on top of the auth rules.

## Quick Facts

| Item | Value |
|------|-------|
| Entry point | [`server.py`](server.py) — `create_app()` (factory), `main()` (CLI) |
| MCP endpoint | `POST /mcp` (streamable HTTP) |
| HTTP endpoints | `GET /health`, `GET /metrics`, `/api/*` (config API, opt-in) |
| Config file | `$CONFIG_DIR/ssh-mcp-config.json` (default `/config`) |
| Secrets | `$CONFIG_DIR/secrets.json` and `MCP_SSH_SECRET_*` env vars |
| Logs | `$LOG_DIR` (default `/logs`), JSONL |
| Dashboard | `/api/ui/` — single-page app, no build step |
| API docs | `/api/docs` (FastAPI OpenAPI) |

## Repository Layout

```
mcp-ssh/
├── server.py                    # FastMCP app factory, tool handlers, CLI, graceful shutdown
├── lib/                         # 31 modules + __init__.py (public re-exports)
├── config-api/                  # Config API + web dashboard, mounted at /api
│   ├── config_api/              # app.py, auth.py, body_size_middleware.py, config_service.py,
│   │                            # mcp_client.py, models.py, routes.py
│   │   └── ui/                  # index.html (single-file SPA) + self-hosted tailwindcss.js
│   ├── requirements.{in,txt}    # FastAPI / uvicorn / pydantic / httpx pins
│   └── tests/                   # 7 test modules for the API and its service layer
├── tests/
│   ├── test_*.py                # 39 unit-test files, one per module plus cross-cutting suites
│   └── integration/test_mcp_ssh_integration.py   # real Docker containers
├── docs/                        # SECURITY.md, CONFIGURATION.md, CONFIG-API.md, OBSERVABILITY.md
├── examples/                    # sample configs, curl snippets, MCP client example
├── ARCHITECTURE.md, CONTRIBUTING.md, CHANGELOG.md, README.md
├── Dockerfile, compose.yaml, Makefile
├── requirements{,-build,-dev}.{in,txt}
└── default-config.json, config.schema.json
```

### `lib/` modules

| Module | Responsibility |
|--------|---------------|
| [`auth.py`](lib/auth.py) | `AuthorizationManager` — layered chain, immutable `RulesSnapshot`, `AuthResult`, per-rule `sudo_allowed` |
| [`circuit_breaker.py`](lib/circuit_breaker.py) | Per-target CLOSED/OPEN/HALF_OPEN state machine |
| [`command_security.py`](lib/command_security.py) | Dangerous-pattern detection, command segmentation, redirector stripping |
| [`config.py`](lib/config.py) | `ConfigManager` — load, validate, hot-reload, setting overrides, `build_default_config()` |
| [`config_migration.py`](lib/config_migration.py) | Version chain registry (`MIGRATIONS`), backup + write-back (latest supported: 1) |
| [`config_watcher.py`](lib/config_watcher.py) | Polling/watchdog filesystem watcher |
| [`connection_pool.py`](lib/connection_pool.py) | Per-target SSH pooling, idle eviction, concurrency cap |
| [`constants.py`](lib/constants.py) | **All** magic values and defaults: `SETTING_KEY_TYPES`, `SUDOERS_*`, log/metric names |
| [`crypto.py`](lib/crypto.py) | PBKDF2-HMAC-SHA256 API-key hashing + timing-safe verify |
| [`exceptions.py`](lib/exceptions.py) | `MCPSSHError` hierarchy |
| [`file_transfer.py`](lib/file_transfer.py) | SFTP transfer with 7-layer path validation |
| [`health.py`](lib/health.py) | `GET /health` custom route |
| [`loggers.py`](lib/loggers.py) | `BaseLogger` ABC + `FileLogger` (JSONL, thread-safe, size rotation) |
| [`log_composite.py`](lib/log_composite.py) | Fan-out of log entries to several targets |
| [`log_manager.py`](lib/log_manager.py) | Builds log targets from `settings.logging` |
| [`log_handler.py`](lib/log_handler.py) | Bridge from stdlib `logging` to the structured logger |
| [`log_target_jsonfile.py`](lib/log_target_jsonfile.py) | JSONL file target (rotation/gzip) |
| [`log_target_textfile.py`](lib/log_target_textfile.py) | Human-readable file target |
| [`log_target_stdout.py`](lib/log_target_stdout.py) | Stdout target |
| [`metrics.py`](lib/metrics.py) | Prometheus registry + `GET /metrics` (and `OPTIONS`) |
| [`rate_limiter.py`](lib/rate_limiter.py) | Sliding-window per-IP limiter + ASGI middleware |
| [`redos_protection.py`](lib/redos_protection.py) | Static ReDoS analysis, safe compile/match |
| [`request_context.py`](lib/request_context.py) | Request ID, client IP, API key extraction |
| [`sanitize.py`](lib/sanitize.py) | `sanitize_command()`, `sanitize_target_name()`, `sanitize_log_string()` |
| [`secrets.py`](lib/secrets.py) | `SecretsManager` — env `MCP_SSH_SECRET_*` > `secrets.json` > main config |
| [`size_utils.py`](lib/size_utils.py) | `parse_size_bytes()` |
| [`ssh_client.py`](lib/ssh_client.py) | `SSHClientManager` — connect, retry, circuit-break, key loading |
| [`ssh_operations.py`](lib/ssh_operations.py) | Standalone SSH functions + `resolve_command_paths()` for sudoers generation |
| [`sudo.py`](lib/sudo.py) | `SudoHandler` — validate, wrap (`sudo -S -p ''` / `sudo -n`), inject password |
| [`sudoers.py`](lib/sudoers.py) | Pure sudoers drop-in generation: grant union, filename, single-line renderer |
| [`types.py`](lib/types.py) | `TypedDict` result models (`SudoGrants`, `SudoersDocument`, …) |

Every `lib/` module has a matching `tests/test_<module>.py`; cross-cutting suites (`test_server.py`,
`test_config_schema.py`, `test_e2e_config.py`, `test_concurrency.py`, `test_examples.py`,
`test_config_api_mount.py`, `test_piping_chaining_deployed_config.py`) cover wiring and shipped configs.

## Documentation Map

| Document | Read/update when |
|----------|------------------|
| [`README.md`](README.md) | User-facing behaviour: tools, settings, FAQ, troubleshooting |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Changing a module, the request flow, thread-safety, or `lib/` file table |
| [`docs/SECURITY.md`](docs/SECURITY.md) | **Mandatory** for crypto, auth, command security, sudo, sudoers, file transfer, sanitization, secrets, request context |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Adding/renaming any config key or setting |
| [`docs/CONFIG-API.md`](docs/CONFIG-API.md) | Any config API route, dashboard behaviour, secret-handling semantics |
| [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) | Health, metrics, log targets, log fields |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Workflow and style for human contributors |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes (Keep-a-Changelog style) |
| [`examples/`](examples/) | Shipped configs and client snippets — keep them valid, a test loads them |

## Build & Run

```bash
make build          # docker compose build
make up             # start detached (compose maps host 9080 -> container 8080)
make down
make test           # unit tests (main suite)
make integrationtest
make clean-test     # remove test containers/network/log leftovers
```

Run directly from the checkout (no container):

```bash
.venv/bin/python server.py --config ./config --ssh-key ssh_key --log-dir ./logs
.venv/bin/python server.py --print-default-config     # print build_default_config() and exit
.venv/bin/python server.py --fix-permissions          # chmod config/secrets to 0o600
```

Environment variables: `CONFIG_DIR`, `LOG_DIR`, `SSH_KEY_PATH`, `MAX_OUTPUT_LENGTH` (CLI args win),
`CONFIG_API_ENABLED`, `CONFIG_API_TOKEN`, `CONFIG_API_SESSION_COOKIE_SECURE`, `MCP_SERVER_URL` (config API → MCP over
HTTP), plus `MCP_SSH_SETTING_*` (settings overrides) and `MCP_SSH_SECRET_*` (secret overrides).

## Testing

### Main suite (CI runs this)

```bash
make test     # .venv/bin/python -m pytest tests/ -v --ignore=tests/integration/
```

- CI ([`.github/workflows/test.yml`](.github/workflows/test.yml)) runs exactly this on Python 3.13 with only
  `requirements.txt` + `pytest` installed — keep the suite free of extra dependencies.
- Write configs into `tmp_path`; never mutate shared files (`_write_config` helpers in
  [`tests/test_auth.py`](tests/test_auth.py), [`tests/test_server.py`](tests/test_server.py)).
- Mock only true I/O boundaries (`paramiko.SSHClient`, `create_app`, `asyncio.run`).
- Use `pytest.raises()` for expected failures and assert the exception type/message.
- Parser-level tests may call the real `visudo` (see [`tests/test_sudoers.py`](tests/test_sudoers.py)); they
  `pytest.skip()` when it is absent, so they never fail a minimal environment.

### Config API suite (CI does **not** run it)

```bash
cd config-api && ../.venv/bin/python -m pytest tests/
```

- Run it from `config-api/` with the repo venv — `make config-test` is a no-op (it looks for
  `config-api/.venv` and swallows the error with `|| true`). Always run this suite by hand when you touch
  `config-api/`.
- [`config-api/tests/conftest.py`](config-api/tests/conftest.py) installs a stub `lib` package so the API tests import
  `lib.config` / `lib.constants` without pulling paramiko.
- The async route tests need `pytest-asyncio`, which is not pinned. Without it a batch of tests in
  `test_auth.py` and `test_body_size_middleware.py` fail with *"async def functions are not natively supported"* — a
  missing plugin, not a regression.

### Integration suite

```bash
make integrationtest   # builds mcp-ssh:test, runs tests/integration/, needs the docker Python SDK
```

- Real containers on the dedicated bridge network `mcp-ssh-test-net`.
- Covers health, tool listing, execute/sudo paths, file transfer incl. traversal rejection, auth flows (block patterns,
  API keys, networks), sanitization, key variants, and config validation of ReDoS patterns.
- Runs only on `release*` tags in CI ([`.github/workflows/integration.yml`](.github/workflows/integration.yml)).

### Fast inner loop

```bash
.venv/bin/python -m pytest tests/test_<module>.py -x
```

No lint, type-check, or formatter tooling exists (no ruff/mypy/pyright/flake8). [`.editorconfig`](.editorconfig) is the
only style contract. The local `.venv` may be newer than 3.13 — production is 3.13, so avoid interpreter-specific
syntax and behaviour.

## Development Workflow

1. **Analyze** — read the relevant `lib/` module and its test, check config-schema and docs impact, and read
   [`docs/SECURITY.md`](docs/SECURITY.md) before touching a security-sensitive area.
2. **Implement** — respect module boundaries; closure DI for tools; no module-level side effects; constants in
   [`lib/constants.py`](lib/constants.py); exceptions in [`lib/exceptions.py`](lib/exceptions.py); re-export public
   symbols from [`lib/__init__.py`](lib/__init__.py).
3. **Unit test** — `tests/test_<module>.py`, success **and** error paths.
4. **Config API test** — `config-api/tests/` when the change touches the API, service layer, or dashboard.
5. **Integration test** — extend
   [`tests/integration/test_mcp_ssh_integration.py`](tests/integration/test_mcp_ssh_integration.py) when touching SSH,
   auth, sudo, file transfer, rate limiting, or HTTP.
6. **Docs** — update the documents named in the [Documentation Map](#documentation-map).
7. **Commit** — one commit per task, short imperative-mood subject.
8. **PR** — feature branch → PR against `testing`; never push to `main` or `testing`; delete the branch after merge.

## Coding Conventions

| Rule | Detail |
|------|--------|
| **No side effects at import** | App factories only; no I/O, threads, network, or env reads at module level |
| **Constants** | Every magic number/string in [`lib/constants.py`](lib/constants.py) with a docstring |
| **Exceptions** | Subclass `MCPSSHError`; never raise bare `Exception` |
| **Type hints** | Full annotations on public functions and methods |
| **Docstrings** | Google-style (`Args`/`Returns`/`Raises`) on every public function |
| **Closure DI** | Tool handlers capture from `_register_tools()` parameters, not globals |
| **Config access** | `config_manager.data.get("settings", {})` with a fallback, never direct attribute poking |
| **Logging** | `file_logger.log({...})` with `event`, `request_id`, `log_level`, `log_format_version` |
| **Metrics** | Increment `REQUESTS_TOTAL` per tool call; observe `COMMAND_DURATION_SECONDS` for SSH |
| **Imports** | `from __future__ import annotations`; stdlib → third-party → local |
| **Line length** | Python 88; Markdown prose 120 (`max_line_length` in [`.editorconfig`](.editorconfig)); tables may run wider |
| **Naming** | Tools `ssh_<verb>_<noun>`; the MCP argument for a target is always `server_name` |
| **Web/SPA** | Plain ES2020 in one `<script>`; no bundler, no framework, no npm |

## Configuration Model

Top-level keys of `ssh-mcp-config.json` (`version` is currently `1`):

| Section | Shape |
|---------|-------|
| `ssh_targets` | `{name: {host, port, username, password?, private_key?, checkcommand?}}` |
| `block_patterns` | List of regexes; match → deny (ReDoS-checked on load) |
| `allowed_commands.default` | List of `{targets, commands, sudo_allowed?}` applied to all clients |
| `allowed_commands.api_keys` | List of `{name, key_hash?, rules: [...]}` |
| `allowed_commands.networks` | List of `{name, range, rules: [...]}` |
| `settings` | Runtime tunables — see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) |

- **Settings registry** — every setting key, its type, and coercion lives in `SETTING_KEY_TYPES`
  ([`lib/constants.py`](lib/constants.py)). Adding a setting means updating that map, `default-config.json`,
  `config.schema.json` (hand-written, mirrored by [`tests/test_config_schema.py`](tests/test_config_schema.py)), and the
  docs.
- **Validation** — [`ConfigManager._validate()`](lib/config.py) is the single validator; the config API reuses it.
  It requires at least one of `password` / `private_key` per target, rejects `sudo_allowed` entries outside the rule's
  `commands`, rejects ReDoS-prone `block_patterns`, and rejects unknown target keys (`ALLOWED_TARGET_KEYS` in
  [`lib/config.py`](lib/config.py)) — a new per-target field must be added there as well as to the schema.
- **Secrets** — `password`, `private_key`, and `key_hash` may live in the main file, but `MCP_SSH_SECRET_*` and
  `secrets.json` override them at load time (env > file > main config).
- **Hot reload** — the watcher polls every 15 s with a 2 s debounce; consumers swap immutable snapshots atomically.
  `settings.watcher_debounce_seconds` tunes the debounce.
- **Migration** — [`lib/config_migration.py`](lib/config_migration.py) holds a version→migration registry and writes a
  `.bak` before rewriting a config it upgrades.

## Authorization Model

The chain is **layered and ordered**; every command segment passes through all of it:

1. **target validation** — unknown target → DENY
2. **block_patterns** — command matches a regex → DENY
3. **dangerous patterns** — `$()`, backticks, newlines → DENY
4. **redirection-target guard** — redirects into protected pseudo-filesystem paths → DENY
5. **segmentation + redirector stripping** — split on chaining operators; each segment runs the whole chain
6. **default rules** — allow/deny for all clients
7. **API key rules** — a matching authenticated key decides
8. **network rules** — a matching client-IP CIDR decides
9. **deny** — implicit fallback

`AuthResult.matched_via` records which layer decided (`"default"`, `"api_key:<name>"`, `"network:<name>"`, plus a
`" (sudo)"` suffix for sudo denials). When changing authorization, consider **all** layers, the sudo gate, and the
generated sudoers file.

**Per-rule sudo:** each rule may carry `sudo_allowed`, a subset of its `commands`. `sudo=True` is permitted only when
the matching rule lists the command's base name (or `"*"`); a rule without `sudo_allowed` denies every sudo attempt with
`sudo not allowed for '<command>' by this rule`. The check runs on the **unwrapped** command before sudo is added.

## Sudo

Two halves, both security-relevant:

**Runtime wrapping** — [`lib/sudo.py`](lib/sudo.py) runs `sudo -S -p ''` when the target has a `password` (fed over
stdin) and `sudo -n` when it only has a key. Raw `sudo` in the command string is always blocked by `block_patterns`;
double wrapping is rejected.

**Generated drop-in** — `GET /api/config/ssh_targets/{name}/sudoers` turns the config's sudo grants into an
`/etc/sudoers.d` file ([`lib/sudoers.py`](lib/sudoers.py) for the pure part,
[`resolve_command_paths()`](lib/ssh_operations.py) for the one SSH step). Invariants to preserve:

- **Scope** — the union of `default`, API-key, and network rules for that target; each rule contributes only its own
  `sudo_allowed`, because all layers log in as the target's single `username`.
- **One grant line, no aliases** — `username ALL = (root) NOPASSWD: /usr/bin/a, /usr/bin/b, …`. sudoers has no line
  continuation, and a `Cmnd_Alias` with continuation backslashes is invalid; alias names also cannot carry the hyphens
  that target ids do.
- **Bare absolute paths** — no argument pattern. A spec without a pattern permits any arguments (what the rule means);
  a trailing `*` reads the same to classic sudo but is **not implemented by sudo-rs before 0.2.9**, where it makes the
  line match nothing. Do not reintroduce the wildcard.
- **Host field `ALL`** — sudo compares it against the local machine name, never an address.
- **Never `ALL`** — a rule with `commands: ["*"]` and `sudo_allowed: ["*"]` is skipped and reported as such
  (`# skipped: …`).
- **Validated interpolation** — names and paths must match `SUDOERS_COMMAND_NAME_PATTERN` / `SUDOERS_PATH_PATTERN`;
  anything else is reported `invalid` and never written out.
- **Unresolved commands** — commented out in the file and listed in the response. When nothing resolves, `content` is
  empty and `notes` explain why.
- **Filename** — `mcp-ssh-<target>` with unsafe characters replaced (`SUDOERS_FILENAME_*`), intended for
  [`SUDOERS_DROPIN_DIR`](lib/constants.py). Operators install it as `0440 root:root` after `visudo -c`.

The response carries `target`, `username`, `host`, `filename`, `content`, `resolved`, `unresolved`, `skipped`,
`invalid`, `notes`. Unknown target → 404, unreachable target → 502. Path resolution bypasses the auth chain on purpose:
it is one fixed, read-only lookup made by the service, never caller-supplied text.

## Config API & Dashboard

- **Enabled** with `CONFIG_API_ENABLED=true`; [`server.py`](server.py) mounts the FastAPI app at `/api` (dashboard at
  `/api/ui/`, OpenAPI at `/api/docs`). Disabled → no routes at all.
- **Two modes** — *unified* (the API gets the live `SSHClientManager` and `ConfigManager` and calls `lib` directly) and
  *standalone* (`mcp_client.py` speaks JSON-RPC over the MCP streamable-HTTP transport to `MCP_SERVER_URL`). Keep both
  paths working when adding a feature that reaches a target.
- **Auth** — `CONFIG_API_TOKEN` as a Bearer token (timing-safe compare) or a session cookie issued by
  `POST /api/auth/login` (`config_api_session`, HttpOnly, `SameSite=strict`, `Secure` unless
  `CONFIG_API_SESSION_COOKIE_SECURE=false`, 1 h max age, 30 min idle). `POST /api/auth/logout`, `GET /api/auth/session`.
- **Body limit** — `BodySizeLimitMiddleware` rejects oversized requests (`CONFIG_API_MAX_BODY_SIZE_BYTES`, 1 MiB).
- **Public static assets** — `/ui` is served without authentication; only the API calls the SPA makes are protected. Do
  not put configuration, tokens, or target data into the HTML file.
- **Routes** — health/schema (`/health`, `/config/schema`, `/config/validate`, `/hash-key`), config documents
  (`GET|PUT /config`, `GET|PUT /config/{section}`), single targets (`GET|PUT|DELETE /config/ssh_targets/{name}`,
  `POST …/check`, `GET …/sudoers`), API keys, block patterns (including per-index `PUT|DELETE`), backups (list, restore,
  delete).
- **Secret handling** — reads never include `password` / `private_key` / `key_hash`; targets report `has_password`
  and `has_private_key` instead, and a newly created API key is returned in plaintext exactly once. `PUT` on a target
  is read-modify-write for secrets: **missing or `""` keeps**, **explicit `null` deletes**, **any value replaces**;
  deleting the last credential is refused with 400.
- **Writes** — validated with `ConfigManager._validate()`, timestamped `.bak` backup, temp file + atomic replace, then
  in-memory caches are invalidated so the MCP server sees the change immediately.

**Dashboard conventions** ([`config-api/config_api/ui/index.html`](config-api/config_api/ui/index.html)):

- One file, one `<script>`, Tailwind via the self-hosted `tailwindcss.js`; no build, no npm, no framework.
- Reuse the helpers: `el()`, `makeFormGroup()`, `makeRemoveCheckbox()`, `showModal()` (title, body builder, save
  handler), `toast()`, and the `renderX()` render functions.
- A destructive control belongs directly under the field it affects, and should disable/clear that field while ticked.
- Handlers read values from the modal body at save time (`body.querySelector('#m-…')`), never from captured state.
- There is no JS test harness in the repo. Verify a change by extracting the inline script and syntax-checking it:

  ```bash
  python3 -c "import re,pathlib;s=pathlib.Path('config-api/config_api/ui/index.html').read_text();\
  pathlib.Path('/tmp/spa.mjs').write_text(re.findall(r'<script>(.*?)</script>',s,re.S)[-1])"
  node --check /tmp/spa.mjs
  ```

## Security-Sensitive Areas

Read [`docs/SECURITY.md`](docs/SECURITY.md) **before** modifying: [`lib/crypto.py`](lib/crypto.py),
[`lib/auth.py`](lib/auth.py), [`lib/command_security.py`](lib/command_security.py),
[`lib/file_transfer.py`](lib/file_transfer.py), [`lib/sudo.py`](lib/sudo.py), [`lib/sudoers.py`](lib/sudoers.py),
[`lib/request_context.py`](lib/request_context.py), [`lib/secrets.py`](lib/secrets.py),
[`lib/sanitize.py`](lib/sanitize.py), [`config-api/config_api/auth.py`](config-api/config_api/auth.py),
[`config-api/config_api/config_service.py`](config-api/config_api/config_service.py).

**Key rules:**
- Never log raw API keys, passwords, or private key material (not even at debug level).
- `key_hash` is the only stored form of an API key; the plaintext is returned once, at creation.
- Upload paths must start with `/tmp/` or `/home/`.
- Error responses must not leak internal paths, stack traces, or credentials.
- Anything written into a sudoers line must match the `SUDOERS_*` patterns first.
- Redact `password`/`private_key`/`key_hash` from anything that leaves a process boundary — API responses, logs,
  `ssh_list_servers` output.

## Adding a Tool

Work through the [File-Touch Checklist](#file-touch-checklist). Reference handler: `ssh_execute_command`, registered in
`_register_tools()` ([`server.py`](server.py)). Handler patterns:

- Name it `ssh_<verb>_<noun>` and follow the [Tool Naming Convention](README.md#tool-naming-convention).
- Name the target argument `server_name`; it is the MCP-side name of an `ssh_targets` key. Sanitize it with
  `sanitize_target_name()` and use `target` in every layer below the tool — never introduce `target` or `host` at the
  MCP boundary.
- Decorate with `@mcp.tool(annotations=ToolAnnotations(...))` — set `readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint` honestly; return type `-> str` (JSON).
- Capture dependencies from `_register_tools()` parameters (closure DI), never module globals.
- Source IP: `get_client_ip()` from [`lib/request_context.py`](lib/request_context.py).
- Authorize first with `_authorize_command()` and check `auth_result.allowed`; a denial returns
  `_format_error(...)`.
- Blocking SSH I/O goes through `ssh_executor.submit(...).result()`.
- Record timing/exit code/output with `_finish_log_entry()`; render the output with `_format_execution_result()`.
- Catch `MCPSSHError` and return an error JSON — a tool handler never raises.

### Writing Tests

1. Build a config with `_write_config()` / `_make_minimal_config()`
   ([`tests/test_server.py`](tests/test_server.py)) into `tmp_path`.
2. Patch `paramiko.SSHClient` (and nothing else you can avoid patching).
3. Assert the JSON shape: success contains the expected text, failure returns `{"error": true, ...}`.
4. Model the class on `TestSshListServers` in [`tests/test_server.py`](tests/test_server.py).

## File-Touch Checklist

| # | File | Action | Skip if |
|---|------|--------|---------|
| 1 | [`lib/constants.py`](lib/constants.py) | Add defaults/patterns (and `SETTING_KEY_TYPES` entries) | No new magic values |
| 2 | [`lib/types.py`](lib/types.py) | Add a `TypedDict` for a structured result | Returns simple JSON |
| 3 | [`lib/__init__.py`](lib/__init__.py) | Re-export new public symbols | Nothing new in steps 1–2 |
| 4 | [`server.py`](server.py) | Handler + registration in `_register_tools()` | Never |
| 5 | `tests/test_<module>.py` | Success + error paths | Never |
| 6 | `default-config.json`, `config.schema.json`, `tests/test_config_schema.py`, `ALLOWED_TARGET_KEYS` | New key/section | No config change |
| 7 | `config-api/config_api/routes.py`, `models.py`, `config_service.py` | Route, model, service method | No API change |
| 8 | [`config-api/config_api/ui/index.html`](config-api/config_api/ui/index.html) | Dashboard control | API-only |
| 9 | `config-api/tests/` | Route + service tests | No API change |
| 10 | [`tests/integration/test_mcp_ssh_integration.py`](tests/integration/test_mcp_ssh_integration.py) | End-to-end case | No SSH/auth/HTTP change |
| 11 | Docs per [Documentation Map](#documentation-map) | README, ARCHITECTURE, CONFIGURATION, CONFIG-API | Never (at least check) |
| 12 | — | `make test`, `cd config-api && ../.venv/bin/python -m pytest tests/`, `make integrationtest` | Never |
| 13 | — | Commit | Never |

## Definition of Done

- [ ] Constants centralized; `SETTING_KEY_TYPES` updated if a setting was added
- [ ] Public API re-exported from [`lib/__init__.py`](lib/__init__.py); new exceptions subclass `MCPSSHError`
- [ ] Config schema, `default-config.json`, and `tests/test_config_schema.py` agree with the validator
- [ ] `make test` passes with zero regressions
- [ ] `cd config-api && ../.venv/bin/python -m pytest tests/` passes (CI will not catch this for you)
- [ ] Integration suite passes, with new scenarios if SSH/auth/sudo/HTTP changed
- [ ] SPA still parses (`node --check` on the extracted script) and the changed dialog behaves
- [ ] Docs updated: README, ARCHITECTURE, CONFIGURATION, CONFIG-API, SECURITY, CHANGELOG as applicable
- [ ] Security review done for any file listed in [Security-Sensitive Areas](#security-sensitive-areas)
- [ ] Commit created; PR opened against `testing` (never push to `main` or `testing`)

## Dependency Management

- **Runtime deps:** [`requirements.in`](requirements.in) → hash-locked [`requirements.txt`](requirements.txt)
- **Dev/test deps:** [`requirements-dev.in`](requirements-dev.in) → [`requirements-dev.txt`](requirements-dev.txt)
  (currently just the `docker` SDK; pytest is deliberately unpinned)
- **Config API deps:** `config-api/requirements.in` → `config-api/requirements.txt` (the same packages the main image
  gets from `requirements.txt`, pinned separately for standalone use)
- **Regenerate:** `pip-compile --generate-hashes --no-reuse-hashes requirements.in` inside `python:3.13-alpine`, so the
  musllinux hashes match the runtime wheels. Never hand-edit a `*.txt`.
- **No `pyproject.toml`** — raw pip + requirements files.
- **SBOM / audit:** `cyclonedx-py` in the Docker `sbom` stage; `pip-audit` via `requirements-build.txt`.
- **Renovate:** [`renovate.json`](renovate.json) — dependency dashboard plus Docker digest pinning.

## Docker / Deployment

- Runtime: `python:3.13-alpine` (digest-pinned), non-root `mcpssh` user; the image has two stages — `sbom` (build-time
  CycloneDX generation) and the runtime stage that copies `server.py`, `lib/`, `config_api/`, and the two JSON files.
- Writable mounts: `./config` → `/config`, `./logs` → `/logs`; read-only key: `./ssh_key` → `/app/ssh_key`.
- `compose.yaml` maps host `9080` → container `8080` and passes `CONFIG_DIR`, `LOG_DIR`, `CONFIG_API_ENABLED`,
  `CONFIG_API_TOKEN`, `CONFIG_API_SESSION_COOKIE_SECURE`.
- Health: `wget --spider http://127.0.0.1:8080/health`; the image declares a `HEALTHCHECK`.
- No TLS: terminate it in a reverse proxy and keep `CONFIG_API_SESSION_COOKIE_SECURE=true` there. Over plain HTTP the
  dashboard's clipboard API is unavailable — that is expected browser behaviour, not a bug.
- Image publishing: `.github/workflows/docker.yaml` builds and pushes to GHCR on `main`, `testing`, and `v*` tags.

## Known Traps

- **CI is green ≠ config API is tested.** CI runs only the main suite, on Python 3.13, with `pytest` alone.
- **`make config-test` does nothing.** It looks for `config-api/.venv` and ends with `|| true`, so it exits 0 silently.
  Use `cd config-api && ../.venv/bin/python -m pytest tests/`.
- **`pytest-asyncio` is not pinned.** The API's async tests fail without it; install it locally rather than "fixing"
  the tests.
- **Secrets from outside the file block API writes.** The service reads, validates, and writes
  `ssh-mcp-config.json` only. A target whose only credential comes from `secrets.json` / `MCP_SSH_SECRET_*` reports
  `has_password: false`, and any PUT/DELETE fails validation with *at least one of 'private_key' or 'password' must be
  non-empty*.
- **Setting defaults live in three places** — `SETTING_KEY_TYPES`, `default-config.json`, `config.schema.json` — and a
  test asserts they stay in sync.
- **sudoers:** no aliases, no line continuation, no argument wildcard, never `ALL`. See [Sudo](#sudo).
- **Docker bind mounts of single missing files silently create a directory.** Check the source exists before mounting a
  generated file into a container.
- **`visudo -c -f <file>`** is the only trustworthy syntax check; run it before installing a generated drop-in.
