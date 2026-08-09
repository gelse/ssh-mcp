# 03 - Separation of Concerns

## Current State Analysis

### Concern Boundaries

| Concern | Current Location | Correct? |
|---------|-----------------|----------|
| MCP Tool Definitions | [`server.py`](server.py:1) | ✓ |
| SSH Transport | [`server.py`](server.py:1) | ✗ should be in `lib/` |
| Authorization Logic | [`lib/auth.py`](lib/auth.py:1) | ✓ |
| Config Management | [`lib/config.py`](lib/config.py:1) | ✓ |
| Structured Logging | [`lib/loggers.py`](lib/loggers.py:1) | ✓ |
| Health Check | [`lib/health.py`](lib/health.py:1) | ✓ |
| Request Context | [`lib/request_context.py`](lib/request_context.py:1) | ✓ |
| IP Extraction | [`server.py`](server.py:1) | ⚠ should be a utility |
| API Key Extraction | [`server.py`](server.py:1) | ⚠ should be a utility |
| Sudo Command Validation | [`server.py`](server.py:1) | ⚠ crosses auth + command concern |
| File Path Validation | [`server.py`](server.py:1) | ✗ should be in `lib/` |
| Docker/Traefik Config | `compose.yaml`, `Dockerfile` | ✓ |

### Specific Violations

#### 1. IP Extraction Logic in Application Layer
[`_extract_client_ip()`](server.py:93) parses X-Forwarded-For headers directly in `server.py`. This is an HTTP concern that belongs in middleware or a utility module. The fallback logic and header parsing shouldn't be in the same file as SSH tool definitions.

#### 2. API Key Extraction in Application Layer
[`get_api_key()`](server.py:78) reads `x-api-key` and `Authorization: Bearer` headers directly. This is an authentication concern that should be in middleware and stored in request context, not called imperatively in tool handlers.

#### 3. Sudo Overlap Between Auth and Command Execution
[`_is_sudo_command()`](server.py:174) and the sudo wrapping logic in [`ssh_execute_command()`](server.py:190) create duplication: auth.py blocks raw `sudo` in block patterns, then server.py re-validates and wraps it. The validate-then-wrap concern spans two modules when it should be a single concern.

#### 4. File Path Validation Duplication
Both [`ssh_download_file()`](server.py:252) and [`ssh_upload_file()`](server.py:298) independently validate paths:
- `os.path.isabs()` check
- `os.pardir` check
- Remote path = f"/{remote_path.lstrip('/')}"
This should be one `PathValidator` class reused by both.

#### 5. SSH Client Creation Mixed with Business Logic
[`get_ssh_client()`](server.py:152) handles key loading, password detection, socket configuration, connect timeout, and client creation — all infrastructure concerns — in the same file that defines MCP tool semantics.

### Recommended Restructuring

```
lib/
  auth.py              → domain: authorization rules
  config.py            → domain: configuration
  loggers.py           → domain: logging
  health.py            → app: health endpoint
  request_context.py   → app: request context
  ssh_client.py        → NEW: infrastructure: SSH transport
  file_transfer.py     → NEW: infrastructure: SFTP operations
  auth_middleware.py   → NEW: app: API key extraction → context
  path_validator.py    → NEW: domain: file path validation
  constants.py         → NEW: shared constants
  exceptions.py        → NEW: shared exception hierarchy
  types.py             → NEW: shared TypedDict types
server.py              → app: MCP tool definitions ONLY
```

### Acceptance Criteria
- `server.py` contains only MCP tool decorators and thin call delegation
- IP extraction lives in `lib/request_context.py` or `lib/auth_middleware.py`
- API key extraction populates request context via middleware, not tool calls
- Sudo validation/wrapping is a single cohesive module or class
- Path validation is implemented once and reused
- No Paramiko imports outside `lib/ssh_client.py` and `lib/file_transfer.py`
