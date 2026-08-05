# Plan 03c: Client Identity Extraction + Request Context Wiring

## Prerequisites
- Plan 03a (`lib/auth.py`) — `AuthorizationManager` class exists
- Plan 03b (`tests/test_auth.py`) — all unit tests pass

## Subtask
Modify [`server.py`](server.py) to:
1. Add two helper functions that extract client identity from the HTTP request: `extract_client_ip()` and `extract_api_key()`
2. Create a mechanism to access the current HTTP request from within MCP tool functions
3. Instantiate `AuthorizationManager` as a module-level singleton
4. Remove the old `check_block_patterns()`, `is_command_allowed()`, and `validate_command()` functions

## Design Decision: Accessing the Starlette Request in MCP Tools

FastMCP v2 tools run in a context where the underlying Starlette request is accessible. After researching the FastMCP internals and how the Starlette app is already accessed in [`lib/health.py`](lib/health.py), we use a **thread-local storage** approach combined with Starlette middleware.

### Approach: ASGI Middleware + `contextvars`

Since FastMCP tools run synchronously (no `async def`), we use Python's `contextvars` module to store the request in a context variable that propagates through the call stack:

```python
from contextvars import ContextVar
from starlette.requests import Request

# Context variable for the current request
_current_request: ContextVar[Request | None] = ContextVar("current_request", default=None)
```

Then register ASGI middleware on the Starlette app that sets this context variable before each request:

```python
from starlette.middleware.base import BaseHTTPMiddleware

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = _current_request.set(request)
        try:
            response = await call_next(request)
            return response
        finally:
            _current_request.reset(token)
```

This middleware is attached to the internal Starlette app using the same pattern as `attach_health_endpoint()` in [`lib/health.py`](lib/health.py).

### Implementation Strategy

Add a new function in [`lib/health.py`](lib/health.py) (or a new helper module; the existing pattern is to add to `health.py`) that attaches the request-context middleware. However, since this is growing, we should add a dedicated module:

Create [`lib/request_context.py`](lib/request_context.py):

```python
"""
Request context middleware for MCP tools to access the HTTP request.

Provides a context variable ``_current_request`` that is set by ASGI
middleware before each request and cleared afterward. Tool functions
can call ``get_current_request()`` to access client IP and headers.
"""

from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_current_request: ContextVar[Request | None] = ContextVar("current_request", default=None)


def get_current_request() -> Request | None:
    """Return the current Starlette Request, or None if outside a request."""
    return _current_request.get()


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware that stores the current request in a context variable."""

    async def dispatch(self, request: Request, call_next):
        token = _current_request.set(request)
        try:
            response = await call_next(request)
            return response
        finally:
            _current_request.reset(token)
```

---

## Changes to [`server.py`](server.py)

### 1. New imports

Add at the top of [`server.py`](server.py):

```python
import hashlib
from lib.auth import AuthorizationManager, AuthResult
from lib.request_context import get_current_request
```

### 2. Client identity extraction functions

```python
def extract_client_ip() -> str | None:
    """
    Extract the client's source IP from the current HTTP request.

    Checks X-Forwarded-For header first (leftmost IP = original client),
    then falls back to the direct connection IP.

    Returns None if no request context is available.
    """
    request = get_current_request()
    if request is None:
        return None

    # Check X-Forwarded-For header
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Take the leftmost IP (original client)
        return forwarded.split(",")[0].strip()

    # Fall back to direct client IP
    if request.client is not None:
        return request.client.host

    return None


def extract_api_key() -> str | None:
    """
    Extract the API key from the Authorization: Bearer header.

    Returns the raw key string (without the "Bearer " prefix),
    or None if no Authorization header is present.

    Does NOT hash the key here — that's the AuthorizationManager's job.
    """
    request = get_current_request()
    if request is None:
        return None

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # strip "Bearer " prefix
    return None
```

### 3. AuthorizationManager instantiation

After `config_manager` is created, add:

```python
# Initialize authorization manager
auth_manager = AuthorizationManager(config_manager)
```

### 4. Register middleware on the Starlette app

After the `attach_health_endpoint(mcp)` call (around line 74), add middleware registration using the same Starlette-app-discovery pattern:

```python
from lib.request_context import RequestContextMiddleware

# Attach request context middleware (same Starlette discovery pattern as health.py)
app = None
for attr_name in dir(mcp):
    try:
        candidate = getattr(mcp, attr_name)
    except RuntimeError:
        continue
    if hasattr(candidate, "add_middleware"):
        app = candidate
        break

if app is None:
    # Try the known FastMCP >= 2.x structure
    inner = getattr(mcp, "_mcp", None)
    if inner is not None:
        app = getattr(inner, "_streamable_http_app", None)

if app is not None and hasattr(app, "add_middleware"):
    app.add_middleware(RequestContextMiddleware)
else:
    import logging
    logging.getLogger(__name__).warning(
        "Could not attach RequestContextMiddleware: Starlette app not found"
    )
```

**IMPORTANT**: The middleware must be added BEFORE `mcp.run_streamable_http_async()` is called. Since `server.py` defines `mcp` at module level and then calls `asyncio.run(mcp.run_streamable_http_async())` only in `__main__`, the middleware registration at module level is correct.

### 5. Remove old functions

Delete these three functions entirely from [`server.py`](server.py):
- `check_block_patterns()` (lines 76-86)
- `is_command_allowed()` (lines 89-115)
- `validate_command()` (lines 118-122)

---

## Changes to [`lib/health.py`](lib/health.py)

*None.* The request context middleware uses the same Starlette discovery pattern but is a separate concern, so it goes in its own module [`lib/request_context.py`](lib/request_context.py). The `attach_health_endpoint()` function in [`lib/health.py`](lib/health.py) is not modified.

---

## Files to Create

| File | Purpose |
|------|---------|
| [`lib/request_context.py`](lib/request_context.py) | `RequestContextMiddleware`, `get_current_request()`, `_current_request` context var |

## Files to Modify

| File | Change |
|------|--------|
| [`server.py`](server.py) | Add imports, `extract_client_ip()`, `extract_api_key()`, `auth_manager` instantiation, middleware registration, remove old functions |

---

## Edge Cases Handled

| Scenario | Behavior |
|----------|----------|
| No `X-Forwarded-For` header | Falls back to `request.client.host` (direct connection IP) |
| Multiple `X-Forwarded-For` values | Takes the leftmost (original client) |
| No `Authorization` header | `extract_api_key()` returns `None` |
| `Authorization` header without `Bearer` prefix | `extract_api_key()` returns `None` |
| Running outside request context (e.g., tests) | `get_current_request()` returns `None`, helpers return `None` |
| Starlette app not found for middleware | Warning logged, no crash — tools still work but without client identity (source_ip and api_key will be None) |

---

## What This Subtask Does NOT Do

- Does NOT modify tool function bodies (that's in 03d)
- Does NOT add `ssh_list_allowed_commands` tool (that's in 03d)
- Does NOT update `ssh_list_servers` to use ConfigManager (already done in Plan 02 — current code at [server.py:174-188](server.py:174) already reads from `config_manager`)
- Does NOT change the SSH execution logic in `ssh_execute_command`

---

## Acceptance Criteria

1. `server.py` imports successfully (no `ImportError`)
2. `extract_client_ip()` returns `"10.0.0.1"` when `X-Forwarded-For: 10.0.0.1, 10.0.0.2` is set
3. `extract_client_ip()` falls back to `request.client.host` when no forwarded header
4. `extract_api_key()` returns `"my-secret-key"` for `Authorization: Bearer my-secret-key`
5. `extract_api_key()` returns `None` for missing/invalid Authorization header
6. `auth_manager` is an `AuthorizationManager` instance
7. Middleware is registered on the Starlette app (no crash at startup)
8. Old `check_block_patterns()`, `is_command_allowed()`, `validate_command()` are removed from [`server.py`](server.py)
9. Existing unit tests in [`tests/test_server.py`](tests/test_server.py) **continue to pass** — these tests don't import `server.py` directly (they recreate the logic inline), so removal of old functions doesn't affect them. However, if any test imports from `server` module, it must be updated.
