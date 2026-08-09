# 03b - Move API Key Extraction to Middleware

**Parent Plan**: [03-separation-of-concerns.md](plans/03-separation-of-concerns.md)

## Objective
Move API key extraction from imperative calls in tool handlers to middleware-based population of request context.

## Context
[`get_api_key()`](server.py:78) reads headers (`x-api-key`, `Authorization: Bearer`) directly in each tool handler. This is an authentication/middleware concern. The API key should be extracted once per request by middleware and stored in the request context.

## Implementation Steps
1. Add `_request_api_key: ContextVar[str | None]` to `lib/request_context.py`
2. Add `get_api_key() -> str | None` function that reads from context var
3. In `RequestContextMiddleware.dispatch()`, extract API key from headers and set context var
4. Remove `get_api_key()` from `server.py`
5. Update all tool handlers to call `get_api_key()` from `lib/request_context` instead of `server`
6. Hash the API key early (in middleware or first use) with the same `sha256:` prefix logic

## Dependencies
- None

## Acceptance Criteria
- API key extracted in middleware, stored in context var
- `get_api_key()` from `lib/request_context.py` returns the key or None
- `server.py` no longer contains API key extraction logic
- Tests verify extraction from both `x-api-key` and `Authorization: Bearer` headers
