# 03a - Move IP Extraction to Request Context Middleware

**Parent Plan**: [03-separation-of-concerns.md](plans/03-separation-of-concerns.md)

## Objective
Move the `_extract_client_ip()` function from `server.py` into `lib/request_context.py` middleware, making IP extraction a middleware concern rather than an application concern.

## Context
[`_extract_client_ip()`](server.py:93) currently lives in `server.py`, parsing X-Forwarded-For headers and falling back to direct client IP. This is an HTTP/protocol concern, not a tool concern. The middleware already stores the Starlette `Request` object — it should also extract and store the resolved client IP.

## Implementation Steps
1. Add `get_client_ip()` function to `lib/request_context.py`
2. Add IP validation using `ipaddress.ip_address()` 
3. Parse X-Forwarded-For (leftmost non-trusted IP or first entry)
4. Store resolved IP in context variable `_request_client_ip: ContextVar[str] = ContextVar("request_client_ip")`
5. Set IP in middleware `dispatch()` method for every request
6. Remove `_extract_client_ip()` from `server.py`
7. Update all call sites to use `get_client_ip()` from `lib/request_context`
8. Add unit tests for `get_client_ip()` with various header scenarios

## Dependencies
- None

## Acceptance Criteria
- `lib/request_context.py` exports `get_client_ip()` returning validated IP string
- IP extracted and validated in middleware, stored in context var
- `server.py` no longer contains IP extraction logic
- Tests for X-Forwarded-For parsing (single, multiple, with/without port)
- Tests for IPv6, IPv4, and invalid IP handling
