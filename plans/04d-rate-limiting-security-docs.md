# 04d - Add Rate Limiting and SECURITY.md

**Parent Plan**: [04-security.md](plans/04-security.md)

## Objective
Implement configurable per-IP rate limiting for MCP endpoints and create SECURITY.md documenting the project's security model.

## Implementation Steps
1. Add rate limit settings to config schema: `settings.rate_limit.max_requests_per_minute` (default: 60), `settings.rate_limit.auth_failure_backoff_seconds` (default: 5)
2. Create `lib/rate_limiter.py` with `RateLimiter` class using a sliding-window counter per IP stored in a `dict[str, deque[float]]` with periodic cleanup
3. Add middleware that checks rate limit before processing requests, returns 429 on exceed
4. Create `SECURITY.md` documenting: TLS/reverse proxy requirement, API key management, command authorization model, vulnerability reporting process, security-relevant config options
5. Add `--no-cache-dir` to Dockerfile pip install, pin base image digest, pin dependency versions with hashes in requirements.txt

## Acceptance Criteria
- Rate limiting returns 429 with Retry-After header
- Configurable in settings
- `SECURITY.md` documents security model and TLS requirement
- Dockerfile uses `--no-cache-dir` and pinned base image
