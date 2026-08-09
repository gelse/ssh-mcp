# 13a - Input Validation Pipeline & Sanitization

**Parent Plan**: [13-data-validation-input-sanitization.md](plans/13-data-validation-input-sanitization.md)

## Objective
Add input sanitization pipeline for commands, harden IP/API key/path validation, add config resource limits, and implement ReDoS protection for block pattern regex.

## Implementation Steps
1. Create `lib/sanitize.py` with sanitization functions:
   - `sanitize_command(raw: str) -> str`: strip null bytes → strip control chars → NFKC normalize → strip whitespace
   - `sanitize_server_name(raw: str) -> str`: validate `[a-zA-Z0-9._-]{1,128}`
   - `sanitize_log_string(raw: str) -> str`: strip newlines from single-line fields
2. Integrate `sanitize_command()` into tool handlers before auth check
3. Harden IP validation in `get_client_ip()`: validate with `ipaddress.ip_address()`
4. Harden API key validation: max 1024 chars, printable ASCII only
5. Add config resource limits to validation:
   - Max 1000 targets, max 500 block patterns, max 128 char target names
   - Max 10000 chars per regex pattern
6. Add ReDoS protection to `AuthorizationManager`:
   - Test patterns on init with a timeout (e.g., `signal.alarm` or threading timer)
   - Flag patterns matching known dangerous patterns: `(a+)+`, `(a|a)+`, `(.*a){n}`
7. Add `sanitize_server_name()` validation to config loader
8. Integration tests for sanitization pipeline

## Dependencies
- Task 04b (command hardening), 02a (constants), 03a (IP extraction)

## Acceptance Criteria
- Command input goes through sanitization pipeline before auth
- Server names validated to `[a-zA-Z0-9._-]{1,128}`
- IPs validated with ipaddress module
- Config resource limits enforced
- Dangerous regex patterns flagged at config load
- Newlines stripped from log string fields
