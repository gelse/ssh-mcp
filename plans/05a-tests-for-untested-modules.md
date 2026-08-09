# 05a - Add Tests for Untested Modules

**Parent Plan**: [05-test-coverage.md](plans/05-test-coverage.md)

## Objective
Create unit tests for `lib/health.py`, `lib/request_context.py`, and `lib/ssh_client.py` (new module from 01a).

## Implementation Steps
1. Create `tests/test_health.py`: Test `attach_health_endpoint()` returns correct JSON on GET /health, returns 405 on POST, test with mock FastMCP
2. Create `tests/test_request_context.py`: Test middleware sets `_current_request` context var during request, clears after, test `get_current_request()` returns None outside request, test `get_client_ip()` and `get_api_key()` (from tasks 03a/03b)
3. Create `tests/test_ssh_client.py`: Test `SSHClientManager.create_client()` with mock `paramiko.SSHClient`, test key type detection (Ed25519 PEM header, RSA PEM header, OpenSSH format), test password auth flow, test connection failure raises `SSHConnectionError`, test timeout handling

## Dependencies
- Task 01a (SSHClientManager), 03a/03b (middleware changes)

## Acceptance Criteria
- `tests/test_health.py` with 3+ test cases
- `tests/test_request_context.py` with 5+ test cases
- `tests/test_ssh_client.py` with 5+ test cases
- All tests pass
