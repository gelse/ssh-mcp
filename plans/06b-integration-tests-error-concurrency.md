# 06b - Add Integration Tests for Error Scenarios & Concurrency

**Parent Plan**: [06-integration-test-coverage.md](plans/06-integration-test-coverage.md)

## Objective
Add integration tests for SSH error scenarios, command timeout, and concurrent request handling.

## Implementation Steps
1. Add error scenario tests:
   - `test_ssh_execute_nonexistent_server`: Unknown server name → clear error message
   - `test_ssh_execute_auth_failure`: Wrong SSH credentials → error (no key leak in message)
   - `test_ssh_execute_command_timeout`: Long-running command `sleep 200` with short timeout → timeout error
2. Add concurrent tests:
   - `test_concurrent_ssh_execute`: 10 parallel requests → all succeed
   - `test_concurrent_file_transfer`: 5 parallel downloads + 5 parallel uploads → all succeed
   - `test_concurrent_mixed_operations`: Mix of execute and transfer → all succeed
3. Add SSH key variant test:
   - Add second SSH container with RSA key to test fixture
   - `test_ssh_execute_with_rsa_key`: Connect using RSA key → command executes
   - `test_ssh_execute_with_password_auth`: Password auth target → command executes
4. Add large output test:
   - `test_large_output_truncation`: Command generates output exceeding `max_command_output` → truncated with indication

## Dependencies
- Task 06a (test infrastructure enhancements)

## Acceptance Criteria
- Error scenario tests cover connection failure, auth failure, timeout
- Concurrent tests with 10+ parallel requests pass
- RSA key and password auth variants tested
- Large output truncation verified
