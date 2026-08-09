# 05b - Rewrite Server Tests to Import Actual Code & Add Parametrized Security Tests

**Parent Plan**: [05-test-coverage.md](plans/05-test-coverage.md)

## Objective
Rewrite `tests/test_server.py` to import and call actual production code instead of reimplementing logic inline, and add parametrized security test cases.

## Context
Many tests in [`tests/test_server.py`](tests/test_server.py:1) simulate logic rather than importing the module. For example, `_is_sudo_command()` tests reimplement the regex instead of calling the actual function. This validates the test's own logic, not the production code.

## Implementation Steps
1. Create test fixtures that set up `ConfigManager` with known config, `AuthorizationManager` with known rules
2. Rewrite `TestExtractClientIP` to import actual `_extract_client_ip()` (or its new location from task 03a)
3. Rewrite `TestIsCommandSudo` to import actual function
4. Rewrite `TestSudoWrap` to import actual function  
5. Add `TestSSHClientCreation` that uses mock `paramiko.SSHClient` but real `get_ssh_client()`
6. Add parametrized security test class `TestCommandInjection`:
   - `@pytest.mark.parametrize("payload", [...])` with 20+ payloads
   - Test `$()`, backticks, `&&`, `||`, newlines, Unicode homoglyphs
7. Add parametrized path traversal test class `TestPathTraversal`
8. Add test for authorization bypass attempts

## Dependencies
- Task 01c (factory pattern for testability), 04b (command hardening)

## Acceptance Criteria
- server.py tests import actual code, not simulations
- Parametrized security tests with 20+ injection payloads
- Parametrized path traversal tests with 10+ payloads
- All existing test coverage maintained
