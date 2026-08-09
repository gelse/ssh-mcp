# 06a - Add Integration Tests for File Transfer & Authorization Flows

**Parent Plan**: [06-integration-test-coverage.md](plans/06-integration-test-coverage.md)

## Objective
Add integration tests for file download/upload operations and expand authorization flow testing with API keys and network rules.

## Implementation Steps
1. Add file transfer integration tests to `tests/integration/test_integration.py`:
   - `test_ssh_download_file`: Create file on SSH target → download → verify content
   - `test_ssh_upload_file`: Upload file → download back → verify roundtrip
   - `test_ssh_download_file_traversal_rejected`: Attempt traversal path → verify 400 error
   - `test_ssh_download_file_binary`: Download binary file → verify checksum
2. Add authorization integration tests:
   - `test_command_blocked_by_pattern`: Config with block pattern → blocked command rejected
   - `test_command_allowed_by_api_key`: Config with API key allowing specific command → passes with key, fails without
   - `test_command_allowed_by_network`: Config with network rule → passes from matching IP
   - `test_chained_command_with_blocked_segment`: `safe_cmd | blocked_cmd` → rejected
3. Add helper utilities to test module: `create_test_file_on_target()`, `verify_file_contents()`, `setup_config_with_api_keys()`

## Dependencies
- Task 01c (factory pattern may affect config loading), 02a (constants)

## Acceptance Criteria
- File download integration test passes
- File upload integration test passes
- Path traversal rejection tested at integration level
- API key auth flow tested end-to-end
- Network auth flow tested end-to-end
- Command blocking by pattern tested at integration level
