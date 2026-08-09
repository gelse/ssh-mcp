# 06 - Integration Test Coverage

## Current State Analysis

### Existing Integration Tests

Located in [`tests/integration/test_integration.py`](tests/integration/test_integration.py:1):

| Test | What it Validates |
|------|-------------------|
| `test_health_endpoint` | GET /health returns 200 + `{"status": "ok"}` |
| `test_tools_list` | tools/list returns expected tool names |
| `test_ssh_list_servers` | ssh_list_servers returns server list with expected fields |
| `test_ssh_execute_command` | `echo hello` returns expected output |
| `test_ssh_execute_command_with_sudo` | sudo command executes successfully |
| `test_ssh_execute_command_sudo_blocked_by_pattern` | sudo blocked when not in allowed list |
| `test_ssh_execute_command_sudo_validation` | sudo in command but not first word passes auth but fails sudo wrap |

### Test Infrastructure
- Docker-based: starts `linuxserver/openssh-server` + builds MCP server image
- Dedicated bridge network for isolation
- Uses FastMCP 3.x streamable HTTP client protocol (session init, JSON-RPC 2.0)
- Test SSH target configured in `config.json` with ed25519 key
- Runs in CI via `make integrationtest`

### Gaps in Integration Coverage

#### 1. File Transfer Not Tested
Neither `ssh_download_file` nor `ssh_upload_file` have integration tests:
- No test for downloading a file from the SSH target
- No test for uploading a file to the SSH target
- No test for path traversal rejection in integration context
- No test for large file transfers

#### 2. Authorization Scenarios Insufficient
Only sudo-related auth tests exist. Missing:
- Command blocked by block pattern (integration-level)
- Command allowed by default but not by API key
- API key authentication flow end-to-end
- Network-based authorization (IP matching)
- Chained/piped command authorization

#### 3. Error Scenarios Not Covered
- SSH connection failure (wrong host)
- SSH authentication failure (wrong key/password)
- Command timeout
- Invalid server name
- Session management edge cases

#### 4. Concurrent Requests Not Tested
- Multiple simultaneous SSH connections
- Concurrent file transfers
- Race condition testing for config reload during request

#### 5. SSH Key Types Not Tested
- Only Ed25519 tested
- RSA key support not validated
- Password authentication not tested

#### 6. No Streaming/Large Output Tests
- Large output approaching/exceeding `max_command_output` limit
- Binary output handling
- Unicode/UTF-8 edge cases in command output

#### 7. No Session Lifecycle Tests
- Session initialization → notification → tool call cycle
- Session timeout/cleanup
- Multiple sessions from same client

### Test Infrastructure Improvements

1. **Add SSH Target Variants**
   - Second SSH container with RSA key
   - Second SSH container with password auth
   - Container with restricted commands (different config profile)

2. **Add Test Fixtures for Files**
   - Pre-create files on SSH target for download tests
   - Generate test files of various sizes

3. **Add Auth Test Fixtures**
   - Config with API keys for auth flow testing
   - Config with network rules for IP-based auth testing
   - Config with aggressive block patterns

4. **Add Error Injection**
   - Test with unavailable SSH target
   - Test with killed SSH container mid-transfer
   - Test with full disk (tmpfs)

### Recommended Integration Test Cases

```
File Transfer:
  - Download small text file → verify content
  - Download binary file → verify checksum
  - Upload file → download back → verify roundtrip
  - Download with path traversal attempt → rejected
  - Upload to path traversal destination → rejected
  - Upload to non-existent directory → error

Authorization:
  - Blocked command by pattern → rejected with reason
  - Command allowed only via API key → passes with key, fails without
  - Command allowed only via network → passes from allowed IP
  - Chained command with blocked segment → rejected

Error Handling:
  - Non-existent server name → clear error message
  - SSH auth failure → clear error message (no key leak)
  - Command timeout → timeout error, not hang
  - Invalid MCP method → proper JSON-RPC error

Concurrent:
  - 10 parallel ssh_execute_command → all succeed
  - Config reload during active request → graceful
  - Rapid session create/destroy → no leaks
```

### Acceptance Criteria
- File transfer tools have integration tests (download + upload)
- At least one API-key auth flow tested end-to-end
- At least one network-auth flow tested end-to-end
- At least one SSH connection failure scenario tested
- At least one command timeout scenario tested
- All integration tests pass in Docker environment
