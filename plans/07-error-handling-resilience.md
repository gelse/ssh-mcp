# 07 - Error Handling & Resilience

## Current State Analysis

### Error Handling Patterns Found

#### 1. Broad `except Exception` in Tool Handlers
[`server.py:247`](server.py:247) catches `Exception` in every tool handler, wrapping all errors in `{"error": str(e)}`. This:
- Masks unexpected bugs as user errors
- Loses stack trace information
- Cannot distinguish transient vs permanent failures
- Prevents proper error categorization in client responses

#### 2. `ValueError` for Domain Errors
Multiple places raise `ValueError` for domain-specific conditions:
- Unknown SSH target
- Invalid server name
- Authentication failures (indirectly)
This is a generic exception type that carries no semantic meaning.

#### 3. `ConfigValidationError` — Good Pattern
[`lib/config.py`](lib/config.py:1) defines a custom `ConfigValidationError` with field-level error tracking. This is the right approach but is the only custom exception in the codebase.

#### 4. Silent Failure in `_extract_client_ip()`
[`server.py:93`](server.py:93): If header parsing fails or `get_current_request()` returns None, falls back to `127.0.0.1` silently. This could:
- Authorize requests that should be denied (loopback may have elevated permissions)
- Mask network misconfiguration

#### 5. Logger Failure Handling
[`lib/loggers.py`](lib/loggers.py:1): FileLogger catches `Exception` broadly during write and silently swallows errors. A logging failure should at minimum emit to stderr as fallback.

#### 6. Config Watcher Error Handling
[`lib/config.py`](lib/config.py:1): The watcher thread catches exceptions during reload but doesn't expose them. If the config file becomes permanently invalid, the watcher silently stops updating.

#### 7. SSH Client Error Propagation
[`get_ssh_client()`](server.py:152): Raises `ValueError` for unknown key types, but lets `paramiko.SSHException`, `socket.error`, `paramiko.AuthenticationException` propagate raw. Callers get Paramiko-specific exceptions they shouldn't need to know about.

#### 8. No Retry Logic
No retry mechanism for:
- Transient SSH connection failures
- Config file read races
- Temporary filesystem errors

#### 9. No Circuit Breaker
If an SSH target is consistently failing, every request still attempts a full connection. No backoff or fast-fail mechanism.

### Resilience Improvements

1. **Custom Exception Hierarchy** (see also Clean Code plan)
```
MCPSSHError (base)
├── ConfigurationError
│   ├── ConfigValidationError (existing)
│   └── ConfigReloadError
├── AuthorizationError
│   ├── CommandBlockedError
│   └── AuthenticationFailedError
├── SSHConnectionError
│   ├── SSHHostUnreachableError
│   ├── SSHAuthenticationError
│   └── SSHTimeoutError
├── FileTransferError
│   ├── PathValidationError
│   └── TransferFailedError
└── InternalError
```

2. **Typed Error Responses**
Tools should return structured errors:
```json
{
  "error": true,
  "error_type": "SSHTimeoutError",
  "message": "Connection to target 'web-01' timed out after 120s",
  "target": "web-01",
  "retryable": true
}
```

3. **Exponential Backoff Retry**
- Add retry with jitter for connection-level errors
- Configurable in settings: `retry_max_attempts`, `retry_backoff_base_seconds`
- Only for transient errors (timeout, connection refused), not auth failures

4. **Circuit Breaker per Target**
- Track failure count per SSH target
- After N consecutive failures, fast-fail for M seconds
- Configurable thresholds

5. **Graceful Degradation on Logger Failure**
- If file logger fails, fall back to `logging` module with stderr handler
- Log the failure as a structured error once logging recovers

6. **Watcher Health Reporting**
- Expose watcher status (healthy/stale/error) via health endpoint or `ssh_list_servers`
- Include last successful reload timestamp
- Include last error message if in error state

7. **Request ID Tracking**
- Assign unique request ID per MCP call
- Include in all log lines and error responses
- Enables end-to-end tracing

### Acceptance Criteria
- All domain errors use custom exception types, not built-in exceptions
- Error responses include error type, message, and retryable flag
- Configurable retry with exponential backoff for transient SSH errors
- Circuit breaker prevents hammering dead targets
- Logger falls back to stderr on write failure
- Watcher status exposed and monitorable
- Request IDs included in all log output
