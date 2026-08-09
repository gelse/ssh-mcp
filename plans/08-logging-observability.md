# 08 - Logging & Observability

## Current State Analysis

### Logging Infrastructure

[`lib/loggers.py`](lib/loggers.py:1) provides:
- `BaseLogger` ABC with `write()`, `info()`, `error()`, `close()` interface
- `FileLogger` implementation with JSONL output and size-based rotation
- Thread-safe writes via `threading.Lock`

### Log Entry Structure
```json
{
  "timestamp": "2024-01-01T00:00:00.000000+00:00",
  "event": "command_result",
  "server_name": "web-01",
  "command": "echo hello",
  "command_segments": ["echo hello"],
  "authorized": true,
  "matched_via": "default",
  "api_key_name": null,
  "client_ip": "192.168.1.1",
  "exit_code": 0,
  "output": "hello\n",
  "output_length": 6,
  "duration_ms": 123.45
}
```

### Positive Aspects
- Structured JSONL format — easily parseable by log aggregators (Loki, ELK)
- Rich metadata: timestamps with timezone, duration, authorization details
- Size-based rotation with configurable backup count
- Thread-safe design is correct for JSONL (line-based writes)
- Unicode support via `ensure_ascii=False`

### Issues Identified

#### 1. Missing Standard Logging Integration
The custom `BaseLogger`/`FileLogger` does not integrate with Python's `logging` module. This means:
- No `logging.getLogger()` compatibility
- No standard log level filtering (DEBUG, INFO, WARNING, ERROR)
- Third-party libraries (FastMCP, Paramiko) can't use the same log sink
- No way to capture uvicorn/starlette access logs in the same format

#### 2. No Request Tracing
- No correlation ID / request ID in log entries
- Cannot trace a single MCP request through authorization → SSH connection → command execution → result
- Multiple concurrent requests produce interleaved log lines with no way to group them

#### 3. Only Two Log Events
Currently only logs `command_result` and `startup` events. Missing:
- SSH connection attempts (success/failure)
- File transfer operations
- Authorization decisions (especially denials)
- Config reload events
- Health check access
- Server errors with stack traces

#### 4. No Log Level Support
All log entries use the same structure. No distinction between:
- Debug: detailed SSH protocol negotiation
- Info: normal operations (command execution, file transfer)
- Warning: config reload failure, auth denial, near-limit output
- Error: SSH failure, unexpected exceptions
- Critical: logger failure, unrecoverable config error

#### 5. No Output Truncation for Logs
Command output is logged in full up to `max_command_output`. In the config, `max_command_output` is 50KB default. This means every command result writes up to 50KB to logs. A busy server could fill disk quickly.

#### 6. No Structured Error Logging
Errors are logged as `logger.error(str(e))` which produces unstructured messages. Stack traces are lost. Error context (which target, which command, client IP) must be manually reconstructed.

#### 7. No Metrics/Telemetry
No counters, gauges, or histograms for:
- Request rate per tool
- SSH connection duration distribution
- Authorization deny rate
- Error rate by type
- Active connection count
- Log rotation events

#### 8. Missing Log File Management
- No compression of rotated log files
- No total log directory size management
- No automatic cleanup of very old log files
- No log format version field (breaking changes to log schema are invisible)

### Observability Improvements

1. **Integrate with `logging` Module**
   - Create a `logging.Handler` subclass that writes to `FileLogger`
   - Configure root logger to use this handler
   - Capture uvicorn/FastMCP/Paramiko logs in JSONL format
   - Add log level to JSONL schema

2. **Add Correlation ID**
   - Generate UUID per request in middleware
   - Store in request context
   - Include `request_id` and `session_id` in every log line
   - Pass to SSH operations for end-to-end tracing

3. **Expand Log Events**
   ```
   - request.start     (method, path, client_ip, request_id)
   - request.end       (status_code, duration_ms, request_id)
   - auth.check        (command, result, matched_via, request_id)
   - auth.deny         (command, reason, client_ip, request_id)
   - ssh.connect       (target, duration_ms, request_id)
   - ssh.disconnect    (target, duration_ms, request_id)
   - ssh.error         (target, error_type, message, request_id)
   - command.execute   (target, command, request_id)
   - command.result    (exit_code, output_length, duration_ms, request_id)
   - file.download     (target, path, size, duration_ms, request_id)
   - file.upload       (target, path, size, duration_ms, request_id)
   - config.reload     (success, error_message, request_id)
   - health.check      (client_ip)
   - startup           (version, config_path, targets_count)
   - shutdown          (uptime_seconds)
   ```

4. **Add Log Levels**
   - Extend `BaseLogger` with `debug()`, `warning()`, `critical()`
   - Add `log_level` setting to config
   - Filter log output by level

5. **Separate Log Output Limit**
   - Add `max_log_output` setting (default: 4096 characters)
   - Truncate and mark: `"... [truncated, full output length: 50000 bytes]"`
   - Never lose the metadata, only truncate the content

6. **Add Prometheus Metrics Endpoint**
   - Use `prometheus_client` library
   - Expose counters and histograms on `/metrics`
   - Add to FastMCP via `mcp.custom_route`

7. **Add Log Format Version**
   - Include `"log_format_version": 1` in every log entry
   - Enables log processors to handle format migrations

8. **Compress Rotated Logs**
   - Gzip rotated log files
   - Configurable `compress_rotated` setting

### Acceptance Criteria
- `logging` module integration with JSONL handler
- All log entries include `request_id` for tracing
- All lifecycle events logged (auth, SSH, file transfer, config reload)
- Log levels supported: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Command output truncated separately for logs vs responses
- Rotated logs are gzip-compressed
- Log format version field in every entry
