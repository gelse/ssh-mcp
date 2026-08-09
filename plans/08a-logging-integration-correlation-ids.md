# 08a - Integrate with Python logging Module & Add Correlation IDs

**Parent Plan**: [08-logging-observability.md](plans/08-logging-observability.md)

## Objective
Create a `logging.Handler` that writes to `FileLogger`, add correlation IDs to all log entries, and expand log event types across the full request lifecycle.

## Implementation Steps
1. Create `lib/log_handler.py` with `JSONLHandler(logging.Handler)`:
   - Override `emit(record)` to format log record as JSONL and write to `FileLogger`
   - Map Python log levels to structured `level` field
   - Include `logger_name`, `module`, `funcName` from log record
2. Configure root logger in `create_app()` to use `JSONLHandler`
3. Add correlation ID to `lib/request_context.py`:
   - `_request_id: ContextVar[str]` — UUID generated per request in middleware
   - `get_request_id() -> str` — returns ID or "unknown"
4. Update all log calls to include `request_id` from context
5. Expand log events across lifecycle:
   - `auth.check` / `auth.deny` — on every authorization check
   - `ssh.connect` / `ssh.disconnect` — on connection lifecycle
   - `file.download` / `file.upload` — on transfer operations
   - `config.reload` — on config changes
   - `health.check` — on health endpoint access
6. Add `log_level` field to all JSONL entries
7. Add `log_format_version: 1` to all entries

## Dependencies
- Task 01c (factory pattern), 03a/03b (middleware context)

## Acceptance Criteria
- Third-party library logs (uvicorn, paramiko) captured in JSONL format
- Every log entry has `request_id` field
- Auth, SSH, file transfer, config reload, and health events all logged
- Log level filtering via config settings
- Log format version field present
