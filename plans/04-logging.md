# Plan 04: Structured Logging

## Master Plan — contains all context needed for implementation

---

## Overview

Implement structured, file-based logging with an abstraction layer that allows swapping log targets (file, syslog, Graylog, etc.) in the future. For now, only file logging is implemented. Logs capture: timestamp, source IP, command, allowed yes/no, and the reason for the decision.

## Design Principle: Pluggable Logging Backend

The logging system uses a **strategy pattern** so the backend can be swapped without changing the logging interface:

```
                    ┌─────────────────────┐
                    │    Logger (ABC)      │
                    │   (lib/logging.py)   │
                    ├─────────────────────┤
                    │ + log_access(entry)  │
                    │ + log_config_change()│
                    │ + log_error(entry)   │
                    └─────────┬───────────┘
                              │  implements
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼──────┐ ┌─────▼──────┐ ┌──────▼──────────┐
    │ FileLogger     │ │ SyslogLogger│ │ GraylogLogger   │
    │ (implemented)  │ │ (future)    │ │ (future)        │
    └────────────────┘ └────────────┘ └─────────────────┘
```

Only `FileLogger` is implemented now. The abstract base class defines the interface for future backends.

## Log Entry Schema

All log entries are JSON objects (one per line for file logging — JSONL format for easy parsing by log aggregators).

### Access log entry (command execution attempt)

```json
{
  "timestamp": "2026-08-05T09:13:50.184Z",
  "event": "command_execution",
  "source_ip": "10.42.43.78",
  "api_key_name": "monitoring-service",
  "command": "docker ps",
  "server_name": "knubbel",
  "allowed": true,
  "reason": "allowed by API key monitoring-service",
  "matched_via": "api_key:monitoring-service",
  "execution_time_ms": 234,
  "exit_code": 0
}
```

Fields:
| Field | Type | Always present? | Description |
|-------|------|-----------------|-------------|
| `timestamp` | ISO8601 string | Yes | When the request was processed |
| `event` | string | Yes | Event type: `command_execution`, `config_reload`, `startup`, `error` |
| `source_ip` | string | Yes | Client IP (from `X-Forwarded-For` or direct) |
| `api_key_name` | string|null | Yes | Matched API key name, or `null` if none |
| `command` | string | Yes (for command_execution) | The command that was requested |
| `server_name` | string | Yes (for command_execution) | Target SSH server name |
| `allowed` | boolean | Yes | Whether execution was permitted |
| `reason` | string | Yes | Human-readable reason |
| `matched_via` | string | Yes | Machine-readable: `default`, `api_key:<name>`, `network:<name>`, `blocked:<pattern>`, `denied` |
| `execution_time_ms` | int|null | Only if allowed=true | How long the SSH command took |
| `exit_code` | int|null | Only if allowed=true | Exit code of the remote command |

**CRITICAL PRIVACY RULE**: Never log the raw API key value. Only log `api_key_name` (the human-readable name from config). If an unknown API key is provided, log `api_key_name: "unknown"` — never the key itself.

### Config reload log entry

```json
{
  "timestamp": "2026-08-05T09:15:00.000Z",
  "event": "config_reload",
  "success": true,
  "message": "Configuration reloaded successfully"
}
```

### Startup log entry

```json
{
  "timestamp": "2026-08-05T09:00:00.000Z",
  "event": "startup",
  "config_dir": "/config",
  "log_dir": "/logs",
  "version": "1.0.0"
}
```

## Logging Module

**File**: [`lib/logging.py`](lib/logging.py) — note: this shadows Python's built-in `logging` module within the `lib` package, but that's acceptable since we use `from lib.logging import ...` explicitly. To avoid confusion, the file could be named `lib/loggers.py` instead.

**Decision**: Name it [`lib/loggers.py`](lib/loggers.py) to avoid shadowing the stdlib `logging` module.

### Abstract Base Class: `BaseLogger`

```python
from abc import ABC, abstractmethod

class BaseLogger(ABC):
    """Abstract interface for log backends."""
    
    @abstractmethod
    def log(self, entry: dict) -> None:
        """Write a log entry."""
        ...
    
    @abstractmethod
    def close(self) -> None:
        """Flush and close the log backend."""
        ...
```

### Concrete Class: `FileLogger`

```python
class FileLogger(BaseLogger):
    """
    JSONL file logger.
    Writes one JSON object per line to a daily-rotating log file.
    """
    
    def __init__(self, log_dir: str, max_file_size_mb: int = 10, backup_count: int = 5):
        """
        Args:
            log_dir: Directory for log files
            max_file_size_mb: Max size before rotation
            backup_count: Number of rotated files to keep
        """
        ...
    
    def log(self, entry: dict) -> None:
        """Append a JSON line to the current log file. Thread-safe."""
        ...
    
    def close(self) -> None:
        """Flush and close the file handle."""
        ...
```

### Log file naming

- Active log: `<log_dir>/ssh-mcp.log`
- Rotated: `<log_dir>/ssh-mcp.log.1`, `<log_dir>/ssh-mcp.log.2`, etc.
- Rotation: when file exceeds `max_file_size_mb`, rotate (simple `RotatingFileHandler`-style)

### Thread Safety

The `FileLogger.log()` method must be thread-safe since multiple requests may arrive concurrently. Use `threading.Lock` around file write operations.

## Integration Points

### In [`server.py`](server.py) — `ssh_execute_command` handler

```python
@mcp.tool()
def ssh_execute_command(server_name: str, command: str, timeout: int = 30) -> str:
    # 1. Extract client identity (source_ip, api_key)
    # 2. Auth check via auth_manager.check_command(...)
    # 3. Log the attempt IMMEDIATELY (before execution)
    
    log_entry = {
        "timestamp": utcnow_iso(),
        "event": "command_execution",
        "source_ip": source_ip,
        "api_key_name": api_key_name,
        "command": command,
        "server_name": server_name,
        "allowed": auth_result.allowed,
        "reason": auth_result.reason,
        "matched_via": auth_result.matched_via,
    }
    
    if not auth_result.allowed:
        logger.log(log_entry)
        return f"ERROR: Command '{command}' is not allowed."
    
    # 4. Execute command, measure time
    start = time.monotonic()
    result = execute_ssh_command(...)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    
    # 5. Augment and write final log entry
    log_entry["execution_time_ms"] = elapsed_ms
    log_entry["exit_code"] = exit_code_from_result
    logger.log(log_entry)
    
    return result
```

### Config reload logging (from Plan 02's ConfigManager)

When `ConfigManager` detects a config file change and reloads:
```python
logger.log({
    "timestamp": utcnow_iso(),
    "event": "config_reload",
    "success": True,
    "message": "Configuration reloaded successfully"
})
```

On validation failure:
```python
logger.log({
    "timestamp": utcnow_iso(),
    "event": "config_reload",
    "success": False,
    "message": f"Config validation failed: {error}"
})
```

### Startup logging

On server startup, after config and logger are initialized:
```python
logger.log({
    "timestamp": utcnow_iso(),
    "event": "startup",
    "config_dir": str(config_dir),
    "log_dir": str(log_dir),
})
```

## Files to Create/Modify

### New files

| File | Purpose |
|------|---------|
| [`lib/loggers.py`](lib/loggers.py) | `BaseLogger` ABC and `FileLogger` implementation |
| [`tests/test_loggers.py`](tests/test_loggers.py) | Unit tests for FileLogger |

