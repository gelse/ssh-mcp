# 12 - Concurrency & Thread Safety

## Current State Analysis

### Concurrency Model

The application uses two concurrency mechanisms:
1. **FastMCP/Starlette**: ASGI server (likely Uvicorn) handling multiple HTTP requests concurrently
2. **Config Watcher Thread**: Background `threading.Thread` polling for config changes every 15 seconds

### Thread Safety Analysis by Component

#### `lib/config.py` — ConfigManager ✓
- Uses `threading.Lock` for write operations (reload)
- Reads are lock-free but operate on an atomic reference swap:
  ```python
  with self._lock:
      self._config = new_config  # atomic in CPython due to GIL
  ```
- `get_target()` reads `self._config` without lock — safe for dict access but could see stale data briefly
- **Verdict**: Safely thread-safe for read-heavy workload

#### `lib/loggers.py` — FileLogger ✓
- `threading.Lock` around all write operations
- Rotation is done under lock
- **Verdict**: Correctly thread-safe

#### `lib/auth.py` — AuthorizationManager ⚠
- `check_command()` calls `_split_command_segments()` which creates new objects each call
- No mutable shared state — reads `self.block_patterns` which is a list reference
- `list_allowed_commands()` reads `self.api_keys` and `self.networks`
- **Verdict**: Thread-safe by immutability, but no explicit guarantee. If config reload replaces patterns mid-check, could see mixed state.

#### `server.py` — Module-Level State ⚠
- `config_manager` and `auth_manager` are module globals
- `get_ssh_client()` creates a new `paramiko.SSHClient` per call (no shared state) ✓
- `get_api_key()` reads from request context (ContextVar, request-scoped) ✓
- `_extract_client_ip()` reads from request context ✓
- **Verdict**: Mostly thread-safe but globals make it fragile

### Issues Identified

#### 1. Auth Manager Receives Partial Updates
When `config_manager.reload()` updates config, it calls `auth_manager.update_rules()`. If another thread is executing `check_command()`, it could see:
- Old block patterns + new allowed commands
- New block patterns + old allowed commands
This is because `update_rules()` sets attributes one at a time, not atomically.

#### 2. No Atomic Config Swap in Auth Manager
[`auth_manager.update_rules()`](lib/auth.py) likely updates individual attributes:
```python
def update_rules(self, config):
    self.block_patterns = config["block_patterns"]
    self.default_allowed = config["allowed_commands"]["default"]
    self.api_keys = config["api_keys"]
    self.networks = config["allowed_commands"].get("networks", {})
```
Between these assignments, `check_command()` sees a partially-updated state. This should be an atomic swap.

#### 3. SSH Client Not Thread-Safe for Connection Pooling
If SSH connection pooling is implemented (see Performance plan), `paramiko.SSHClient` instances are not thread-safe for concurrent use. Each connection must be used by one thread at a time, or channels must be used.

#### 4. Config Watcher Thread Not a Daemon
The watcher thread in [`lib/config.py`](lib/config.py:1) should be a daemon thread so it doesn't prevent clean shutdown. Verify it's `daemon=True`.

#### 5. No Shutdown Synchronization
No mechanism to:
- Signal the watcher thread to stop
- Wait for pending operations to complete
- Clean up SSH connections on shutdown

If the server receives SIGTERM, active SSH connections may leak.

#### 6. ContextVar Usage is Correct but Unclear
[`lib/request_context.py`](lib/request_context.py:1) uses `ContextVar` correctly per-request. However, `get_current_request()` can return `None` and callers don't consistently handle it.

#### 7. No Limitation on Concurrent SSH Connections
The application will create as many simultaneous SSH connections as there are concurrent requests. This could:
- Exhaust file descriptors
- Overwhelm SSH target servers
- Cause resource starvation

#### 8. FileLogger Rotation During Concurrent Writes
Rotation is done under lock, but if many threads are queued waiting for the lock during rotation (which does file I/O), it could cause latency spikes.

### Thread Safety Improvements

1. **Atomic Auth Manager Updates**
   - Accept a complete config snapshot object
   - Build all internal state from the snapshot
   - Swap in a single atomic assignment
   - Or use a read-write lock during update

2. **Config Change Notification System**
   - `ConfigManager` maintains a list of callbacks
   - On reload, atomically prepare new state, then notify all callbacks
   - AuthManager is one subscriber, connection pool is another

3. **Graceful Shutdown**
   - Add `shutdown()` method to main app
   - Signal watcher thread to stop
   - Close all SSH connections in pool
   - Close log file
   - Wait for pending requests (with timeout)

4. **Concurrency Limits**
   - `max_concurrent_ssh_connections` setting
   - Semaphore-based limiting
   - Queue overflow handling (reject with 503)

5. **Document Thread Safety Guarantees**
   - Python `@dataclass(frozen=True)` for immutable config snapshots
   - Explicit thread-safety notes in docstrings
   - `threading.Lock` usage documented with what it protects

6. **Test Concurrent Scenarios**
   - Concurrent config reload + auth check
   - Concurrent log writes during rotation
   - Concurrent SSH connections to multiple targets
   - Stress test with many concurrent requests

### Acceptance Criteria
- Auth manager uses atomic config snapshots, never partial state
- Watcher thread is a daemon thread
- Graceful shutdown closes all resources
- Configurable limit on concurrent SSH connections
- Thread-safety guarantees documented in docstrings
- Concurrent stress tests pass without data races
