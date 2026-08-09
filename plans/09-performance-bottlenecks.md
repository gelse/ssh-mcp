# 09 - Performance & Bottlenecks

## Current State Analysis

### Request Flow & Latency Sources

```
MCP Request
  → RequestContextMiddleware (negligible)
  → Tool handler
    → extract_client_ip() (negligible)
    → get_api_key() (negligible)
    → config_manager.get_target() (O(n) list scan, small n)
    → auth_manager.check_command() (O(n) block patterns + rules scan)
    → get_ssh_client() (network: TCP connect + SSH handshake)
    → client.exec_command() (network: command execution)
    → stdout.read() (network: output transfer)
    → logger.write() (disk I/O)
    → client.close() (network: SSH disconnect)
```

### Performance Issues Identified

#### 1. SSH Connection Per Request — Major Bottleneck
Every `ssh_execute_command`, `ssh_download_file`, and `ssh_upload_file` call creates a new SSH connection, executes one operation, then closes it. SSH handshake involves:
- TCP 3-way handshake
- Key exchange (cryptographic, CPU-intensive)
- User authentication
- Session channel setup

For rapid tool calls, this adds ~100-500ms overhead per call. A connection pool would reduce this to near-zero.

#### 2. `config_manager.get_target()` — Linear Scan
[`lib/config.py`](lib/config.py:1): Iterates over `ssh_targets` list to find by name. With few targets this is negligible, but no index exists. If the target list grows to hundreds, this becomes O(n) per request.

#### 3. `check_command()` — Linear Pattern Scan
[`lib/auth.py`](lib/auth.py:1): Block patterns are checked sequentially. Each pattern is a regex that must be compiled and matched. For large rule sets (hundreds of patterns), this could be slow.

#### 4. Block Pattern Re-Compilation
[`lib/config.py`](lib/config.py:1): Block patterns are validated as valid regex during config load, but auth.py re-compiles them each time `check_command()` is called (or per-request). Compiled regex objects should be cached.

#### 5. No Persistent SSH Sessions
Paramiko supports persistent `SSHClient` connections and multiplexed channels via `transport.open_session()`. The current pattern is `connect → exec_command → close`, which maximizes connection overhead.

#### 6. No Output Streaming
[`ssh_execute_command()`](server.py:190): Reads entire stdout and stderr into memory before returning. For large outputs approaching `max_command_output` (50KB default), this works. But there's no streaming option for clients that want incremental output.

#### 7. Synchronous I/O Throughout
All operations are synchronous (blocking):
- SSH connections block the async event loop (or thread pool)
- File I/O blocks
- Config reads block

FastMCP uses Starlette/ASGI which can handle async, but the entire tool call chain is synchronous.

#### 8. Config Watcher Polling
[`lib/config.py`](lib/config.py:1): Polls `os.path.getmtime()` every 15 seconds. For configs that change rarely, this is wasted I/O. Inotify/watchdog would be event-driven.

### Performance Improvement Recommendations

1. **SSH Connection Pool**
   - Implement `SSHConnectionPool` with per-target connection reuse
   - Connection lifecycle: idle timeout (configurable, e.g., 300s), max connections per target
   - Health check: test connection before reuse (exec `true` or send keepalive)
   - Auto-reconnect on connection loss
   - Thread-safe pool with `threading.Lock`

2. **Cache Compiled Regex Patterns**
   - Store compiled `re.Pattern` objects in `AuthorizationManager` at init
   - Recompile only on config reload
   - Cache command segmentation regex

3. **Build Target Name Index**
   - `ConfigManager` should maintain `dict[str, SSHTarget]` alongside the list
   - O(1) target lookup instead of O(n)

4. **Pre-Compile Auth Patterns**
   - On config load/reload, compile all block pattern regexes once
   - Store as list of `re.Pattern` objects in AuthorizationManager
   - Rebuild on every config change notification

5. **Move SSH Operations to Thread Pool**
   - Use `concurrent.futures.ThreadPoolExecutor`
   - Submit SSH operations to avoid blocking the ASGI event loop
   - Configure pool size based on expected concurrency

6. **Add Command Output Streaming Option**
   - Accept `stream: bool` parameter in `ssh_execute_command`
   - If streaming, yield output chunks as they arrive
   - Requires MCP streaming response support (check FastMCP capabilities)

7. **Replace Config Polling with Inotify**
   - Use `watchdog` library for event-driven config reload
   - Eliminates 15-second polling delay and unnecessary stat calls
   - Falls back to polling if inotify unavailable

8. **Benchmark Suite**
   - Add `tests/benchmarks/` directory
   - Measure: SSH connection setup time, auth check time, tool call latency
   - Run as part of CI to detect regressions

### Acceptance Criteria
- SSH connections reused via connection pool with configurable idle timeout
- Auth patterns compiled once and cached
- Target lookup is O(1) via dict index
- Config reload is event-driven (watchdog with polling fallback)
- Benchmark suite measures latency for key operations
- No regression in tool call latency under load
