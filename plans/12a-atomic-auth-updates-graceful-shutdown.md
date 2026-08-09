# 12a - Atomic Auth Manager Updates & Graceful Shutdown

**Parent Plan**: [12-concurrency-thread-safety.md](plans/12-concurrency-thread-safety.md)

## Objective
Make `AuthorizationManager` accept complete config snapshots atomically instead of updating individual attributes, implement graceful shutdown with resource cleanup, and add concurrency limits for SSH connections.

## Implementation Steps
1. Refactor `AuthorizationManager.update_rules()` to accept a complete config snapshot:
   - Build all internal state (block patterns, compiled regex, api keys, network rules) in a single method
   - Store as immutable state object: `_rules: RulesSnapshot` (frozen dataclass)
   - Swap `self._rules = new_rules` atomically
   - All read methods access `self._rules` (single reference read)
2. Add `ConfigManager.on_change(callback)` registration:
   - Maintain list of callbacks
   - On reload, prepare new state, then call all callbacks with new config
3. Implement graceful shutdown:
   - Add `create_app().shutdown()` method
   - Signal config watcher thread to stop (via `threading.Event`)
   - Close all SSH connections in pool
   - Close log file
   - Wait for pending requests with timeout (default 30s)
4. Add concurrency limits:
   - `max_concurrent_ssh_connections` setting (default: 20)
   - `threading.Semaphore` in `SSHConnectionPool`
   - Return 503 Service Unavailable when limit reached
5. Make watcher thread a daemon thread (verify or fix)
6. Add concurrent stress tests:
   - 50 concurrent auth checks during config reload
   - 50 concurrent log writes during rotation
   - Rapid config changes during active SSH connections

## Dependencies
- Task 09a (connection pool), 07b (circuit breaker)

## Acceptance Criteria
- Auth rules swapped atomically, no partial state visible
- Config change callbacks fire after atomic update
- Graceful shutdown releases all resources
- Concurrent SSH connections limited with clear error
- Watcher thread is daemon=True
- Concurrent stress tests pass without data races
