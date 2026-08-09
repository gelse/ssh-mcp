# 07b - Add Retry, Circuit Breaker, and Graceful Degradation

**Parent Plan**: [07-error-handling-resilience.md](plans/07-error-handling-resilience.md)

## Objective
Implement exponential backoff retry for transient SSH errors, circuit breaker per target to prevent hammering dead servers, and graceful degradation for logger failures.

## Implementation Steps
1. Add retry to `SSHClientManager.create_client()`:
   - Only for transient errors: `SSHTimeoutError`, `socket.error`, connection refused
   - NOT for auth failures or authorization errors
   - Configurable: `settings.retry_max_attempts` (default 3), `settings.retry_backoff_base_seconds` (default 1.0)
   - Exponential backoff with jitter: `backoff = base * 2^attempt + random(0, base)`
2. Create `lib/circuit_breaker.py` with `CircuitBreaker` class:
   - Per-target state: CLOSED → OPEN (after N failures) → HALF_OPEN (after timeout)
   - Configurable: `circuit_breaker_failure_threshold` (default 5), `circuit_breaker_timeout_seconds` (default 60)
   - `__call__(target_name)` returns True if request should proceed
   - `record_success(target_name)` / `record_failure(target_name)`
3. Integrate circuit breaker into `SSHClientManager.connect()` context manager
4. Add graceful degradation to `FileLogger.write()`:
   - On write failure, emit to `sys.stderr` via `logging` module
   - Track consecutive failures; reset on success
   - Log recovery event when file writes resume
5. Add watcher health: expose `last_reload_timestamp`, `last_error`, `healthy` status

## Dependencies
- Task 07a (exceptions), 01a (SSHClientManager)

## Acceptance Criteria
- Retry with exponential backoff for transient SSH errors
- Circuit breaker opens after N consecutive failures per target
- Half-open probe after timeout succeeds → closes circuit
- Logger falls back to stderr on write failure
- Watcher status exposed and testable
