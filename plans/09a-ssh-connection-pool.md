# 09a - Implement SSH Connection Pool

**Parent Plan**: [09-performance-bottlenecks.md](plans/09-performance-bottlenecks.md)

## Objective
Implement an SSH connection pool with per-target connection reuse, idle timeout, connection health checking, and auto-reconnect.

## Implementation Steps
1. Create `lib/connection_pool.py` with `SSHConnectionPool` class:
   - `__init__(self, ssh_client_manager, max_connections_per_target=5, idle_timeout_seconds=300)`
   - `get_connection(target_name) -> SSHClient` — returns existing or new connection
   - `return_connection(target_name, client)` — returns to pool (if healthy)
   - `_health_check(client) -> bool` — sends keepalive/exec true to verify
   - `_cleanup_idle()` — removes connections idle > timeout
2. Per-target pool: `dict[str, deque[PooledConnection]]`
3. `PooledConnection` dataclass with `client`, `created_at`, `last_used_at`
4. Thread safety with `threading.Lock` per target
5. Background thread for idle cleanup (runs every 60s)
6. Update `SSHClientManager.connect()` to use pool instead of new connection
7. Add `_return_to_pool()` call in context manager `__exit__`
8. Add pool stats: `active_connections`, `idle_connections`, `total_created`
9. Expose pool stats in health endpoint and Prometheus metrics

## Dependencies
- Task 01a (SSHClientManager), 02b (context manager)

## Acceptance Criteria
- Same target reuses connection within idle timeout
- Connections checked for health before reuse
- Idle connections cleaned up after timeout
- Pool size limits enforced per target
- Thread-safe concurrent access
- Pool stats exposed in health + metrics
