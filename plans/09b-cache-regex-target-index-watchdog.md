# 09b - Cache Compiled Regex, Build Target Index, Replace Polling with Watchdog

**Parent Plan**: [09-performance-bottlenecks.md](plans/09-performance-bottlenecks.md)

## Objective
Cache compiled regex patterns in AuthorizationManager, build an O(1) target name index in ConfigManager, and replace mtime polling with event-driven config watching using `watchdog`.

## Implementation Steps
1. Cache compiled regex in `AuthorizationManager`:
   - On `update_rules()`, compile all block patterns to `list[re.Pattern]`
   - On `_check_block_patterns()`, iterate pre-compiled patterns
2. Build target name index in `ConfigManager`:
   - Add `self._targets_by_name: dict[str, SSHTarget]`
   - Populate on config load/reload
   - `get_target(name)` returns `self._targets_by_name.get(name)`
3. Replace polling watcher with `watchdog`:
   - Add `watchdog` to requirements
   - Create `lib/config_watcher.py` with `FileChangeHandler(watchdog.events.FileSystemEventHandler)`
   - `on_modified(event)` → debounce 2s → reload config
   - Fall back to polling if `watchdog` unavailable
   - `ConfigManager.start_watcher()` starts observer, `stop_watcher()` stops
4. Add debounce to config reload: ignore changes within 2s of last reload
5. Thread pool executor for SSH: use `concurrent.futures.ThreadPoolExecutor` in `create_app()` for non-blocking SSH operations

## Dependencies
- Task 01a (SSHClientManager), 02a (constants)

## Acceptance Criteria
- Block patterns compiled once, not per-request
- Target lookup is O(1) via dict
- Config reload is event-driven with `watchdog`
- 2-second debounce on config changes
- Falls back to polling if watchdog unavailable
