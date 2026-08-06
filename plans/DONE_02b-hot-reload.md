# Plan 02b: Hot-Reload Watcher — Polling Thread & Thread Safety

## Parent: [Plan 02 — External Config File with Watching](plans/02-config-file.md)
## Dependency: [Plan 02a — ConfigManager Core](plans/02a-config-core.md)

---

## Scope

This sub-plan adds the **background polling watcher** to [`lib/config.py`](lib/config.py):
- A daemon thread that polls `os.path.getmtime()` every 15 seconds
- Hot-reload: detect changes → reload → swap or keep
- Graceful startup/shutdown of the watcher
- Thread safety for concurrent access to config data

**Requires**: `ConfigManager.load()`, `ConfigManager.reload()`, and `ConfigManager._validate()` from Plan 02a to already exist.

**Out of scope**: Server.py integration (→ Plan 02c), migration/cleanup (→ Plan 02d).

---

## Implementation: Additions to [`lib/config.py`](lib/config.py)

### New Methods on `ConfigManager`

```python
class ConfigManager:
    # ... existing methods from Plan 02a ...
    
    def start_watcher(self, polling_interval: float = 15.0) -> None:
        """
        Start the background polling thread for hot-reload.
        
        Spawns a daemon thread that checks os.path.getmtime()
        of the config file every `polling_interval` seconds.
        If modification time changed since last load, calls reload().
        
        Idempotent: calling multiple times has no effect if already running.
        """
        ...
    
    def stop_watcher(self) -> None:
        """
        Stop the background polling thread gracefully.
        
        Signals the thread to exit via a threading.Event and joins
        with a timeout. Safe to call if watcher was never started.
        """
        ...
    
    @property
    def watcher_running(self) -> bool:
        """Return True if the watcher thread is currently active."""
        ...
```

### New Instance Variables (in `__init__`)

```python
self._watcher_thread: threading.Thread | None = None
self._watcher_stop_event = threading.Event()
self._last_mtime: float = 0.0  # Track last known mtime
```

---

### `start_watcher()` Flow

```
start_watcher(polling_interval=15.0):
  1. If self._watcher_thread is not None and is_alive():
       return (idempotent, already running)
  2. Clear self._watcher_stop_event
  3. Record current mtime: self._last_mtime = os.path.getmtime(self._config_path)
  4. Create threading.Thread(target=self._watcher_loop, args=(polling_interval,))
  5. Set thread.daemon = True (won't block process exit)
  6. Set thread name = "config-watcher"
  7. Start thread
  8. Store reference in self._watcher_thread
```

### `_watcher_loop()` Flow (internal)

```
_watcher_loop(polling_interval):
  1. While not self._watcher_stop_event.is_set():
     a. Sleep for polling_interval seconds, checking stop_event periodically
        (use self._watcher_stop_event.wait(timeout=polling_interval))
     b. If stop_event is set during wait → break
     c. Try:
          - Check if config file exists (it might have been deleted)
          - If not exists: log warning, continue (don't crash)
          - current_mtime = os.path.getmtime(self._config_path)
          - If current_mtime != self._last_mtime:
              - Log "Config file changed, reloading..."
              - success = self.reload()
              - If success:
                  - self._last_mtime = current_mtime
                  - Log "Config reloaded successfully"
              - Else:
                  - Log "Config reload failed, keeping previous config"
                  - Do NOT update self._last_mtime (will retry next poll)
        except Exception as e:
          - Log exception with traceback
          - Continue loop (don't crash the watcher)
```

### `stop_watcher()` Flow

```
stop_watcher():
  1. Set self._watcher_stop_event
  2. If self._watcher_thread is not None and is_alive():
       - Join with timeout of polling_interval + 5 seconds
       - If thread still alive after timeout: log warning
  3. Set self._watcher_thread = None
```

---

### Thread Safety Details

The `ConfigManager` uses `threading.Lock` (already introduced in Plan 02a) to protect:
- `self._data` — read/written by `load()`, `reload()`, and the `data` property
- `self._last_mtime` — read/written by the watcher loop and `load()`/`reload()`
- `self._watcher_thread` — checked by `start_watcher()` and `stop_watcher()`

All public read methods (`data`, `get_ssh_target`, `list_ssh_targets`) acquire the lock for reading. All write operations (`load`, `reload`) acquire the lock for writing.

---

### Watcher Interaction with `load()` and `reload()`

- `load()` is called once during `__init__`. It sets `self._last_mtime` after successful load.
- `reload()` is called by the watcher loop when mtime changes. It does NOT update `self._last_mtime` — that's the watcher loop's responsibility (so it can decide whether to retry on failure).
- Alternative: `reload()` could update `self._last_mtime` only on success. The watcher loop then simply checks `current_mtime != self._last_mtime`. This is simpler and preferred.

**Preferred approach**: `reload()` updates `self._last_mtime = os.path.getmtime(self._config_path)` on success, inside the lock. The watcher loop only needs to compare mtimes.

---

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| [`lib/config.py`](lib/config.py) | **Modify** | Add `start_watcher()`, `stop_watcher()`, `_watcher_loop()`, `watcher_running` property, and related instance variables |
| [`tests/test_config.py`](tests/test_config.py) | **Modify** | Add tests for watcher functionality |

---

## Implementation Steps

1. Add instance variables to `ConfigManager.__init__`:
   - `self._watcher_thread = None`
   - `self._watcher_stop_event = threading.Event()`
   - `self._last_mtime = 0.0`

2. Implement `_watcher_loop(polling_interval)` — the core polling logic with mtime comparison

3. Implement `start_watcher(polling_interval=15.0)` — spawn daemon thread, idempotent

4. Implement `stop_watcher()` — signal + join with timeout

5. Implement `watcher_running` property

6. Update `load()` to set `self._last_mtime` after successful load

7. Update `reload()` to update `self._last_mtime` on success (inside lock)

8. Add tests to [`tests/test_config.py`](tests/test_config.py):
   - Test: `start_watcher()` spawns a thread and `watcher_running` returns True
   - Test: `start_watcher()` is idempotent (calling twice doesn't create two threads)
   - Test: `stop_watcher()` stops the thread and `watcher_running` returns False
   - Test: `stop_watcher()` is safe to call when watcher was never started
   - Test: Modifying the config file on disk triggers reload (write new valid config, wait up to 2× polling_interval, verify `data` updated)
   - Test: Modifying the config file with invalid content does NOT change `data` (old config preserved)
   - Test: Deleting the config file while watcher is running does not crash (logs warning, continues)
   - Test: `reload()` updates `_last_mtime` on success
   - Test: `reload()` does NOT update `_last_mtime` on failure

9. Run tests: `python -m pytest tests/test_config.py -v`

---

## Self-Test Criteria

After implementing this sub-plan, the following must be true:

- [ ] `start_watcher()` spawns a background daemon thread
- [ ] Modifying the config file on disk causes automatic reload within 2× polling interval
- [ ] Invalid config changes are rejected; the previous valid config remains active
- [ ] `stop_watcher()` cleanly shuts down the watcher thread
- [ ] The watcher does not block process exit (daemon thread)
- [ ] Concurrent reads of `data` during a reload do not raise exceptions
- [ ] All watcher-related unit tests pass
