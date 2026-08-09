"""Watchdog-based config file change handler for hot-reload.

Provides :class:`FileChangeHandler`, a
:class:`watchdog.events.FileSystemEventHandler` subclass that triggers a
config reload when the SSH MCP config file is modified.  The ``watchdog``
import is guarded so the module can be imported (and the polling fallback
used) even when ``watchdog`` is not installed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

try:
    from watchdog.events import FileSystemEventHandler
except ImportError:  # pragma: no cover - exercised when watchdog is absent
    FileSystemEventHandler = object


class FileChangeHandler(FileSystemEventHandler):
    """Handle filesystem events for the SSH MCP config file.

    Subclasses :class:`watchdog.events.FileSystemEventHandler` so the
    watchdog observer dispatches modification events to
    :meth:`on_modified`.  Each event is filtered to the exact config
    file, debounced, and then triggers the reload callback.

    Args:
        config_path: Path to ``ssh-mcp-config.json`` (the only file whose
            modification triggers a reload).
        reload_callback: Zero-argument callable that re-reads and
            validates the config (e.g. ``ConfigManager.reload``).
        debounce_callback: Zero-argument callable returning ``True`` when
            the change arrived within the debounce window and should be
            ignored.
        logger: Optional :class:`logging.Logger`; defaults to the module
            logger.
    """

    def __init__(
        self,
        config_path: Path,
        reload_callback,
        debounce_callback,
        logger=None,
    ):
        self._config_path = Path(config_path)
        self._reload_callback = reload_callback
        self._debounce_callback = debounce_callback
        self._logger = logger or logging.getLogger(__name__)

    def on_modified(self, event) -> None:
        """Reload the config when the config file itself is modified.

        Directory events and events for other paths are ignored, as are
        changes that fall inside the debounce window (so a burst of
        filesystem events from a single edit coalesces into one reload).
        """
        if event.is_directory:
            return
        if os.path.abspath(event.src_path) != os.path.abspath(str(self._config_path)):
            return
        if self._debounce_callback():
            self._logger.info(
                "Config change within debounce window — skipping reload"
            )
            return
        self._logger.info("Config file changed, reloading...")
        self._reload_callback()
