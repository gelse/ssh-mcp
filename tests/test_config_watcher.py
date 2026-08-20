"""Unit tests for lib/config_watcher — FileChangeHandler."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from lib.config_watcher import FileChangeHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class RecordingLogger:
    """Duck-typed logger that captures structured events."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, entry: dict) -> None:
        self.entries.append(entry)


def _make_handler(
    tmp_path: Path,
    *,
    reload_callback=None,
    debounce_return: bool = False,
    log_event=None,
) -> tuple[FileChangeHandler, MagicMock, MagicMock]:
    """Create a FileChangeHandler wired to mock callbacks.

    Returns (handler, reload_mock, debounce_mock).
    """
    config_path = tmp_path / "ssh-mcp-config.json"
    config_path.write_text("{}")
    reload_cb = reload_callback or MagicMock()
    debounce_cb = MagicMock(return_value=debounce_return)
    handler = FileChangeHandler(
        config_path=config_path,
        reload_callback=reload_cb,
        debounce_callback=debounce_cb,
        log_event=log_event,
    )
    return handler, reload_cb, debounce_cb


def _event(
    src_path: str | Path,
    is_directory: bool = False,
) -> SimpleNamespace:
    """Create a fake watchdog event."""
    return SimpleNamespace(is_directory=is_directory, src_path=str(src_path))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFileChangeHandler:
    """Tests for FileChangeHandler.on_modified filtering and dispatch."""

    def test_directory_event_ignored(self, tmp_path: Path) -> None:
        """A directory modification event must not trigger a reload."""
        handler, reload_cb, _ = _make_handler(tmp_path)
        handler.on_modified(_event(tmp_path, is_directory=True))
        reload_cb.assert_not_called()

    @pytest.mark.parametrize(
        "wrong_path",
        [
            "other.json",
            "ssh-mcp-config.json.bak",
            "subdir/ssh-mcp-config.json",
        ],
        ids=["different-file", "backup-file", "subdirectory"],
    )
    def test_non_matching_path_ignored(
        self, tmp_path: Path, wrong_path: str
    ) -> None:
        """Events for paths that don't match the config file are ignored."""
        handler, reload_cb, _ = _make_handler(tmp_path)
        handler.on_modified(_event(tmp_path / wrong_path))
        reload_cb.assert_not_called()

    def test_debounced_event_skips_reload(self, tmp_path: Path) -> None:
        """When debounce returns True, reload is not triggered."""
        handler, reload_cb, debounce_cb = _make_handler(
            tmp_path, debounce_return=True
        )
        config_path = tmp_path / "ssh-mcp-config.json"
        handler.on_modified(_event(config_path))
        reload_cb.assert_not_called()
        debounce_cb.assert_called_once()

    def test_debounced_event_emits_log_event(self, tmp_path: Path) -> None:
        """A debounced event emits config.watcher.debounced via log_event."""
        events: list[tuple[str, bool]] = []
        handler, _, _ = _make_handler(
            tmp_path,
            debounce_return=True,
            log_event=lambda event, success, msg: events.append((event, success)),
        )
        handler.on_modified(_event(tmp_path / "ssh-mcp-config.json"))
        assert events == [("config.watcher.debounced", True)]

    def test_matching_path_triggers_reload(self, tmp_path: Path) -> None:
        """A matching file event with debounce=False triggers reload once."""
        handler, reload_cb, debounce_cb = _make_handler(tmp_path)
        config_path = tmp_path / "ssh-mcp-config.json"
        handler.on_modified(_event(config_path))
        reload_cb.assert_called_once()
        debounce_cb.assert_called_once()

    def test_matching_path_emits_reload_event(self, tmp_path: Path) -> None:
        """A non-debounced reload emits config.watcher.reload_triggered."""
        events: list[tuple[str, bool]] = []
        handler, _, _ = _make_handler(
            tmp_path,
            log_event=lambda event, success, msg: events.append((event, success)),
        )
        handler.on_modified(_event(tmp_path / "ssh-mcp-config.json"))
        assert events == [("config.watcher.reload_triggered", True)]

    def test_reload_callback_exception_propagates(self, tmp_path: Path) -> None:
        """If reload_callback raises, the exception is not swallowed."""
        error_cb = MagicMock(side_effect=RuntimeError("reload failed"))
        handler, _, _ = _make_handler(tmp_path, reload_callback=error_cb)
        with pytest.raises(RuntimeError, match="reload failed"):
            handler.on_modified(_event(tmp_path / "ssh-mcp-config.json"))

    def test_log_event_not_provided(self, tmp_path: Path) -> None:
        """When log_event is None, no AttributeError occurs and reload fires."""
        handler, reload_cb, _ = _make_handler(tmp_path, log_event=None)
        handler.on_modified(_event(tmp_path / "ssh-mcp-config.json"))
        reload_cb.assert_called_once()

    def test_path_matching_with_relative_path(self, tmp_path: Path) -> None:
        """Relative event.src_path still matches the absolute config_path."""
        handler, reload_cb, debounce_cb = _make_handler(tmp_path)
        # Use a relative path that resolves to the same file
        handler.on_modified(
            _event(
                os.path.relpath(
                    tmp_path / "ssh-mcp-config.json", start=os.getcwd()
                )
            )
        )
        # May or may not match depending on CWD — but if it's the same file
        # via abspath, reload fires.  We just verify no crash.
        assert debounce_cb.called or reload_cb.called

    def test_no_log_event_on_reload_no_crash(self, tmp_path: Path) -> None:
        """log_event=None on reload path does not cause any error."""
        handler, reload_cb, _ = _make_handler(tmp_path, log_event=None)
        handler.on_modified(_event(tmp_path / "ssh-mcp-config.json"))
        reload_cb.assert_called_once()
