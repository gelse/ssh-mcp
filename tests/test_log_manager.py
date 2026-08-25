"""Unit tests for lib/log_manager.py — LoggingManager."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lib.constants import (
    ACTIVE_LOG_FILENAME,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_LOG_OUTPUT,
)
from lib.exceptions import ConfigValidationError
from lib.log_composite import CompositeLogger
from lib.log_manager import LoggingManager
from lib.log_target_jsonfile import JsonFileLogger
from lib.log_target_stdout import StdoutLogger
from lib.log_target_textfile import TextFileLogger


# ---------------------------------------------------------------------------
# Tests: new-style config (log_targets array)
# ---------------------------------------------------------------------------


class TestLoggingManagerNewStyleConfig:
    """Tests for building targets from new-style logging.log_targets config."""

    def test_builds_stdout_target(self):
        """A stdout target is built from config."""
        settings = {
            "logging": {
                "log_targets": [{"target": "stdout"}],
            }
        }
        mgr = LoggingManager(settings)
        try:
            assert len(mgr.logger.targets) == 1
            assert isinstance(mgr.logger.targets[0], StdoutLogger)
        finally:
            mgr.close()

    def test_builds_jsonfile_target(self, tmp_path: Path):
        """A jsonfile target is built from config with filepath."""
        filepath = str(tmp_path / "test.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "jsonfile", "filepath": filepath}
                ],
            }
        }
        mgr = LoggingManager(settings)
        try:
            assert len(mgr.logger.targets) == 1
            assert isinstance(mgr.logger.targets[0], JsonFileLogger)
        finally:
            mgr.close()

    def test_builds_textfile_target(self, tmp_path: Path):
        """A file target is built from config with filepath."""
        filepath = str(tmp_path / "test.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "file", "filepath": filepath}
                ],
            }
        }
        mgr = LoggingManager(settings)
        try:
            assert len(mgr.logger.targets) == 1
            assert isinstance(mgr.logger.targets[0], TextFileLogger)
        finally:
            mgr.close()

    def test_builds_multiple_targets(self, tmp_path: Path):
        """Multiple targets are built from config."""
        filepath = str(tmp_path / "test.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "stdout"},
                    {"target": "jsonfile", "filepath": filepath},
                ],
            }
        }
        mgr = LoggingManager(settings)
        try:
            assert len(mgr.logger.targets) == 2
            assert isinstance(mgr.logger.targets[0], StdoutLogger)
            assert isinstance(mgr.logger.targets[1], JsonFileLogger)
        finally:
            mgr.close()

    def test_empty_log_targets_falls_back_to_legacy(self):
        """Empty log_targets array triggers legacy fallback."""
        settings = {"logging": {"log_targets": []}}
        mgr = LoggingManager(settings, log_dir="/tmp/test_logs_empty")
        try:
            assert len(mgr.logger.targets) == 1
            assert isinstance(mgr.logger.targets[0], JsonFileLogger)
        finally:
            mgr.close()


# ---------------------------------------------------------------------------
# Tests: legacy config fallback
# ---------------------------------------------------------------------------


class TestLoggingManagerLegacyConfig:
    """Tests for backward-compatible legacy config fallback."""

    def test_legacy_creates_single_jsonfile(self, tmp_path: Path):
        """Legacy config (no logging section) creates a single JsonFileLogger."""
        settings = {}
        log_dir = str(tmp_path)
        mgr = LoggingManager(settings, log_dir=log_dir)
        try:
            assert len(mgr.logger.targets) == 1
            assert isinstance(mgr.logger.targets[0], JsonFileLogger)
        finally:
            mgr.close()

    def test_legacy_uses_log_level_from_settings(self, tmp_path: Path):
        """Legacy config uses settings.log_level."""
        settings = {"log_level": "DEBUG"}
        mgr = LoggingManager(settings, log_dir=str(tmp_path))
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._log_level == "DEBUG"
        finally:
            mgr.close()

    def test_legacy_uses_max_log_output_from_settings(self, tmp_path: Path):
        """Legacy config uses settings.max_log_output."""
        settings = {"max_log_output": 100}
        mgr = LoggingManager(settings, log_dir=str(tmp_path))
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._delegate._max_log_output == 100
        finally:
            mgr.close()

    def test_legacy_uses_compress_rotated_from_settings(self, tmp_path: Path):
        """Legacy config uses settings.compress_rotated."""
        settings = {"compress_rotated": False}
        mgr = LoggingManager(settings, log_dir=str(tmp_path))
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._delegate._compress_rotated is False
        finally:
            mgr.close()

    def test_legacy_filepath_includes_log_dir(self, tmp_path: Path):
        """Legacy target filepath is resolved relative to log_dir."""
        log_dir = str(tmp_path)
        settings = {}
        mgr = LoggingManager(settings, log_dir=log_dir)
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            # FileLogger writes to log_dir / ACTIVE_LOG_FILENAME
            log_file = tmp_path / ACTIVE_LOG_FILENAME
            assert log_file.exists()
        finally:
            mgr.close()


# ---------------------------------------------------------------------------
# Tests: log level resolution
# ---------------------------------------------------------------------------


class TestLoggingManagerLogLevelResolution:
    """Tests for log level precedence: per-target > env > config > default."""

    def test_default_level_used_when_nothing_specified(self, tmp_path: Path):
        """DEFAULT_LOG_LEVEL is used when nothing else is specified."""
        settings = {"logging": {"log_targets": [{"target": "stdout"}]}}
        mgr = LoggingManager(settings)
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, StdoutLogger)
            # StdoutLogger stores the parsed integer level
            assert target._log_level == 20  # INFO
        finally:
            mgr.close()

    def test_env_override_changes_default_level(self, tmp_path: Path):
        """log_level_env_override changes the default level for targets."""
        settings = {"logging": {"log_targets": [{"target": "stdout"}]}}
        mgr = LoggingManager(settings, log_level_env_override="WARNING")
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, StdoutLogger)
            assert target._log_level == 30  # WARNING
        finally:
            mgr.close()

    def test_per_target_level_takes_precedence_over_env(self, tmp_path: Path):
        """Per-target log_level overrides the env override."""
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "stdout", "log_level": "ERROR"}
                ],
            }
        }
        mgr = LoggingManager(settings, log_level_env_override="WARNING")
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, StdoutLogger)
            assert target._log_level == 40  # ERROR
        finally:
            mgr.close()

    def test_legacy_env_override_changes_level(self, tmp_path: Path):
        """In legacy mode, env override changes the target log level."""
        settings = {}
        mgr = LoggingManager(
            settings,
            log_dir=str(tmp_path),
            log_level_env_override="DEBUG",
        )
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._log_level == "DEBUG"
        finally:
            mgr.close()

    def test_legacy_per_settings_level_takes_precedence(self, tmp_path: Path):
        """In legacy mode, settings.log_level takes precedence over env."""
        settings = {"log_level": "ERROR"}
        mgr = LoggingManager(
            settings,
            log_dir=str(tmp_path),
            log_level_env_override="WARNING",
        )
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._log_level == "ERROR"
        finally:
            mgr.close()


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------


class TestLoggingManagerErrorHandling:
    """Tests for error handling in LoggingManager."""

    def test_unknown_target_type_raises_error(self):
        """Unknown target type raises ConfigValidationError."""
        settings = {
            "logging": {
                "log_targets": [{"target": "syslog"}],
            }
        }
        with pytest.raises(ConfigValidationError, match="Unknown log target"):
            LoggingManager(settings)

    def test_missing_filepath_for_jsonfile_raises_error(self):
        """jsonfile target without filepath raises ConfigValidationError."""
        settings = {
            "logging": {
                "log_targets": [{"target": "jsonfile"}],
            }
        }
        with pytest.raises(ConfigValidationError, match="filepath"):
            LoggingManager(settings)

    def test_missing_filepath_for_textfile_raises_error(self):
        """file target without filepath raises ConfigValidationError."""
        settings = {
            "logging": {
                "log_targets": [{"target": "file"}],
            }
        }
        with pytest.raises(ConfigValidationError, match="filepath"):
            LoggingManager(settings)


# ---------------------------------------------------------------------------
# Tests: filepath resolution
# ---------------------------------------------------------------------------


class TestLoggingManagerFilepathResolution:
    """Tests for filepath resolution (relative vs absolute)."""

    def test_absolute_filepath_used_as_is(self, tmp_path: Path):
        """Absolute filepath is used as-is."""
        filepath = str(tmp_path / "abs.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "jsonfile", "filepath": filepath}
                ],
            }
        }
        mgr = LoggingManager(settings)
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            # The logger was created without error
        finally:
            mgr.close()

    def test_relative_filepath_resolved_against_log_dir(self, tmp_path: Path):
        """Relative filepath is resolved against log_dir."""
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "jsonfile", "filepath": "sub/test.log"}
                ],
            }
        }
        mgr = LoggingManager(settings, log_dir=str(tmp_path))
        try:
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            # FileLogger writes to the resolved directory
            log_dir = tmp_path / "sub"
            assert log_dir.exists()
        finally:
            mgr.close()


# ---------------------------------------------------------------------------
# Tests: close() and configure()
# ---------------------------------------------------------------------------


class TestLoggingManagerLifecycle:
    """Tests for close() and configure() delegation."""

    def test_close_closes_all_targets(self, tmp_path: Path):
        """close() closes all underlying targets."""
        filepath = str(tmp_path / "test.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "jsonfile", "filepath": filepath},
                ],
            }
        }
        mgr = LoggingManager(settings)
        target = mgr.logger.targets[0]
        mgr.close()

        # JsonFileLogger delegates to FileLogger; after close, fp is None
        assert target._delegate._fp is None

    def test_configure_forwards_to_targets(self, tmp_path: Path):
        """configure() forwards to all targets."""
        filepath = str(tmp_path / "test.log")
        settings = {
            "logging": {
                "log_targets": [
                    {"target": "jsonfile", "filepath": filepath},
                ],
            }
        }
        mgr = LoggingManager(settings)
        try:
            mgr.configure(max_log_output=50, compress_rotated=False)
            target = mgr.logger.targets[0]
            assert isinstance(target, JsonFileLogger)
            assert target._delegate._max_log_output == 50
            assert target._delegate._compress_rotated is False
        finally:
            mgr.close()

    def test_logger_property_returns_composite(self, tmp_path: Path):
        """logger property returns a CompositeLogger instance."""
        settings = {}
        mgr = LoggingManager(settings, log_dir=str(tmp_path))
        try:
            assert isinstance(mgr.logger, CompositeLogger)
        finally:
            mgr.close()
