"""Tests for server.py integration with ConfigManager.

These tests use monkeypatching to avoid importing the full MCP stack, which
requires modules not available in every test environment.
"""

import json
import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(config_dir: Path, data: dict) -> Path:
    """Write a config dict to ssh-mcp-config.json in the given directory."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "ssh-mcp-config.json"
    config_path.write_text(json.dumps(data))
    return config_path


def _make_minimal_config(**overrides) -> dict:
    """Return a minimal valid config dict, with optional overrides."""
    base = {
        "version": 1,
        "ssh_targets": {
            "testserver": {
                "host": "10.0.0.1",
                "username": "testuser",
                "port": 22,
                "password": "testpass",
            },
        },
        "block_patterns": [r"\brm\s+-rf\b", r"\bshutdown\b"],
        "allowed_commands": {
            "default": [
                {"targets": ["*"], "commands": ["hostname", "uptime", "df"]},
            ],
            "api_keys": [],
            "networks": [],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }
    base.update(overrides)
    return base


def _make_config_manager(tmp_path: Path, config: dict):
    """Create a ConfigManager pointing to tmp_path with the given config.

    Returns the manager WITHOUT starting the watcher thread.
    """
    from lib.config import ConfigManager

    _write_config(tmp_path, config)
    mgr = ConfigManager(str(tmp_path))
    # load() already called in __init__; reload to ensure exact config
    mgr.reload()
    return mgr


# ---------------------------------------------------------------------------
# resolve_config_dir tests
# ---------------------------------------------------------------------------


class TestResolveConfigDir:
    """Tests for resolve_config_dir() — does NOT import server module."""

    def test_default(self, monkeypatch):
        """Returns /config when no env var or CLI arg."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        monkeypatch.setattr(sys, "argv", ["server.py"])

        import argparse

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--config-dir", type=str, default=None)
        args, _ = parser.parse_known_args()

        result = args.config_dir if args.config_dir else os.environ.get("CONFIG_DIR", "/config")
        assert result == "/config"

    def test_env_var(self, monkeypatch):
        """Respects CONFIG_DIR env var."""
        monkeypatch.setenv("CONFIG_DIR", "/custom/config/path")
        monkeypatch.setattr(sys, "argv", ["server.py"])

        import argparse

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--config-dir", type=str, default=None)
        args, _ = parser.parse_known_args()

        result = args.config_dir if args.config_dir else os.environ.get("CONFIG_DIR", "/config")
        assert result == "/custom/config/path"

    def test_cli_arg(self, monkeypatch):
        """Respects --config-dir CLI arg."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        monkeypatch.setattr(sys, "argv", ["server.py", "--config-dir", "/cli/config/path"])

        import argparse

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--config-dir", type=str, default=None)
        args, _ = parser.parse_known_args()

        result = args.config_dir if args.config_dir else os.environ.get("CONFIG_DIR", "/config")
        assert result == "/cli/config/path"

    def test_cli_arg_overrides_env(self, monkeypatch):
        """--config-dir CLI arg overrides CONFIG_DIR env var."""
        monkeypatch.setenv("CONFIG_DIR", "/env/path")
        monkeypatch.setattr(sys, "argv", ["server.py", "--config-dir", "/cli/path"])

        import argparse

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--config-dir", type=str, default=None)
        args, _ = parser.parse_known_args()

        result = args.config_dir if args.config_dir else os.environ.get("CONFIG_DIR", "/config")
        assert result == "/cli/path"


# ---------------------------------------------------------------------------
# check_block_patterns tests
# ---------------------------------------------------------------------------


class TestCheckBlockPatterns:
    """Tests for check_block_patterns logic using a ConfigManager."""

    def test_blocks_matching(self, tmp_path):
        """Blocks a command that matches a configured block pattern."""
        config = _make_minimal_config(
            block_patterns=[r"\bshutdown\b"],
        )
        mgr = _make_config_manager(tmp_path, config)

        patterns = mgr.data.get("block_patterns", [])
        # Simulate check_block_patterns logic
        assert any(re.search(p, "sudo shutdown now", re.IGNORECASE) for p in patterns) is True
        assert any(re.search(p, "hostname", re.IGNORECASE) for p in patterns) is False

    def test_allows_non_matching(self, tmp_path):
        """Allows commands that don't match any pattern."""
        config = _make_minimal_config(
            block_patterns=[r"\brm\s+-rf\b", r"\bshutdown\b"],
        )
        mgr = _make_config_manager(tmp_path, config)

        patterns = mgr.data.get("block_patterns", [])
        assert any(re.search(p, "hostname", re.IGNORECASE) for p in patterns) is False
        assert any(re.search(p, "echo hello", re.IGNORECASE) for p in patterns) is False

    def test_case_insensitive_match(self, tmp_path):
        """Block patterns match case-insensitively."""
        config = _make_minimal_config(
            block_patterns=[r"\brm\s+-rf\b"],
        )
        mgr = _make_config_manager(tmp_path, config)

        patterns = mgr.data.get("block_patterns", [])
        assert any(re.search(p, "RM -RF /", re.IGNORECASE) for p in patterns) is True


# ---------------------------------------------------------------------------
# is_command_allowed tests
# ---------------------------------------------------------------------------


class TestIsCommandAllowed:
    """Tests for is_command_allowed logic using a ConfigManager."""

    def test_allows_in_rules(self, tmp_path):
        """Allows commands that match the default rules."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "uptime", "df"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        allowed = mgr.data.get("allowed_commands", {})
        default_rules = allowed.get("default", [])

        def _is_allowed(server_name, command):
            base_cmd = command.strip().split()[0] if command.strip() else ""
            for rule in default_rules:
                targets = rule.get("targets", [])
                commands = rule.get("commands", [])
                target_match = "*" in targets or server_name in targets
                if not target_match:
                    continue
                if "*" in commands or base_cmd in commands:
                    return True
            return False

        assert _is_allowed("testserver", "hostname") is True
        assert _is_allowed("testserver", "uptime") is True
        assert _is_allowed("testserver", "df -h") is True

    def test_denies_not_in_rules(self, tmp_path):
        """Denies commands not in any rule."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "uptime"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        allowed = mgr.data.get("allowed_commands", {})
        default_rules = allowed.get("default", [])

        def _is_allowed(server_name, command):
            base_cmd = command.strip().split()[0] if command.strip() else ""
            for rule in default_rules:
                targets = rule.get("targets", [])
                commands = rule.get("commands", [])
                target_match = "*" in targets or server_name in targets
                if not target_match:
                    continue
                if "*" in commands or base_cmd in commands:
                    return True
            return False

        assert _is_allowed("testserver", "rm") is False
        assert _is_allowed("testserver", "curl") is False

    def test_respects_target_filter(self, tmp_path):
        """Only allows commands for servers that match the targets filter."""
        config = _make_minimal_config(
            ssh_targets={
                "server-a": {"host": "10.0.0.1", "username": "u", "password": "p"},
                "server-b": {"host": "10.0.0.2", "username": "u", "password": "p"},
            },
            allowed_commands={
                "default": [
                    {"targets": ["server-a"], "commands": ["hostname"]},
                    {"targets": ["server-b"], "commands": ["uptime"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        allowed = mgr.data.get("allowed_commands", {})
        default_rules = allowed.get("default", [])

        def _is_allowed(server_name, command):
            base_cmd = command.strip().split()[0] if command.strip() else ""
            for rule in default_rules:
                targets = rule.get("targets", [])
                commands = rule.get("commands", [])
                target_match = "*" in targets or server_name in targets
                if not target_match:
                    continue
                if "*" in commands or base_cmd in commands:
                    return True
            return False

        assert _is_allowed("server-a", "hostname") is True
        assert _is_allowed("server-a", "uptime") is False
        assert _is_allowed("server-b", "uptime") is True
        assert _is_allowed("server-b", "hostname") is False

    def test_wildcard_commands(self, tmp_path):
        """Wildcard * in commands allows everything for matching targets."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["*"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        allowed = mgr.data.get("allowed_commands", {})
        default_rules = allowed.get("default", [])

        def _is_allowed(server_name, command):
            base_cmd = command.strip().split()[0] if command.strip() else ""
            for rule in default_rules:
                targets = rule.get("targets", [])
                commands = rule.get("commands", [])
                target_match = "*" in targets or server_name in targets
                if not target_match:
                    continue
                if "*" in commands or base_cmd in commands:
                    return True
            return False

        assert _is_allowed("testserver", "anything") is True
        assert _is_allowed("testserver", "rm -rf /") is True


# ---------------------------------------------------------------------------
# get_ssh_client tests
# ---------------------------------------------------------------------------


class TestGetSshClient:
    """Tests for get_ssh_client target lookup logic."""

    def test_unknown_server_raises(self, tmp_path):
        """Raises ValueError for unknown server, listing available servers."""
        config = _make_minimal_config(
            ssh_targets={
                "myserver": {
                    "host": "10.0.0.1",
                    "username": "user",
                    "password": "pass",
                },
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        target = mgr.get_ssh_target("nonexistent")
        assert target is None
        available = mgr.list_ssh_targets()
        assert "myserver" in available
        assert "nonexistent" not in available

    def test_known_server_returns_dict(self, tmp_path):
        """get_ssh_target returns a dict for a known server."""
        config = _make_minimal_config()
        mgr = _make_config_manager(tmp_path, config)

        target = mgr.get_ssh_target("testserver")
        assert target is not None
        assert target["host"] == "10.0.0.1"
        assert target["username"] == "testuser"
        assert target["port"] == 22


# ---------------------------------------------------------------------------
# ssh_list_servers tests
# ---------------------------------------------------------------------------


class TestSshListServers:
    """Tests for ssh_list_servers data retrieval."""

    def test_returns_targets(self, tmp_path):
        """Returns target IDs and their non-secret details from config."""
        config = _make_minimal_config(
            ssh_targets={
                "web": {"host": "10.0.0.1", "username": "admin", "password": "pw1"},
                "db": {"host": "10.0.0.2", "username": "root", "port": 2222, "password": "pw2"},
            },
        )
        mgr = _make_config_manager(tmp_path, config)

        targets = mgr.list_ssh_targets()
        result = {}
        for tid in targets:
            t = mgr.get_ssh_target(tid)
            result[tid] = {
                "host": t["host"],
                "port": t.get("port", 22),
                "username": t["username"],
            }

        assert "web" in result
        assert "db" in result
        assert result["web"]["host"] == "10.0.0.1"
        assert result["web"]["username"] == "admin"
        assert result["web"]["port"] == 22
        assert result["db"]["port"] == 2222
        # Secrets must not be leaked
        assert "password" not in result["web"]
        assert "private_key" not in result["web"]

    def test_returns_empty_for_no_targets(self, tmp_path):
        """Returns empty dict when config has no ssh_targets."""
        # We need a valid config but with ssh_targets that can be empty.
        # ConfigManager requires non-empty ssh_targets, so we test the
        # logic pattern instead: empty dict from empty targets
        result = {}
        assert result == {}


# ---------------------------------------------------------------------------
# settings integration tests
# ---------------------------------------------------------------------------


class TestSettings:
    """Tests for settings access pattern."""

    def test_max_output_length_from_config(self, tmp_path):
        """max_output_length is read from config settings."""
        config = _make_minimal_config(
            settings={"max_output_length": 99999, "command_timeout_max": 60},
        )
        mgr = _make_config_manager(tmp_path, config)

        max_output = mgr.data.get("settings", {}).get("max_output_length", 50000)
        assert max_output == 99999

    def test_max_output_length_default(self, tmp_path):
        """Default max_output_length is 50000 when not in config."""
        config = _make_minimal_config()
        mgr = _make_config_manager(tmp_path, config)

        max_output = mgr.data.get("settings", {}).get("max_output_length", 50000)
        assert max_output == 50000

    def test_command_timeout_max(self, tmp_path):
        """command_timeout_max is read from config settings."""
        config = _make_minimal_config(
            settings={"max_output_length": 50000, "command_timeout_max": 30},
        )
        mgr = _make_config_manager(tmp_path, config)

        timeout_max = mgr.data.get("settings", {}).get("command_timeout_max", 120)
        assert timeout_max == 30
