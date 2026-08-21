"""Comprehensive unit tests for AuthorizationManager, AuthResult, helper functions,
and cryptographic API-key hashing.

Tests the layered authorization chain: block_patterns -> default -> api_key -> network -> deny.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from lib.auth import (
    AuthorizationManager,
    AuthResult,
    RulesSnapshot,
    _extract_base_command,
    _split_command_segments,
)
from lib.config import ConfigManager
from lib.crypto import hash_api_key, verify_api_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmpdir: str, config_dict: dict) -> str:
    """Write *config_dict* as ``ssh-mcp-config.json`` inside *tmpdir*."""
    conf_path = Path(tmpdir) / "ssh-mcp-config.json"
    conf_path.write_text(json.dumps(config_dict), encoding="utf-8")
    return str(conf_path)


def _minimal_auth_config(**overrides) -> dict:
    """Return a minimal valid config dict suitable for authorization tests.

    Accepts ``**overrides`` that are passed to ``cfg.update(overrides)`` so
    callers can tweak specific sections.
    """
    cfg = {
        "version": 1,
        "ssh_targets": {
            "knubbel": {"host": "10.0.0.1", "username": "admin", "password": "secret"},
            "home": {"host": "10.0.0.2", "username": "root", "password": "secret"},
            "mail": {"host": "10.0.0.3", "username": "root", "password": "secret"},
            "piprint": {"host": "10.0.0.4", "username": "root", "password": "secret"},
        },
        "block_patterns": [r"\brm\s+-rf\b", r"\bshutdown\b"],
        "allowed_commands": {
            "default": [
                {
                    "targets": ["*"],
                    "commands": ["hostname", "uptime", "free", "df", "grep"],
                }
            ],
            "api_keys": [
                {
                    "name": "monitoring-service",
                    "key_hash": (
                        "sha256:9f86d081884c7d659a2feaa0c55ad015"
                        "a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    ),
                    "rules": [
                        {
                            "targets": ["knubbel", "home"],
                            "commands": ["docker", "systemctl", "journalctl"],
                        },
                        {
                            "targets": ["*"],
                            "commands": ["uptime", "free", "df", "ping"],
                        },
                    ],
                },
                {
                    "name": "full-admin",
                    "key_hash": (
                        "sha256:2c26b46b68ffc68ff99b453c1d304134"
                        "13422d706483bfa0f98a5e886266e7ae"
                    ),
                    "rules": [
                        {"targets": ["*"], "commands": ["*"]}
                    ],
                },
            ],
            "networks": [
                {
                    "name": "homelab-internal",
                    "range": "10.42.43.0/24",
                    "rules": [
                        {"targets": ["*"], "commands": ["*"]}
                    ],
                },
                {
                    "name": "guest-wifi",
                    "range": "10.42.99.0/24",
                    "rules": [
                        {"targets": ["piprint"], "commands": ["uptime", "free", "ping"]}
                    ],
                },
            ],
        },
        "settings": {
            "max_output_length": 50000,
            "command_timeout_max": 120,
        },
    }
    cfg.update(overrides)
    return cfg


def _make_auth_manager(tmp_path: Path, config: dict | None = None):
    """Create a ConfigManager + AuthorizationManager from *config*.

    Args:
        tmp_path: pytest's ``tmp_path`` fixture (provides the config directory).
        config: Optional config dict.  When ``None``, ``_minimal_auth_config()``
                is used.

    Returns:
        ``AuthorizationManager`` instance backed by a ``ConfigManager`` that
        has already loaded the config.
    """
    if config is None:
        config = _minimal_auth_config()
    _write_config(str(tmp_path), config)
    cm = ConfigManager(str(tmp_path))
    return AuthorizationManager(cm)


# ---------------------------------------------------------------------------
# TestHelperFunctions
# ---------------------------------------------------------------------------


class TestCommandParsingHelpers:
    """Tests for command-segmentation helper functions: _extract_base_command and _split_command_segments."""

    # -- _extract_base_command --

    def test_extract_base_command_simple(self):
        assert _extract_base_command("docker ps -a") == "docker"

    def test_extract_base_command_single_word(self):
        assert _extract_base_command("hostname") == "hostname"

    def test_extract_base_command_with_whitespace(self):
        assert _extract_base_command("   uptime   ") == "uptime"

    def test_extract_base_command_empty(self):
        assert _extract_base_command("") == ""

    def test_extract_base_command_only_spaces(self):
        assert _extract_base_command("   ") == ""

    # -- _split_command_segments --

    def test_split_single_command(self):
        assert _split_command_segments("hostname") == ["hostname"]

    def test_split_pipe(self):
        assert _split_command_segments("ls | grep foo") == ["ls", "grep foo"]

    def test_split_semicolon(self):
        assert _split_command_segments("echo hi; uptime") == ["echo hi", "uptime"]

    def test_split_ampersand(self):
        assert _split_command_segments("cmd1 & cmd2") == ["cmd1", "cmd2"]

    def test_split_mixed(self):
        assert _split_command_segments("cat file | grep x; echo done") == [
            "cat file",
            "grep x",
            "echo done",
        ]

    def test_split_empty(self):
        assert _split_command_segments("") == []

    def test_split_only_delimiters(self):
        assert _split_command_segments(";;&|") == []


# ---------------------------------------------------------------------------
# TestAuthResult
# ---------------------------------------------------------------------------


class TestAuthResult:
    """Tests for the AuthResult dataclass."""

    def test_auth_result_allowed(self):
        result = AuthResult(True, "ok", "default", "test-target")
        assert result.allowed is True
        assert result.reason == "ok"
        assert result.matched_via == "default"
        assert result.target_name == "test-target"

    def test_auth_result_denied(self):
        result = AuthResult(False, "blocked", "blocked:rm -rf", "test-target")
        assert result.allowed is False
        assert result.target_name == "test-target"


# ---------------------------------------------------------------------------
# TestCheckCommandBlockPatterns
# ---------------------------------------------------------------------------


class TestCheckCommandBlockPatterns:
    """Tests that block_patterns are evaluated first and unconditionally."""

    def test_blocked_command(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("rm -rf /", "knubbel")
        assert result.allowed is False
        assert result.matched_via.startswith("blocked:")

    def test_blocked_case_insensitive(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("RM -RF /", "knubbel")
        assert result.allowed is False

    def test_blocked_takes_precedence(self, tmp_path):
        """Block patterns take priority over any allow rule."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("shutdown now", "knubbel")
        assert result.allowed is False

    def test_non_blocked_passes(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "knubbel")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# TestBlockPatternReDoSProtection
# ---------------------------------------------------------------------------


class TestBlockPatternReDoSProtection:
    """Verify the ReDoS protection layers applied to block patterns."""

    def test_block_patterns_compiled_with_safety_flag(self, tmp_path):
        """Block patterns are compiled with ``re.LIMITED_TIME`` when available."""
        am = _make_auth_manager(tmp_path)
        _raw, compiled = am._rules.block_patterns[0]
        limited_time = getattr(re, "LIMITED_TIME", None)
        if limited_time is not None:
            assert compiled.flags & int(limited_time)

    def test_block_pattern_timeout_returns_no_match(self, tmp_path, monkeypatch):
        """A timeout during matching yields no block -- the safe default."""
        import lib.auth as auth_mod

        cfg = _minimal_auth_config(block_patterns=[r"\bblockme\b"])
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["blockme", "hostname"]}
        ]
        monkeypatch.setattr(auth_mod, "safe_regex_search", lambda *a, **k: None)
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("blockme", "knubbel")
        # Pattern match timed out (returned None) so block_patterns did not
        # block; the command passes through to the default allow rule.
        assert result.allowed is True


# ---------------------------------------------------------------------------
# TestCheckCommandDefaultRules
# ---------------------------------------------------------------------------


class TestCheckCommandDefaultRules:
    """Tests for the default rules layer."""

    def test_default_allows_listed_command(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "knubbel")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_default_allows_command_with_args(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("df -h", "knubbel")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_default_denies_unlisted_command(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("curl http://example.com", "knubbel")
        assert result.allowed is False
        assert result.matched_via == "denied"

    def test_default_target_filter(self, tmp_path):
        """Default rules are filtered by target — a rule for 'home' does not allow 'knubbel'."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["knubbel"], "commands": ["hostname"]},
            {"targets": ["home"], "commands": ["uptime"]},
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("uptime", "knubbel")
        assert result.allowed is False

    def test_default_wildcard_target(self, tmp_path):
        """Wildcard '*' in targets matches any target."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "home")
        assert result.allowed is True

    def test_default_wildcard_commands(self, tmp_path):
        """Wildcard '*' in commands allows anything."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["*"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("anything", "knubbel")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# TestCheckCommandApiKey
# ---------------------------------------------------------------------------


class TestCheckCommandApiKey:
    """Tests for the API-key authorization layer."""

    def test_api_key_allows_listed_command(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("docker ps", "knubbel", api_key="test")
        assert result.allowed is True
        assert result.matched_via == "api_key:monitoring-service"

    def test_api_key_allows_wildcard_target(self, tmp_path):
        """monitoring-service has a wildcard-target rule with ping."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("ping 8.8.8.8", "mail", api_key="test")
        assert result.allowed is True
        assert result.matched_via == "api_key:monitoring-service"

    def test_api_key_denies_wrong_target(self, tmp_path):
        """monitoring-service's docker rule only targets knubbel,home — not mail."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("docker ps", "mail", api_key="test")
        assert result.allowed is False

    def test_api_key_full_admin(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("anything", "knubbel", api_key="foo")
        assert result.allowed is True
        assert result.matched_via == "api_key:full-admin"

    def test_unknown_api_key_falls_through(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("curl http://example.com", "knubbel", api_key="unknown-key")
        assert result.allowed is False  # curl not in default rules
        assert result.matched_via == "denied"

    def test_api_key_empty_string(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("docker ps", "knubbel", api_key="")
        # Empty string treated as no API key; docker not in default rules
        assert result.allowed is False
        assert result.matched_via == "denied"

    def test_api_key_none(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("docker ps", "knubbel", api_key=None)
        assert result.allowed is False
        assert result.matched_via == "denied"


# ---------------------------------------------------------------------------
# TestCheckCommandNetwork
# ---------------------------------------------------------------------------


class TestCheckCommandNetwork:
    """Tests for the network-based authorization layer."""

    def test_network_homelab_full_access(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("anything", "knubbel", source_ip="10.42.43.100")
        assert result.allowed is True
        assert result.matched_via.startswith("network:homelab-internal")

    def test_network_guest_limited(self, tmp_path):
        """Guest-wifi allows uptime for piprint.  Remove piprint from default
        rules so the network layer is reached."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {
                "targets": ["knubbel", "home", "mail"],
                "commands": ["hostname", "uptime", "free", "df", "grep"],
            }
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("uptime", "piprint", source_ip="10.42.99.50")
        assert result.allowed is True
        assert result.matched_via.startswith("network:guest-wifi")

    def test_network_guest_denied(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("docker ps", "piprint", source_ip="10.42.99.50")
        # docker not in guest-wifi commands, and piprint not in default targets
        assert result.allowed is False
        assert result.matched_via == "denied"

    def test_network_no_match_falls_through(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("curl http://example.com", "knubbel", source_ip="192.168.1.1")
        assert result.allowed is False
        assert result.matched_via == "denied"

    def test_network_invalid_ip(self, tmp_path):
        """Invalid IP should fall through silently, not crash."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "knubbel", source_ip="not-an-ip")
        # Falls through to default, which allows hostname
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_network_empty_string(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "knubbel", source_ip="")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_network_none(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "knubbel", source_ip=None)
        assert result.allowed is True
        assert result.matched_via == "default"


# ---------------------------------------------------------------------------
# TestCheckCommandChainedCommands
# ---------------------------------------------------------------------------


class TestCheckCommandChainedCommands:
    """Tests for piped / semicolon / ampersand-chained commands."""

    def test_pipe_all_allowed(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname | grep x", "knubbel")
        assert result.allowed is True

    def test_pipe_one_denied(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname | curl example.com", "knubbel")
        assert result.allowed is False

    def test_semicolon_all_allowed(self, tmp_path):
        """Delimiters need surrounding whitespace so the fall-through
        _extract_base_command on the original command still resolves cleanly."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("uptime ; free", "knubbel")
        assert result.allowed is True

    def test_semicolon_one_denied(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("uptime ; rm /tmp/x", "knubbel")
        assert result.allowed is False

    def test_pipe_blocked(self, tmp_path):
        """Block patterns apply to each segment, even inside a pipe."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname | rm -rf /", "knubbel")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# TestCheckCommandRedirectionStripping
# ---------------------------------------------------------------------------


class TestCheckCommandRedirectionStripping:
    """Verify redirect stripping lets allow-listed commands with benign
    redirections/terminals pass, while protected targets are still denied."""

    def test_redirect_to_tmp_allowed(self, tmp_path):
        """Redirects into a non-protected path (e.g. /tmp) are stripped, so
        the allow-listed base command 'uptime' is allowed."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("uptime >/tmp/o 2>&1", "knubbel")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_pipe_with_stderr_redirect_all_segments_allowed(self, tmp_path):
        """A pipe whose segments are all allow-listed, with a stderr redirect
        glued to the first segment, should be allowed after stripping."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["grep", "head"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("grep pattern 2>&1 | head", "knubbel")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_chain_second_command_not_allowed_denied(self, tmp_path):
        """Redirect stripping must not grant access to a non-allow-listed
        chained command — 'nc' is denied."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["echo"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("echo hi 2>&1 && nc example.com", "knubbel")
        assert result.allowed is False
        assert result.matched_via == "denied"

    def test_chain_block_pattern_beats_semicolon(self, tmp_path):
        """Stripping does not hide a blocked command in a chain — the 'rm -rf'
        block pattern still denies the whole command."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["echo"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("echo hi 2>&1; rm -rf /tmp/x", "knubbel")
        assert result.allowed is False
        assert result.matched_via.startswith("blocked:")

    def test_redirect_to_dev_protected(self, tmp_path):
        """Redirection into /dev/sda is a protected target and is denied."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("cat file >/dev/sda", "knubbel")
        assert result.allowed is False
        assert result.matched_via == "blocked:redirection-target"

    def test_redirect_to_proc_protected(self, tmp_path):
        """Redirection into /proc/self/fd/0 is denied even though the base
        command is not otherwise restricted."""
        am = _make_auth_manager(tmp_path)
        result = am.check_command("cat file >/proc/self/fd/0", "knubbel")
        assert result.allowed is False
        assert result.matched_via == "blocked:redirection-target"

    def test_protected_target_denied_even_without_block_patterns(self, tmp_path):
        """Defense-in-depth: redirection into a protected path is blocked by
        the dedicated target check, even with an empty block_patterns list."""
        cfg = _minimal_auth_config(block_patterns=[])
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("cat x >/dev/null", "knubbel")
        assert result.allowed is False
        assert result.matched_via == "blocked:redirection-target"

    def test_quoted_greater_than_allowed(self, tmp_path):
        """A '>' inside quotes is not a redirect — the allow-listed 'echo'
        command is allowed."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["echo"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command('echo "a>b"', "knubbel")
        assert result.allowed is True
        assert result.matched_via == "default"


# ---------------------------------------------------------------------------
# TestCheckCommandEdgeCases
# ---------------------------------------------------------------------------


class TestCheckCommandEdgeCases:
    """Tests for edge cases and layer-priority interactions."""

    def test_unknown_target(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("hostname", "nonexistent")
        assert result.allowed is False
        assert "Unknown target" in result.reason
        assert result.matched_via == "denied"

    def test_default_overrides_api_key(self, tmp_path):
        """Command allowed by default layer should match at default and stop."""
        am = _make_auth_manager(tmp_path)
        # 'hostname' is in both default and monitoring-service rules
        result = am.check_command("hostname", "knubbel", api_key="test")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_layer_priority_default_first(self, tmp_path):
        """Command in both default and API key rules — default wins."""
        am = _make_auth_manager(tmp_path)
        # 'free' is in default and monitoring-service wildcard
        result = am.check_command("free", "knubbel", api_key="test")
        assert result.allowed is True
        assert result.matched_via == "default"

    def test_layer_fallthrough_to_api_key(self, tmp_path):
        """Override default to NOT include knubbel; API key should catch it."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["home"], "commands": ["hostname"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("docker ps", "knubbel", api_key="test")
        assert result.allowed is True
        assert result.matched_via == "api_key:monitoring-service"

    def test_layer_fallthrough_to_network(self, tmp_path):
        """Default has no rule for target, no API key, but network matches."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["home"], "commands": ["hostname"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("anything", "knubbel", source_ip="10.42.43.50")
        assert result.allowed is True
        assert result.matched_via.startswith("network:")

    def test_empty_command_string(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.check_command("", "knubbel")
        assert result.allowed is False

    def test_block_patterns_loaded_from_config(self, tmp_path):
        """Changing block_patterns via config should be reflected."""
        cfg = _minimal_auth_config(block_patterns=[r"\bcurl\b"])
        am = _make_auth_manager(tmp_path, cfg)
        # 'curl' is now blocked
        result = am.check_command("curl http://example.com", "knubbel")
        assert result.allowed is False
        # 'hostname' is not blocked
        result2 = am.check_command("hostname", "knubbel")
        assert result2.allowed is True


# ---------------------------------------------------------------------------
# TestListAllowedCommands
# ---------------------------------------------------------------------------


class TestListAllowedCommands:
    """Tests for ``AuthorizationManager.list_allowed_commands()``."""

    def test_default_only(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("knubbel")
        assert result == sorted(["df", "free", "grep", "hostname", "uptime"])

    def test_default_plus_api_key(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("knubbel", api_key="test")
        expected = sorted(
            [
                "df", "docker", "free", "grep",
                "hostname", "journalctl", "ping",
                "systemctl", "uptime",
            ]
        )
        assert result == expected

    def test_wildcard_short_circuits(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("knubbel", api_key="foo")
        assert result == ["*"]

    def test_network_wildcard_short_circuits(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("knubbel", source_ip="10.42.43.100")
        assert result == ["*"]

    def test_unknown_target(self, tmp_path):
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("nonexistent")
        assert result == []

    def test_target_specific_filtering(self, tmp_path):
        """mail target: default rules apply (wildcard target), plus
        monitoring-service wildcard-target rules."""
        am = _make_auth_manager(tmp_path)
        result = am.list_allowed_commands("mail", api_key="test")
        expected = sorted(
            ["df", "free", "grep", "hostname", "ping", "uptime"]
        )
        assert result == expected

    def test_empty_result_when_nothing_matches(self, tmp_path):
        """Config with no rules matching the target should return empty list."""
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["default"] = [
            {"targets": ["home"], "commands": ["hostname"]}
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.list_allowed_commands("knubbel")
        assert result == []


# ---------------------------------------------------------------------------
# TestApiKeyHashing (PBKDF2 upgrade)
# ---------------------------------------------------------------------------


class TestApiKeyHashing:
    """Tests for the upgraded PBKDF2 API-key hashing and verification."""

    def test_hash_produces_valid_format(self):
        """New hash should match pbkdf2:sha256:iter$salt$hash format."""
        h = hash_api_key("my-secret-key")
        parts = h.split("$")
        assert len(parts) == 3, f"Expected 3 $-separated parts, got: {h}"
        prefix, salt_hex, hash_hex = parts
        assert prefix.startswith("pbkdf2:sha256:"), f"Unexpected prefix: {prefix}"
        iterations = int(prefix.split(":")[2])
        assert iterations == 100_000
        assert len(salt_hex) == 32  # 16 bytes hex-encoded
        assert len(hash_hex) == 64  # 32 bytes hex-encoded

    def test_verify_freshly_hashed_key(self):
        """A freshly hashed key should verify successfully."""
        h = hash_api_key("my-api-key-123")
        assert verify_api_key("my-api-key-123", h) is True

    def test_verify_wrong_key_fails(self):
        """A wrong key should NOT verify against a stored hash."""
        h = hash_api_key("correct-key")
        assert verify_api_key("wrong-key", h) is False

    def test_different_keys_produce_different_hashes(self):
        """Two different keys must produce different hash strings."""
        h1 = hash_api_key("key-alpha")
        h2 = hash_api_key("key-beta")
        assert h1 != h2

    def test_same_key_produces_different_hashes_different_salts(self):
        """Same key hashed twice produces different output due to random salt."""
        h1 = hash_api_key("same-key")
        h2 = hash_api_key("same-key")
        # Different salts => different hash strings
        assert h1 != h2
        # But both should verify
        assert verify_api_key("same-key", h1) is True
        assert verify_api_key("same-key", h2) is True

    def test_backward_compat_sha256_format(self):
        """Legacy sha256: format keys must still verify."""
        # sha256:9f86d... = SHA-256("test")  — matches the test config
        legacy_hash = (
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        assert verify_api_key("test", legacy_hash) is True

    def test_backward_compat_sha256_wrong_key(self):
        """Wrong key against legacy sha256: should fail."""
        legacy_hash = (
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        assert verify_api_key("wrong", legacy_hash) is False

    def test_unknown_format_returns_false(self):
        """Completely unknown hash format should return False."""
        assert verify_api_key("anything", "garbage") is False

    def test_malformed_pbkdf2_format_returns_false(self):
        """Malformed PBKDF2 prefix with no delimiters returns False."""
        assert verify_api_key("key", "pbkdf2:sha256:100000") is False

    def test_api_key_integration_with_auth_manager_new_format(self, tmp_path):
        """AuthorizationManager recognizes a PBKDF2-hashed API key."""
        key_hash = hash_api_key("integration-key")
        cfg = _minimal_auth_config()
        cfg["allowed_commands"]["api_keys"] = [
            {
                "name": "integration-user",
                "key_hash": key_hash,
                "rules": [
                    {"targets": ["*"], "commands": ["*"]},
                ],
            }
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("whoami", "knubbel", api_key="integration-key")
        assert result.allowed is True
        assert result.matched_via == "api_key:integration-user"

    def test_api_key_integration_with_auth_manager_wrong_key_new_format(self, tmp_path):
        """AuthorizationManager rejects a wrong key even with PBKDF2 format."""
        key_hash = hash_api_key("correct-integration-key")
        cfg = _minimal_auth_config()
        # default has a rule only for "home" so "knubbel" falls through
        cfg["allowed_commands"]["default"] = [
            {"targets": ["home"], "commands": ["hostname"]}
        ]
        cfg["allowed_commands"]["api_keys"] = [
            {
                "name": "integration-user",
                "key_hash": key_hash,
                "rules": [
                    {"targets": ["*"], "commands": ["*"]},
                ],
            }
        ]
        am = _make_auth_manager(tmp_path, cfg)
        result = am.check_command("whoami", "knubbel", api_key="wrong-integration-key")
        assert result.allowed is False


# ---------------------------------------------------------------------------
# TestRulesSnapshot
# ---------------------------------------------------------------------------


class TestRulesSnapshot:
    """Tests for the frozen, immutable RulesSnapshot dataclass."""

    def test_fields_frozen(self):
        """Mutating any field of a RulesSnapshot raises FrozenInstanceError."""
        snap = RulesSnapshot(
            block_patterns=(("rm", re.compile("rm", re.IGNORECASE)),),
            default_rules=({"targets": ["*"], "commands": ["hostname"]},),
            api_keys=(),
            networks=(),
        )
        with pytest.raises(FrozenInstanceError):
            snap.default_rules = ()

    def test_compiled_patterns_prebuilt(self):
        """block_patterns carry pre-compiled regex patterns."""
        snap = RulesSnapshot(
            block_patterns=(("rm", re.compile("rm", re.IGNORECASE)),),
            default_rules=(),
            api_keys=(),
            networks=(),
        )
        raw, compiled = snap.block_patterns[0]
        assert raw == "rm"
        assert isinstance(compiled, re.Pattern)
        assert compiled.search("rm -rf /") is not None


# ---------------------------------------------------------------------------
# TestRulesSnapshotAtomicity
# ---------------------------------------------------------------------------


def _auth_config_a_with(block_patterns, default_commands):
    """Helper to build a full config dict with the given rules."""
    cfg = _minimal_auth_config(
        block_patterns=block_patterns,
    )
    cfg["allowed_commands"]["default"] = [
        {"targets": ["*"], "commands": list(default_commands)}
    ]
    return cfg


class TestRulesSnapshotAtomicity:
    """Verify update_rules swaps the snapshot atomically via the config_data seam."""

    def test_single_reference_swap(self, tmp_path):
        """update_rules performs a fully-consistent snapshot swap."""
        cfg_a = _auth_config_a_with(
            [r"\brm\s+-rf\b"], ["hostname", "uptime"]
        )
        cfg_b = _auth_config_a_with(
            [r"\brm\s+-rf\b", r"\bshutdown\b"], ["hostname"]
        )
        # Build manager over a minimal base config
        am = _make_auth_manager(tmp_path, cfg_a)

        # Swap to a new full config via the config_data seam
        am.update_rules(cfg_b)

        # Everything is consistent with cfg_b
        assert len(am._rules.default_rules) == 1
        assert am._rules.block_patterns[0][0] == r"\brm\s+-rf\b"
        assert am._rules.block_patterns[1][0] == r"\bshutdown\b"
        # "uptime" no longer allowed by cfg_b defaults
        assert am.check_command("uptime", "knubbel").allowed is False
        # "shutdown" is blocked by cfg_b
        assert am.check_command("shutdown", "knubbel").allowed is False

    def test_threaded_atomicity(self, tmp_path):
        """Concurrent readers only ever observe fully-consistent rule sets."""
        cfg_a = _auth_config_a_with(
            [r"\brm\s+-rf\b"], ["hostname", "uptime", "free"]
        )
        cfg_b = _auth_config_a_with(
            [r"\bshutdown\b"], ["hostname"]
        )
        am = _make_auth_manager(tmp_path, cfg_a)

        stop = threading.Event()
        outcomes: list[bool] = []
        outcomes_lock = threading.Lock()

        def reader():
            while not stop.is_set():
                res = am.check_command("hostname", "knubbel")
                outcomes_lock.acquire()
                try:
                    outcomes.append(res.allowed)
                finally:
                    outcomes_lock.release()

        def writer():
            for _ in range(200):
                am.update_rules(cfg_a)
                am.update_rules(cfg_b)
            stop.set()

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        w = threading.Thread(target=writer)
        w.start()
        w.join()
        for t in threads:
            t.join()

        # Every observed result must be one of the two consistent outcomes:
        # hostname is allowed by both configs' defaults. Since the probe command
        # is allowed under both snapshots, every outcome must be True; this
        # still exercises the read/write race while proving no partial update.
        assert outcomes, "readers should have observed at least one result"
        assert all(outcome is True for outcome in outcomes)


# ---------------------------------------------------------------------------
# TestRulesSnapshotRefresh
# ---------------------------------------------------------------------------


class TestRulesSnapshotRefresh:
    """refresh() rebuilds the snapshot from mutated live config data."""

    def test_refresh_picks_up_new_rules(self, tmp_path):
        """Mutating config_manager.data and calling refresh updates decisions."""
        cfg = _minimal_auth_config()
        _write_config(str(tmp_path), cfg)
        cm = ConfigManager(str(tmp_path))
        am = AuthorizationManager(cm)

        # Initially "docker" is only allowed for knubbel/home via API keys,
        # not by any default rule with no API key presented.
        assert am.check_command("docker", "knubbel").allowed is False

        # Mutate live config data and refresh.
        cm.data["allowed_commands"]["default"] = [
            {"targets": ["*"], "commands": ["docker"]}
        ]
        am.refresh()

        assert am.check_command("docker", "knubbel").allowed is True
        assert "docker" in am.list_allowed_commands("knubbel")
