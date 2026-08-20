"""Tests for :mod:`lib.sanitize` — command, server-name, and log-string sanitizers."""

from __future__ import annotations

import pytest

from pathlib import Path

import pytest

from lib.exceptions import AuthorizationError, ConfigValidationError
from lib.sanitize import (
    sanitize_command,
    sanitize_log_string,
    sanitize_target_name,
    validate_log_path,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Null bytes stripped
        ("echo a\x00b", "echo ab"),
        # ESC control byte stripped (leaves literal sequence text)
        ("\x1b[31mred\x1b[0m", "[31mred[0m"),
        # Tab preserved
        ("ls\t-la", "ls\t-la"),
        # Newline and CR preserved (critical for dangerous-pattern detection)
        ("echo a\nb", "echo a\nb"),
        ("echo a\rb", "echo a\rb"),
        # NFKC homoglyph collapse
        ("\uff4c\uff53 \uff0f\uff45\uff54\uff43", "ls /etc"),
        ("\uff5c", "|"),
        ("\uff04", "$"),
        # Leading/trailing whitespace stripped
        ("  ls -la  ", "ls -la"),
        # Empty / whitespace-only returns empty string
        ("   ", ""),
        ("", ""),
    ],
)
def test_sanitize_command(raw: str, expected: str) -> None:
    """Commands are normalized and ``\\n``/``\\r`` are preserved."""
    assert sanitize_command(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "  host1  ",
        "host1",
        "host_1.beta-x",
        "HOST1.2-3_4",
    ],
)
def test_sanitize_target_name_valid(raw: str) -> None:
    """Valid target names are trimmed and returned unchanged."""
    assert sanitize_target_name(raw) == raw.strip()


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "host name",
        "host/name",
        "host@name",
        "host#name",
        "host!name",
        "host\\name",
        "host;name",
        "host&name",
        "host|name",
        "host$name",
        "ünïcode",
        "名字",
        "host\nname",
        "h" * 129,  # too long (129 chars)
    ],
)
def test_sanitize_target_name_invalid_raises(raw: str) -> None:
    """Invalid target names raise ``AuthorizationError``."""
    with pytest.raises(AuthorizationError):
        sanitize_target_name(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "host\nname",            # newline
        "host\rname",            # carriage return
        "host\x00name",          # null byte
        "host\r\nname",          # CRLF
        "host\n\n\nname",        # multiple newlines
        "host\x1b[31mred\x1b[0m",  # ANSI escape / color sequence
        "host\a\b\v\fname",      # other control characters
    ],
)
def test_sanitize_target_name_log_injection_raises(raw: str) -> None:
    """Target names carrying log-injection payloads (newline/CR/null/ANSI
    control bytes) are rejected."""
    with pytest.raises(AuthorizationError):
        sanitize_target_name(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\nb", "a b"),
        ("a\r\nb", "a b"),
        ("a\n\n\nb", "a b"),
        ("hello", "hello"),
        ("", ""),
    ],
)
def test_sanitize_log_string_collapses_newlines(raw: str, expected: str) -> None:
    """Newlines/carriage returns collapse to a single space."""
    assert sanitize_log_string(raw) == expected


def test_sanitize_log_string_non_str_returns_empty() -> None:
    """Non-string values sanitize to an empty string."""
    assert sanitize_log_string(None) == ""


def test_sanitize_command_preserves_newline_for_dangerous_patterns() -> None:
    """Newline preservation guarantees downstream injection detection."""
    assert "\n" in sanitize_command("echo a\nrm -rf /")
    assert "\r" in sanitize_command("echo a\rrm -rf /")


# ---------------------------------------------------------------------------
# validate_log_path tests
# ---------------------------------------------------------------------------


class TestValidateLogPath:
    """Tests for :func:`validate_log_path` — path safety validation."""

    def test_valid_simple_path(self) -> None:
        """An absolute path without traversal resolves correctly."""
        result = validate_log_path("/tmp/logs")
        assert result == Path("/tmp/logs")

    def test_valid_relative_path(self) -> None:
        """A relative path resolves to an absolute path."""
        result = validate_log_path("logs")
        assert result.is_absolute()

    def test_empty_string_rejected(self) -> None:
        """An empty string raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError, match="must not be empty"):
            validate_log_path("")

    def test_whitespace_only_rejected(self) -> None:
        """A whitespace-only string raises ConfigValidationError."""
        with pytest.raises(ConfigValidationError, match="must not be empty"):
            validate_log_path("   ")

    def test_null_bytes_rejected(self) -> None:
        """Paths containing null bytes are rejected."""
        with pytest.raises(ConfigValidationError, match="null bytes"):
            validate_log_path("/tmp/logs\x00/etc/passwd")

    def test_null_bytes_in_middle_rejected(self) -> None:
        """Null bytes embedded in the middle of a path are rejected."""
        with pytest.raises(ConfigValidationError, match="null bytes"):
            validate_log_path("/tmp\x00/logs")

    def test_path_normalization(self) -> None:
        """Traversal sequences (``../``) are resolved in the output."""
        result = validate_log_path("/tmp/logs/../logs/./app.log")
        assert result == Path("/tmp/logs/app.log")

    def test_base_dir_containment_ok(self) -> None:
        """A path inside base_dir passes validation."""
        result = validate_log_path(
            "/tmp/logs/app.log", base_dir="/tmp/logs"
        )
        assert result == Path("/tmp/logs/app.log")

    def test_base_dir_exact_match(self) -> None:
        """A path equal to base_dir passes validation."""
        result = validate_log_path("/tmp/logs", base_dir="/tmp/logs")
        assert result == Path("/tmp/logs")

    def test_base_dir_escape_rejected(self) -> None:
        """Traversal that escapes base_dir is rejected."""
        with pytest.raises(ConfigValidationError, match="escapes"):
            validate_log_path(
                "/tmp/logs/../../etc/passwd", base_dir="/tmp/logs"
            )

    def test_symlink_escape_rejected(self, tmp_path: Path) -> None:
        """A symlink pointing outside base_dir is detected and rejected."""
        link = tmp_path / "escape_link"
        link.symlink_to("/etc")
        with pytest.raises(ConfigValidationError):
            validate_log_path(
                str(link / "ssh-mcp.log"), base_dir=str(tmp_path)
            )

    def test_symlink_within_base_dir_allowed(self, tmp_path: Path) -> None:
        """A symlink that resolves within base_dir is accepted."""
        target_dir = tmp_path / "real_logs"
        target_dir.mkdir()
        link = tmp_path / "link_logs"
        link.symlink_to(target_dir)
        result = validate_log_path(
            str(link / "app.log"), base_dir=str(tmp_path)
        )
        assert result == target_dir / "app.log"
