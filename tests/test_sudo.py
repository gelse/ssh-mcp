"""Tests for lib/sudo.py — centralized sudo command handling."""

import pytest

from lib.sudo import SudoHandler


# ---------------------------------------------------------------------------
# wrap_sudo_command
# ---------------------------------------------------------------------------


class TestWrapSudoCommand:
    """Tests for SudoHandler.wrap_sudo_command()."""

    def test_wrap_with_password(self):
        """sudo=True with password uses 'sudo -S -p \\'\\''."""
        result = SudoHandler.wrap_sudo_command("whoami", sudo=True, sudo_password="secret")
        assert result == "sudo -S -p '' whoami"

    def test_wrap_without_password(self):
        """sudo=True without password uses 'sudo -n'."""
        result = SudoHandler.wrap_sudo_command("whoami", sudo=True, sudo_password=None)
        assert result == "sudo -n whoami"

    def test_no_wrap_when_sudo_false(self):
        """sudo=False leaves command unchanged."""
        result = SudoHandler.wrap_sudo_command("whoami", sudo=False, sudo_password="secret")
        assert result == "whoami"

    def test_wrap_complex_command(self):
        """Wrapping works with pipe and redirect commands."""
        result = SudoHandler.wrap_sudo_command(
            "grep error /var/log/syslog | head -20",
            sudo=True,
            sudo_password="secret",
        )
        assert result == "sudo -S -p '' grep error /var/log/syslog | head -20"

    def test_wrap_empty_command(self):
        """Empty command wrapped with sudo still prepends flags."""
        result = SudoHandler.wrap_sudo_command("", sudo=True, sudo_password=None)
        assert result == "sudo -n "

    def test_wrap_empty_command_password(self):
        """Empty command with password flag wraps correctly."""
        result = SudoHandler.wrap_sudo_command("", sudo=True, sudo_password="secret")
        assert result == "sudo -S -p '' "

    def test_wrap_already_sudo_prefixed(self):
        """Command already containing 'sudo' is not special-cased by wrapper."""
        result = SudoHandler.wrap_sudo_command(
            "sudo whoami", sudo=True, sudo_password="secret"
        )
        assert result == "sudo -S -p '' sudo whoami"

    def test_wrap_command_with_special_characters(self):
        """Commands with special characters are wrapped correctly."""
        result = SudoHandler.wrap_sudo_command(
            """echo 'hello "world"' > /tmp/out && true""",
            sudo=True,
            sudo_password=None,
        )
        assert result == """sudo -n echo 'hello "world"' > /tmp/out && true"""

    def test_wrap_command_with_env_vars(self):
        """Commands with environment variable prefixes are wrapped."""
        result = SudoHandler.wrap_sudo_command(
            "FOO=bar whoami", sudo=True, sudo_password="secret"
        )
        assert result == "sudo -S -p '' FOO=bar whoami"


# ---------------------------------------------------------------------------
# is_sudo_command
# ---------------------------------------------------------------------------


class TestIsSudoCommand:
    """Tests for SudoHandler.is_sudo_command()."""

    def test_plain_sudo(self):
        """Plain 'sudo cmd' is detected."""
        assert SudoHandler.is_sudo_command("sudo whoami") is True

    def test_sudo_with_user_flag(self):
        """'sudo -u root cmd' is detected."""
        assert SudoHandler.is_sudo_command("sudo -u root whoami") is True

    def test_sudo_with_env_prefix(self):
        """'VAR=val sudo cmd' is detected (sudo as a word boundary)."""
        assert SudoHandler.is_sudo_command("FOO=bar sudo whoami") is True

    def test_no_sudo_in_command(self):
        """Command without sudo returns False."""
        assert SudoHandler.is_sudo_command("whoami") is False

    def test_pseudo_not_sudo(self):
        """'pseudo' is not 'sudo' (word boundary required)."""
        assert SudoHandler.is_sudo_command("pseudo whoami") is False

    def test_case_insensitive(self):
        """'SUDO' and 'Sudo' are detected."""
        assert SudoHandler.is_sudo_command("SUDO whoami") is True
        assert SudoHandler.is_sudo_command("Sudo whoami") is True

    def test_empty_command(self):
        """Empty command does not contain sudo."""
        assert SudoHandler.is_sudo_command("") is False

    def test_sudo_at_end_of_line(self):
        """'cmd | sudo' is detected."""
        assert SudoHandler.is_sudo_command("cat /etc/passwd | sudo tee /tmp/out") is True


# ---------------------------------------------------------------------------
# validate_sudo
# ---------------------------------------------------------------------------


class TestValidateSudo:
    """Tests for SudoHandler.validate_sudo()."""

    def test_valid_sudo_true_no_sudo_in_command(self):
        """sudo=True with a plain command passes validation."""
        result = SudoHandler.validate_sudo("whoami", sudo=True)
        assert result is None

    def test_valid_sudo_false(self):
        """sudo=False always passes validation."""
        result = SudoHandler.validate_sudo("sudo whoami", sudo=False)
        assert result is None

    def test_invalid_sudo_true_with_sudo_in_command(self):
        """sudo=True with 'sudo whoami' returns an error message."""
        result = SudoHandler.validate_sudo("sudo whoami", sudo=True)
        assert result is not None
        assert "ERROR" in result
        assert "must not contain 'sudo'" in result

    def test_invalid_case_insensitive(self):
        """sudo=True with 'SUDO whoami' returns an error message."""
        result = SudoHandler.validate_sudo("SUDO whoami", sudo=True)
        assert result is not None
        assert "ERROR" in result

    def test_valid_empty_command_sudo_false(self):
        """Empty command with sudo=False passes."""
        result = SudoHandler.validate_sudo("", sudo=False)
        assert result is None

    def test_valid_empty_command_sudo_true(self):
        """Empty command with sudo=True passes (no 'sudo' word in empty string)."""
        result = SudoHandler.validate_sudo("", sudo=True)
        assert result is None
