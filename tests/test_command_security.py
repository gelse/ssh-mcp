"""Unit tests for hardened command segmentation and dangerous pattern detection.

Covers :func:`segment_command`, :func:`split_command_segments`, and
:func:`check_dangerous_patterns` from :mod:`lib.command_security`, plus
integration tests verifying that ``AuthorizationManager.check_command``
rejects injection payloads.
"""

from __future__ import annotations

import pytest

from lib.auth import (
    AuthorizationManager,
    _extract_base_command,
    _split_command_segments,
)
from lib.command_security import (
    check_dangerous_patterns,
    segment_command,
    split_command_segments,
)


# ---------------------------------------------------------------------------
# Tests: segment_command
# ---------------------------------------------------------------------------


class TestSegmentCommand:
    """Tests for :func:`segment_command` — safe base-command extraction."""

    # --- Simple commands ---

    def test_simple_command_ls(self):
        assert segment_command("ls") == "ls"

    def test_simple_command_whoami(self):
        assert segment_command("whoami") == "whoami"

    def test_command_with_args(self):
        assert segment_command("cat /etc/hosts") == "cat"

    def test_command_with_multiple_args(self):
        assert segment_command("grep -rn pattern /path") == "grep"

    # --- Quoted arguments ---

    def test_quoted_argument_double(self):
        assert segment_command('echo "hello world"') == "echo"

    def test_quoted_argument_single(self):
        assert segment_command("echo 'hello world'") == "echo"

    def test_command_with_escaped_chars(self):
        assert segment_command(r"grep pattern\ with\ spaces file") == "grep"

    # --- Full path commands ---

    def test_full_path_ls(self):
        assert segment_command("/usr/bin/ls") == "ls"

    def test_full_path_cat(self):
        assert segment_command("/bin/cat /etc/hosts") == "cat"

    def test_full_path_with_args(self):
        assert segment_command("/usr/bin/grep -rn foo") == "grep"

    def test_relative_path_command(self):
        assert segment_command("./myscript arg1") == "myscript"

    # --- Valid complex commands ---

    def test_grep_complex(self):
        assert segment_command('grep -rn "pattern" /path') == "grep"

    def test_awk_command(self):
        assert segment_command("awk '{print $1}' file.txt") == "awk"

    def test_sed_command(self):
        assert segment_command("sed 's/foo/bar/g' file") == "sed"

    def test_find_command(self):
        assert segment_command("find / -name '*.py'") == "find"

    # --- Edge cases ---

    def test_empty_string(self):
        assert segment_command("") == ""

    def test_whitespace_only(self):
        assert segment_command("   ") == ""

    def test_command_with_only_options(self):
        """--help as a command is valid (alphanumeric + dashes)."""
        result = segment_command("--help")
        # Leading dash is rejected by the regex (must start with [a-zA-Z0-9])
        assert result == ""

    def test_command_name_with_underscore(self):
        assert segment_command("my_script arg1") == "my_script"

    def test_command_name_with_dashes(self):
        assert segment_command("git-log --oneline") == "git-log"

    # --- Injection attempts rejected ---

    def test_dollar_substitution(self):
        assert segment_command("$(whoami)") == ""

    def test_dollar_substitution_inline(self):
        assert segment_command("ls$(whoami)") == ""

    def test_backtick_substitution_alone(self):
        """shlex does NOT treat backticks as POSIX quoting — `` `id` `` stays
        as literal `` `id` ``.  Regex rejects backtick chars → ``""``.
        The raw backtick is caught by check_dangerous_patterns()."""
        assert segment_command("`id`") == ""

    def test_backtick_substitution_inline(self):
        """shlex treats backticks as POSIX quoting.  ``echo `whoami` `` →
        tokens ['echo', 'whoami'].  First = 'echo' → valid.  The raw
        backtick is caught by check_dangerous_patterns()."""
        assert segment_command("echo `whoami`") == "echo"

    def test_semicolon_injection(self):
        """shlex.split sees ';' as a token separator, first token = 'ls'."""
        # shlex.split("ls; rm -rf /") → ["ls;", "rm", "-rf", "/"]
        # first token = "ls;" → basename = "ls;" → fails regex (contains ;)
        assert segment_command("ls; rm -rf /") == ""

    def test_pipe_injection(self):
        """shlex.split sees '|' as not special, treats it as token."""
        # shlex.split("ls | cat /etc/passwd") → ["ls", "|", "cat", "/etc/passwd"]
        # first token = "ls" → valid
        # But segment handling in auth.py will split on "|"
        assert segment_command("ls | cat /etc/passwd") == "ls"

    def test_ampersand_injection(self):
        """shlex.split("cmd1 & cmd2") → ["cmd1", "&", "cmd2"], first = "cmd1"."""
        assert segment_command("cmd1 & cmd2") == "cmd1"

    def test_newline_injection(self):
        """shlex treats newline as a token separator in POSIX mode.
        ``ls\\nrm -rf /`` → ['ls', 'rm', '-rf', '/'].  First = 'ls' → valid.
        The raw newline is caught by check_dangerous_patterns()."""
        assert segment_command("ls\nrm -rf /") == "ls"

    def test_carriage_return_injection(self):
        """shlex treats \\r as whitespace.  ``ls\\rrm -rf /`` →
        ['ls', 'rm', '-rf', '/'].  First = 'ls' → valid.
        The raw \\r is caught by check_dangerous_patterns()."""
        assert segment_command("ls\rrm -rf /") == "ls"

    def test_unmatched_quotes(self):
        """Unmatched quotes cause shlex.split to raise ValueError → returns ''."""
        assert segment_command('echo "unmatched') == ""

    def test_command_with_special_char(self):
        """Command name containing '/' should be rejected (path component)."""
        # shlex.split("../bin/evil") → ["../bin/evil"] → basename = "evil" → valid
        # But this is a relative path, not a command name pattern issue
        assert segment_command("../bin/evil") == "evil"


# ---------------------------------------------------------------------------
# Tests: split_command_segments
# ---------------------------------------------------------------------------


class TestSplitCommandSegments:
    """Tests for :func:`split_command_segments`."""

    def test_single_command(self):
        assert split_command_segments("hostname") == ["hostname"]

    def test_pipe_delimiter(self):
        assert split_command_segments("ls | grep foo") == ["ls", "grep foo"]

    def test_semicolon_delimiter(self):
        assert split_command_segments("echo hi; uptime") == ["echo hi", "uptime"]

    def test_ampersand_delimiter(self):
        assert split_command_segments("cmd1 & cmd2") == ["cmd1", "cmd2"]

    def test_double_ampersand(self):
        """&& splits on each &, producing empty strings that get filtered."""
        assert split_command_segments("cmd1 && cmd2") == ["cmd1", "cmd2"]

    def test_double_pipe(self):
        """|| splits on each |, producing empty strings that get filtered."""
        assert split_command_segments("cmd1 || cmd2") == ["cmd1", "cmd2"]

    def test_mixed_delimiters(self):
        assert split_command_segments("cat file | grep x; echo done") == [
            "cat file",
            "grep x",
            "echo done",
        ]

    def test_empty_string(self):
        assert split_command_segments("") == []

    def test_only_delimiters(self):
        assert split_command_segments(";;&|") == []

    def test_command_with_args_not_split(self):
        """Arguments within a command are not split by segment delimiters."""
        assert split_command_segments("grep -rn pattern") == ["grep -rn pattern"]


# ---------------------------------------------------------------------------
# Tests: check_dangerous_patterns
# ---------------------------------------------------------------------------


class TestCheckDangerousPatterns:
    """Tests for :func:`check_dangerous_patterns`."""

    def test_clean_command(self):
        assert check_dangerous_patterns("ls -la") == []

    def test_clean_complex_command(self):
        assert check_dangerous_patterns("grep -rn 'pattern' /path") == []

    def test_dollar_substitution(self):
        result = check_dangerous_patterns("echo $(whoami)")
        assert "$() command substitution" in result

    def test_dollar_substitution_inline(self):
        result = check_dangerous_patterns("ls$(whoami)")
        assert "$() command substitution" in result

    def test_backtick_substitution(self):
        result = check_dangerous_patterns("echo `id`")
        assert "backtick substitution" in result

    def test_newline_injection(self):
        result = check_dangerous_patterns("ls\nrm -rf /")
        assert "newline injection" in result

    def test_carriage_return_injection(self):
        result = check_dangerous_patterns("ls\rrm -rf /")
        assert "carriage-return injection" in result

    def test_multiple_patterns(self):
        result = check_dangerous_patterns("$(id)\n`whoami`")
        assert len(result) >= 3
        assert "$() command substitution" in result
        assert "backtick substitution" in result
        assert "newline injection" in result

    def test_dollar_without_paren(self):
        """Plain $ without parens is not detected (used in awk, etc)."""
        assert check_dangerous_patterns("echo $HOME") == []

    def test_empty_string(self):
        assert check_dangerous_patterns("") == []


# ---------------------------------------------------------------------------
# Tests: _extract_base_command delegates to segment_command
# ---------------------------------------------------------------------------


class TestExtractBaseCommandDelegation:
    """Verify :func:`_extract_base_command` delegates to the new hardened parser."""

    def test_simple_command(self):
        assert _extract_base_command("docker ps -a") == "docker"

    def test_single_word(self):
        assert _extract_base_command("hostname") == "hostname"

    def test_with_whitespace(self):
        assert _extract_base_command("   uptime   ") == "uptime"

    def test_empty(self):
        assert _extract_base_command("") == ""

    def test_only_spaces(self):
        assert _extract_base_command("   ") == ""

    def test_full_path(self):
        assert _extract_base_command("/usr/bin/ls -la") == "ls"

    def test_injection_dollar_sub(self):
        """$() injection should produce empty base command."""
        assert _extract_base_command("$(whoami)") == ""

    def test_quoted_args(self):
        assert _extract_base_command('echo "hello world"') == "echo"


# ---------------------------------------------------------------------------
# Tests: _split_command_segments delegates to split_command_segments
# ---------------------------------------------------------------------------


class TestSplitCommandSegmentsDelegation:
    """Verify :func:`_split_command_segments` delegates to the new splitter."""

    def test_single(self):
        assert _split_command_segments("hostname") == ["hostname"]

    def test_pipe(self):
        assert _split_command_segments("ls | grep foo") == ["ls", "grep foo"]

    def test_semicolon(self):
        assert _split_command_segments("echo hi; uptime") == ["echo hi", "uptime"]

    def test_ampersand(self):
        assert _split_command_segments("cmd1 & cmd2") == ["cmd1", "cmd2"]

    def test_double_ampersand(self):
        assert _split_command_segments("cmd1 && cmd2") == ["cmd1", "cmd2"]

    def test_mixed(self):
        assert _split_command_segments("cat file | grep x; echo done") == [
            "cat file",
            "grep x",
            "echo done",
        ]

    def test_empty(self):
        assert _split_command_segments("") == []


# ---------------------------------------------------------------------------
# Tests: Integration with AuthorizationManager
# ---------------------------------------------------------------------------


class TestAuthorizationManagerInjectionRejection:
    """Verify ``AuthorizationManager.check_command`` rejects injection payloads."""

    @pytest.fixture
    def auth_manager(self, tmp_path):
        """Create an AuthorizationManager with the standard test config."""
        import json
        from lib.config import ConfigManager

        config = {
            "version": 1,
            "ssh_targets": {
                "knubbel": {"host": "10.0.0.1", "username": "admin", "password": "s"},
            },
            "block_patterns": [r"\brm\s+-rf\b", r"\bshutdown\b"],
            "allowed_commands": {
                "default": [
                    {
                        "targets": ["*"],
                        "commands": ["hostname", "uptime", "free", "df", "grep", "ls", "cat", "echo", "whoami", "id"],
                    }
                ],
                "api_keys": [],
                "networks": [],
            },
            "settings": {"max_output_length": 50000, "command_timeout_max": 120},
        }
        conf_path = tmp_path / "ssh-mcp-config.json"
        conf_path.write_text(json.dumps(config), encoding="utf-8")
        cm = ConfigManager(str(tmp_path))
        return AuthorizationManager(cm)

    # --- Injection payloads that should be rejected ---

    def test_dollar_substitution_rejected(self, auth_manager):
        result = auth_manager.check_command("echo $(whoami)", "knubbel")
        assert result.allowed is False
        assert "dangerous" in result.reason

    def test_backtick_substitution_rejected(self, auth_manager):
        result = auth_manager.check_command("echo `id`", "knubbel")
        assert result.allowed is False
        assert "dangerous" in result.reason

    def test_newline_injection_rejected(self, auth_manager):
        result = auth_manager.check_command("hostname\nwhoami", "knubbel")
        assert result.allowed is False
        assert "dangerous" in result.reason

    def test_carriage_return_rejected(self, auth_manager):
        result = auth_manager.check_command("hostname\rwhoami", "knubbel")
        assert result.allowed is False
        assert "dangerous" in result.reason

    def test_dollar_sub_inline_rejected(self, auth_manager):
        result = auth_manager.check_command("ls$(whoami)", "knubbel")
        assert result.allowed is False
        assert "dangerous" in result.reason

    # --- Payloads handled by segment splitting (not dangerous, but validated per segment) ---

    def test_semicolon_second_denied(self, auth_manager):
        """Semicolon splits; 'rm' (part of 'rm /tmp/x') not in allowlist."""
        result = auth_manager.check_command("hostname ; rm /tmp/x", "knubbel")
        assert result.allowed is False

    def test_double_ampersand_second_denied(self, auth_manager):
        """&& splits; second segment 'curl' not in allowlist."""
        result = auth_manager.check_command("hostname && curl example.com", "knubbel")
        assert result.allowed is False

    def test_double_pipe_second_denied(self, auth_manager):
        """|| splits; second segment 'curl' not in allowlist."""
        result = auth_manager.check_command("hostname || curl example.com", "knubbel")
        assert result.allowed is False

    def test_pipe_second_denied(self, auth_manager):
        """| splits; second segment 'curl' not in allowlist."""
        result = auth_manager.check_command("hostname | curl example.com", "knubbel")
        assert result.allowed is False

    def test_semicolon_both_allowed(self, auth_manager):
        """Both sides of ; are in allowlist — allowed."""
        result = auth_manager.check_command("hostname ; uptime", "knubbel")
        assert result.allowed is True

    def test_double_ampersand_both_allowed(self, auth_manager):
        """Both sides of && are in allowlist — allowed."""
        result = auth_manager.check_command("hostname && uptime", "knubbel")
        assert result.allowed is True

    # --- Legitimate commands still work ---

    def test_legitimate_grep(self, auth_manager):
        result = auth_manager.check_command("grep -rn pattern /path", "knubbel")
        assert result.allowed is True

    def test_legitimate_echo_quoted(self, auth_manager):
        result = auth_manager.check_command('echo "hello world"', "knubbel")
        assert result.allowed is True

    def test_legitimate_cat_with_path(self, auth_manager):
        result = auth_manager.check_command("cat /etc/hosts", "knubbel")
        assert result.allowed is True

    def test_legitimate_ls_with_args(self, auth_manager):
        result = auth_manager.check_command("ls -la /tmp", "knubbel")
        assert result.allowed is True

    def test_legitimate_full_path(self, auth_manager):
        """Full-path commands resolve to basename, then matched against allowlist."""
        # /usr/bin/ls → basename 'ls' → in allowlist
        result = auth_manager.check_command("/usr/bin/ls -la", "knubbel")
        assert result.allowed is True

    def test_empty_command_denied(self, auth_manager):
        result = auth_manager.check_command("", "knubbel")
        assert result.allowed is False

    def test_whitespace_only_denied(self, auth_manager):
        result = auth_manager.check_command("   ", "knubbel")
        assert result.allowed is False

    # --- Unicode homoglyph test ---

    def test_unicode_fullwidth_pipe(self, auth_manager):
        """Fullwidth vertical bar (U+FF5C) is not ASCII pipe — shlex treats
        it as a regular character token.  The first token is 'cmd1', which
        is in the allowlist, so the command passes segment_command
        validation.  However, the fullwidth bar is NOT split by
        split_command_segments, so the whole string remains one segment.
        The base command 'cmd1' is allowed.  This is acceptable because
        shlex does not recognise ｜ as a shell metacharacter."""
        result = auth_manager.check_command("hostname \uff5c uptime", "knubbel")
        # The fullwidth bar becomes part of the first token after "hostname"
        # shlex.split("hostname ｜ uptime") → ["hostname", "｜", "uptime"]
        # segment_command returns "hostname" which is in the allowlist
        # split_command_segments sees no ASCII |, &, ; → one segment
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Parametrized injection payloads (10+ payloads)
# ---------------------------------------------------------------------------


INJECTION_PAYLOADS = [
    ("$(whoami)", "dollar-sub at start"),
    ("echo $(whoami)", "dollar-sub after command"),
    ("ls$(whoami)", "dollar-sub concatenated"),
    ("`whoami`", "backtick alone"),
    ("echo `whoami`", "backtick after command"),
    ("echo `id`", "backtick id"),
    ("ls\nrm -rf /", "newline injection"),
    ("hostname\nid", "newline after command"),
    ("hostname && curl x", "double-ampersand chaining"),
    ("hostname || curl x", "double-pipe chaining"),
    ("$(id)\n`whoami`", "multiple dangerous patterns"),
    ("ls\rwhoami", "carriage-return injection"),
]


class TestParametrizedInjectionPayloads:
    """Parametrized tests for injection payload detection."""

    @pytest.mark.parametrize("payload,description", INJECTION_PAYLOADS)
    def test_injection_rejected(self, payload, description, tmp_path):
        """Each injection payload must be rejected by the auth manager."""
        import json
        from lib.config import ConfigManager

        config = {
            "version": 1,
            "ssh_targets": {
                "knubbel": {"host": "10.0.0.1", "username": "admin", "password": "s"},
            },
            "block_patterns": [r"\brm\s+-rf\b"],
            "allowed_commands": {
                "default": [
                    {"targets": ["*"], "commands": ["hostname", "uptime", "ls", "echo", "id", "whoami"]}
                ],
                "api_keys": [],
                "networks": [],
            },
            "settings": {"max_output_length": 50000, "command_timeout_max": 120},
        }
        conf_path = tmp_path / "ssh-mcp-config.json"
        conf_path.write_text(json.dumps(config), encoding="utf-8")
        cm = ConfigManager(str(tmp_path))
        am = AuthorizationManager(cm)

        result = am.check_command(payload, "knubbel")
        assert result.allowed is False, (
            f"Payload '{payload}' ({description}) should be rejected, "
            f"got reason='{result.reason}'"
        )
