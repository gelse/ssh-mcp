"""AuthorizationManager: layered command authorization for SSH MCP.

Provides a thread-safe authorization engine that evaluates whether a
command is allowed for a given client context (source IP, API key) and
SSH target.  Uses the chain:

    block_patterns -> default -> api_key -> network -> deny

At each layer only rules matching the requested target are evaluated.
Does **not** own config — receives a ConfigManager reference for live data.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass

from lib.crypto import hash_api_key, verify_api_key

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class AuthResult:
    """Result of an authorization check."""

    allowed: bool
    reason: str  # human-readable, e.g. "allowed by default"
    matched_via: str  # "default" | "api_key:<name>" | "network:<name> (<range>)" | "blocked:<pattern>" | "denied"
    api_key_name: str | None = None  # Matched API key name, or None


# ---------------------------------------------------------------------------
# Static helpers (module-level, testable without a ConfigManager)
# ---------------------------------------------------------------------------


def _extract_base_command(command: str) -> str:
    """Extract and validate the base command from a command string.

    Delegates to :func:`lib.command_security.segment_command` which uses
    :func:`shlex.split` for POSIX shell tokenization, strips leading path
    components, and validates the command name against a safe character set.
    """
    from lib.command_security import segment_command

    return segment_command(command)


def _split_command_segments(command: str) -> list[str]:
    """Split command by pipes, ampersands, and semicolons for individual validation.

    Delegates to :func:`lib.command_security.split_command_segments`.
    """
    from lib.command_security import split_command_segments

    return split_command_segments(command)


# ---------------------------------------------------------------------------
# AuthorizationManager
# ---------------------------------------------------------------------------


class AuthorizationManager:
    """Evaluates whether a command is allowed for a given client context and target.

    Uses the layered chain: block_patterns -> default -> api_key -> network -> deny.
    At each layer, only rules matching the requested target are evaluated.

    Does **not** own config — receives a ConfigManager reference for current data.
    """

    def __init__(self, config_manager):
        """Args:
        config_manager: Instance of ``lib.config.ConfigManager``.
                        The manager reads live config via ``config_manager.data``.
        """
        self._config_manager = config_manager
        self._block_patterns: list[str] = []
        self._compiled_block_patterns: list[re.Pattern] = []
        self.update_rules()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_command(
        self,
        command: str,
        target: str,
        source_ip: str | None = None,
        api_key: str | None = None,
    ) -> AuthResult:
        """Evaluate *command* through the full authorization chain.

        Args:
            command: The raw command string to validate.
            target: SSH target ID (e.g. ``"knubbel"``).
            source_ip: Client IP address (from request).  ``None`` means
                       "no source IP available".
            api_key: Raw API key from the ``Authorization`` header.
                     ``None`` means "no API key provided".

        Returns:
            :class:`AuthResult` with ``allowed``, ``reason``, and ``matched_via``.
        """
        # 1. Validate target exists
        if target not in self._config_manager.data.get("ssh_targets", {}):
            logger.debug("Unknown target '%s' — denying", target)
            return AuthResult(False, f"Unknown target '{target}'", "denied", None)

        # 2. Check block_patterns
        block_result = self._check_block_patterns(command)
        if block_result is not None:
            return block_result

        # 2b. Check dangerous shell patterns ($(), backticks, newlines)
        dangerous = self._check_dangerous_patterns(command)
        if dangerous is not None:
            return dangerous

        # 3. Check piped/chained commands — each segment runs the FULL chain
        segments = _split_command_segments(command)
        if len(segments) > 1:
            logger.debug("Command contains %d segments — validating each", len(segments))
            for seg in segments:
                segment_result = self.check_command(seg, target, source_ip, api_key)
                if not segment_result.allowed:
                    logger.debug(
                        "Segment '%s' denied: %s — failing whole command",
                        seg,
                        segment_result.reason,
                    )
                    return segment_result
            logger.debug("All %d segments passed — continuing with original command", len(segments))

        # 4. Check DEFAULT rules
        allowed_cmds = self._config_manager.data.get("allowed_commands", {})
        default_rules = allowed_cmds.get("default", [])
        logger.debug("Checking default rules for target '%s'", target)
        if self._is_command_allowed_by_rules(command, default_rules, target):
            logger.info("Command '%s' allowed by default for target '%s'", command, target)
            return AuthResult(True, "allowed by default", "default", None)

        # 5. Check API key
        api_entry = self._match_api_key(api_key)
        if api_entry is not None:
            logger.debug("API key matched: %s", api_entry["name"])
            if self._is_command_allowed_by_rules(command, api_entry["rules"], target):
                logger.info(
                    "Command '%s' allowed by API key '%s' for target '%s'",
                    command,
                    api_entry["name"],
                    target,
                )
                return AuthResult(
                    True,
                    f"allowed by API key {api_entry['name']}",
                    f"api_key:{api_entry['name']}",
                    api_entry["name"],
                )

        # 6. Check network
        net_entry = self._match_network(source_ip)
        if net_entry is not None:
            logger.debug("Network matched: %s (%s)", net_entry["name"], net_entry["range"])
            if self._is_command_allowed_by_rules(command, net_entry["rules"], target):
                logger.info(
                    "Command '%s' allowed by network '%s' (%s) for target '%s'",
                    command,
                    net_entry["name"],
                    net_entry["range"],
                    target,
                )
                return AuthResult(
                    True,
                    f"allowed by network {net_entry['name']} ({net_entry['range']})",
                    f"network:{net_entry['name']} ({net_entry['range']})",
                    None,
                )

        # 7. Deny
        reason = f"denied: not in any allow list for target {target}"
        logger.info("Command '%s' denied for target '%s'", command, target)
        return AuthResult(False, reason, "denied", None)

    def list_allowed_commands(
        self,
        target: str,
        source_ip: str | None = None,
        api_key: str | None = None,
    ) -> list[str]:
        """Collect all command base names allowed for this client context and target.

        Args:
            target: SSH target ID (mandatory).
            source_ip: Client IP address.  ``None`` means not available.
            api_key: Raw API key.  ``None`` means not provided.

        Returns:
            Deduplicated, sorted list of command names (or ``["*"]`` if full
            access).  Returns ``[]`` if the target does not exist or nothing
            is allowed.

        Note:
            Block patterns are **not** considered — the caller is responsible
            for communicating that block patterns may further restrict commands.
        """
        # 1. Target must exist
        if target not in self._config_manager.data.get("ssh_targets", {}):
            return []

        allowed_cmds = self._config_manager.data.get("allowed_commands", {})
        commands: set[str] = set()

        # 2. Default layer
        default_rules = allowed_cmds.get("default", [])
        collected = self._collect_commands_for_target(default_rules, target)
        if "*" in collected:
            return ["*"]
        commands.update(collected)

        # 3. API key layer
        api_entry = self._match_api_key(api_key)
        if api_entry is not None:
            collected = self._collect_commands_for_target(api_entry["rules"], target)
            if "*" in collected:
                return ["*"]
            commands.update(collected)

        # 4. Network layer
        net_entry = self._match_network(source_ip)
        if net_entry is not None:
            collected = self._collect_commands_for_target(net_entry["rules"], target)
            if "*" in collected:
                return ["*"]
            commands.update(collected)

        return sorted(commands)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_dangerous_patterns(self, command: str) -> AuthResult | None:
        """Scan *command* for injection metacharacters.

        Calls :func:`lib.command_security.check_dangerous_patterns` and
        returns a denied :class:`AuthResult` for each dangerous pattern
        found.

        Returns ``None`` if the command is clean.
        """
        from lib.command_security import check_dangerous_patterns

        found = check_dangerous_patterns(command)
        if found:
            reason = f"blocked: dangerous shell pattern(s) — {', '.join(found)}"
            logger.debug("Command '%s' %s", command, reason)
            return AuthResult(False, reason, "blocked:dangerous-patterns", None)
        return None

    def update_rules(self) -> None:
        """Refresh the cached, compiled block patterns from live config.

        Compiles each configured ``block_patterns`` entry into a
        :class:`re.Pattern` exactly once.  Recompilation only happens when
        the raw pattern list actually changes, so per-request authorization
        never re-compiles unchanged patterns.

        Thread safety: only the last writer's pattern list survives, which
        is consistent with the config being replaced atomically by
        :class:`~lib.config.ConfigManager`.
        """
        patterns = self._config_manager.data.get("block_patterns", [])
        if patterns == self._block_patterns:
            return
        logger.debug(
            "Compiling %d block pattern(s) (previous: %d)",
            len(patterns),
            len(self._block_patterns),
        )
        self._block_patterns = list(patterns)
        self._compiled_block_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in patterns
        ]

    def _check_block_patterns(self, command: str) -> AuthResult | None:
        """Check *command* against all configured block patterns.

        Returns an :class:`AuthResult` if a pattern matches, or ``None`` if
        the command passes all patterns.
        """
        self.update_rules()
        for pattern, compiled in zip(
            self._block_patterns, self._compiled_block_patterns
        ):
            if compiled.search(command):
                logger.debug(
                    "Command '%s' blocked by pattern '%s'", command, pattern
                )
                return AuthResult(
                    False,
                    f"blocked by pattern '{pattern}'",
                    f"blocked:{pattern}",
                    None,
                )
        return None

    def _match_api_key(self, api_key: str | None) -> dict | None:
        """Verify *api_key* against stored hashes and return matching entry.

        Uses :func:`~lib.crypto.verify_api_key` which supports both the
        legacy ``sha256:`` format and the newer PBKDF2 format.

        Returns the entry dict (``name``, ``key_hash``, ``rules``) or
        ``None`` if *api_key* is falsy or does not match any entry.
        """
        if not api_key:
            return None

        for entry in (
            self._config_manager.data.get("allowed_commands", {})
            .get("api_keys", [])
        ):
            if verify_api_key(api_key, entry["key_hash"]):
                return entry
        return None

    def _match_network(self, source_ip: str | None) -> dict | None:
        """Parse *source_ip* and find a matching network entry.

        Returns the entry dict (``name``, ``range``, ``rules``) or ``None``
        if *source_ip* is falsy, invalid, or does not match any configured
        network range.
        """
        if not source_ip:
            return None

        try:
            ip = ipaddress.ip_address(source_ip)
        except ValueError:
            return None

        for entry in (
            self._config_manager.data.get("allowed_commands", {})
            .get("networks", [])
        ):
            try:
                net = ipaddress.ip_network(entry["range"], strict=False)
            except ValueError:
                continue
            if ip in net:
                return entry
        return None

    def _is_command_allowed_by_rules(
        self, command: str, rules: list[dict], target: str
    ) -> bool:
        """Check if any *rule* matching *target* allows *command*.

        Handles base-command extraction and the ``"*"`` wildcard.
        """
        base_cmd = _extract_base_command(command)
        if not base_cmd:
            return False

        for rule in rules:
            targets = rule.get("targets", [])
            commands = rule.get("commands", [])

            # Rule must apply to the requested target
            if "*" not in targets and target not in targets:
                continue

            # Wildcard command or exact base-command match
            if "*" in commands or base_cmd in commands:
                return True

        return False

    def _collect_commands_for_target(
        self, rules: list[dict], target: str
    ) -> set[str]:
        """Collect all commands that apply to *target* from a rule list.

        Returns a ``set`` of command strings.  If any matching rule has
        ``commands=["*"]``, returns ``{"*"}`` immediately.
        """
        result: set[str] = set()
        for rule in rules:
            targets = rule.get("targets", [])
            commands = rule.get("commands", [])

            # Rule must apply to the requested target
            if "*" not in targets and target not in targets:
                continue

            if "*" in commands:
                return {"*"}

            result.update(commands)
        return result
