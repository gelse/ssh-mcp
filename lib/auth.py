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

from lib.constants import PROTECTED_REDIRECT_TARGET_RE
from lib.crypto import hash_api_key, verify_api_key

logger = logging.getLogger(__name__)

# Defense-in-depth: redirection targets into protected pseudofilesystem paths.
_PROTECTED_REDIRECT_TARGET_RE = re.compile(PROTECTED_REDIRECT_TARGET_RE)


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


@dataclass(frozen=True)
class RulesSnapshot:
    """Immutable snapshot of all authorization rules.

    All regex compilation happens once at construction; readers only ever
    observe a fully-built, atomically-swapped snapshot.
    """

    block_patterns: tuple[tuple[str, re.Pattern[str]], ...]
    default_rules: tuple[dict[str, object], ...]
    api_keys: tuple[dict[str, object], ...]
    networks: tuple[dict[str, object], ...]


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


def _strip_redirects(command: str) -> str:
    """Strip shell redirection operators before command segmentation.

    Delegates to :func:`lib.command_security.strip_redirects` so ``2>&1``,
    ``>file``, etc. are removed before :func:`_split_command_segments` runs,
    preventing phantom segments (e.g. the ``"1"`` in ``2>&1``).
    """
    from lib.command_security import strip_redirects

    return strip_redirects(command)


# ---------------------------------------------------------------------------
# AuthorizationManager
# ---------------------------------------------------------------------------


class AuthorizationManager:
    """Evaluates whether a command is allowed for a given client context and target.

    Uses the layered chain: block_patterns -> default -> api_key -> network -> deny.
    At each layer, only rules matching the requested target are evaluated.

    Does **not** own config — receives a ConfigManager reference for current data.

    Thread safety
    -------------
    This manager is lock-free.  All authorization state lives in
    ``self._rules``, a frozen (immutable) :class:`RulesSnapshot`.  Updates
    happen only in :meth:`update_rules`, which builds a fresh snapshot and
    swaps the single ``self._rules`` reference atomically (single-reference-read
    pattern); concurrent readers therefore observe a complete, consistent rule
    set and never a partial update.  ``check_command`` and
    ``list_allowed_commands`` additionally read live config via
    ``config_manager.data`` for target-existence checks — that read is
    protected by :class:`~lib.config.ConfigManager`'s own ``_lock`` (a shallow
    copy is returned) and is independent of the frozen snapshot.
    """

    def __init__(self, config_manager):
        """Args:
        config_manager: Instance of ``lib.config.ConfigManager``.
                        The manager reads live config via ``config_manager.data``.
        """
        self._config_manager = config_manager
        self._rules: RulesSnapshot = self._build_snapshot(
            self._config_manager.data
        )
        self._config_manager.on_config_change(self.refresh)

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

        # 3. Check redirection targets into protected paths (defense-in-depth)
        redirect_target = self._check_redirection_targets(command)
        if redirect_target is not None:
            return redirect_target

        # 3b. Check piped/chained commands — each segment runs the FULL chain
        segments = _split_command_segments(_strip_redirects(command))
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
        default_rules = self._rules.default_rules
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

        commands: set[str] = set()

        # 2. Default layer
        default_rules = self._rules.default_rules
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

    def _check_redirection_targets(self, command: str) -> AuthResult | None:
        """Deny redirections whose target is a protected pseudofilesystem path.

        Defense-in-depth check run on the **raw** command (all ``>`` intact),
        independent of the operator-supplied ``block_patterns`` list.  Matches
        redirections into ``/dev/``, ``/proc/``, or ``/sys/`` (e.g. ``>/dev/sda``,
        ``> /proc/self/fd/0``) so the invariant is preserved even if an operator
        removes the corresponding block pattern.

        Returns a denied :class:`AuthResult` if a protected target is detected,
        or ``None`` if the command is clean.
        """
        if _PROTECTED_REDIRECT_TARGET_RE.search(command):
            logger.debug("Command '%s' redirects into a protected path", command)
            return AuthResult(
                False,
                "redirection target is a protected path",
                "blocked:redirection-target",
                None,
            )
        return None

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

    def update_rules(self, config_data: dict | None = None) -> None:
        """Rebuild an immutable RulesSnapshot and atomically swap ``self._rules``.

        Args:
            config_data: Optional complete config dict. If omitted, falls back
                to ``self._config_manager.data``.
        """
        data = self._config_manager.data if config_data is None else config_data
        self._rules = self._build_snapshot(data)  # single atomic reference swap

    def refresh(self) -> None:
        """Callback-compatible wrapper around ``update_rules``."""
        self.update_rules()

    def _build_snapshot(self, data: dict) -> RulesSnapshot:
        """Construct a :class:`RulesSnapshot` from a complete config dict.

        Args:
            data: A complete post-validation config dict (e.g.
                ``config_manager.data``).

        Returns:
            A frozen :class:`RulesSnapshot` with block patterns compiled once.
        """
        allowed_commands = data.get("allowed_commands", {})
        return RulesSnapshot(
            block_patterns=tuple(
                (p, re.compile(p, re.IGNORECASE))
                for p in data.get("block_patterns", [])
            ),
            default_rules=tuple(allowed_commands.get("default", [])),
            api_keys=tuple(allowed_commands.get("api_keys", [])),
            networks=tuple(allowed_commands.get("networks", [])),
        )

    def _check_block_patterns(self, command: str) -> AuthResult | None:
        """Check *command* against all configured block patterns.

        Returns an :class:`AuthResult` if a pattern matches, or ``None`` if
        the command passes all patterns.
        """
        for pattern, compiled in self._rules.block_patterns:
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

        for entry in self._rules.api_keys:
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

        for entry in self._rules.networks:
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
