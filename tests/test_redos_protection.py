"""Unit tests for the ReDoS protection module.

Covers the three defense layers implemented in :mod:`lib.redos_protection`:
static analysis (:func:`check_redos_risk`), safe compilation
(:func:`compile_safe_pattern`), and timeout-bounded matching
(:func:`safe_regex_search`).
"""

from __future__ import annotations

import re
import time

import pytest

from lib.constants import DEFAULT_REDOGS_TIMEOUT_SECONDS, REDOGS_DANGEROUS_PATTERNS
from lib.redos_protection import check_redos_risk, compile_safe_pattern, safe_regex_search


# ---------------------------------------------------------------------------
# Static analysis -- check_redos_risk
# ---------------------------------------------------------------------------


class TestCheckRedosRisk:
    """Known dangerous constructs are flagged, safe patterns are not."""

    @pytest.mark.parametrize(
        "dangerous",
        [
            "(a+)+",   # nested quantifiers: star/plus on a group
            "(a*)*",   # nested quantifiers: star on a group
            "(a+)*",   # nested quantifiers: mixed
            "(a*)+",   # nested quantifiers: mixed
            "(a|a)+",  # overlapping alternation with a quantifier
            "(ab|a)+", # overlapping alternation with a quantifier
            "(a+)+x",  # nested quantifier embedded in a larger pattern
        ],
    )
    def test_dangerous_patterns_detected(self, dangerous: str) -> None:
        reason = check_redos_risk(dangerous)
        assert reason is not None
        assert "e.g." in reason  # a human-readable risk description

    @pytest.mark.parametrize(
        "safe",
        [
            r"\bsudo\b",        # simple word boundary
            r"[a-z]+",          # character class (no wrapping group quantifier)
            r"^rm\s+-rf$",      # anchored command
            r"(dev|proc|sys)",  # alternation without a quantifier
            r"\b(\w+)\s+\1\b",  # backreferences (no ReDoS risk)
            r"[~/]*/(dev|proc|sys)/",  # protected-path style pattern
        ],
    )
    def test_safe_patterns_pass(self, safe: str) -> None:
        assert check_redos_risk(safe) is None

    def test_empty_string_passes(self) -> None:
        assert check_redos_risk("") is None

    def test_returns_first_risk_reason(self) -> None:
        reasoning = check_redos_risk("(a+)+")
        assert reasoning == "nested quantifiers (e.g. (a+)+)"


# ---------------------------------------------------------------------------
# Safe compilation -- compile_safe_pattern
# ---------------------------------------------------------------------------


class TestCompileSafePattern:
    """compile_safe_pattern returns a working pattern with the safety flag."""

    def test_compiles_valid_pattern_with_ignorcease(self) -> None:
        compiled = compile_safe_pattern(r"\bsudo\b", re.IGNORECASE)
        assert compiled is not None
        assert compiled.search("  SUDO  ") is not None
        assert compiled.search("unsudoed") is None

    def test_flags_include_limited_time_when_available(self) -> None:
        # On Python 3.13+ the LIMITED_TIME flag should be OR-ed in.
        compiled = compile_safe_pattern(r"a+")
        if hasattr(re, "LIMITED_TIME"):
            assert compiled.flags & int(re.LIMITED_TIME)  # type: ignore[attr-defined]
        else:
            # On older interpreters the pattern still compiles normally.
            assert compiled.search("aaa") is not None

    def test_invalid_regex_raises(self) -> None:
        with pytest.raises(re.error):
            compile_safe_pattern("(unclosed")

    def test_detectors_themselves_are_valid(self) -> None:
        """The bundled detector patterns must be compilable on all versions."""
        for detector in REDOGS_DANGEROUS_PATTERNS:
            assert re.compile(detector) is not None


# ---------------------------------------------------------------------------
# Timeout-bounded matching -- safe_regex_search
# ---------------------------------------------------------------------------


class TestSafeRegexSearch:
    """safe_regex_search matches normally but never hangs on slow patterns."""

    def test_normal_match(self) -> None:
        compiled = compile_safe_pattern(r"\buname\b")
        result = safe_regex_search(compiled, "uname -a")
        assert result is not None
        assert result.group() == "uname"

    def test_normal_non_match(self) -> None:
        compiled = compile_safe_pattern(r"\buname\b")
        assert safe_regex_search(compiled, "hostname") is None

    def test_slow_match_times_out_to_none(self) -> None:
        """A search that overruns the timeout returns None (no hang), and a
        hung worker thread never blocks the caller."""

        class _SleepingMatch:
            """Fake compiled pattern whose .search sleeps past the timeout."""

            def search(self, text: str) -> None:  # pragma: no cover - never returns
                time.sleep(10.0)
                return None  # type: ignore[unreachable]

        start = time.monotonic()
        # type: ignore[arg-type] -- intentionally passing a fake pattern-like.
        result = safe_regex_search(
            _SleepingMatch(), "input", timeout=0.05  # type: ignore[arg-type]
        )
        elapsed = time.monotonic() - start

        assert result is None
        assert elapsed < 5.0  # returned promptly rather than blocking

    def test_default_timeout_constant_is_positive(self) -> None:
        assert DEFAULT_REDOGS_TIMEOUT_SECONDS > 0
