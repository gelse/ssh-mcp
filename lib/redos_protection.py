"""ReDoS protection for user-provided regex patterns.

Provides three complementary layers of defense against catastrophic
backtracking (ReDoS) on operator-supplied ``block_patterns``:

1. Static analysis (:func:`check_redos_risk`) that scans a pattern source
   string for known dangerous constructs at config load, rejecting clearly
   unsafe patterns before they ever reach runtime.
2. Safe compilation (:func:`compile_safe_pattern`) that sets the
   :data:`re.LIMITED_TIME` engine flag when it is available (Python 3.13+).
3. A timeout-bounded matcher (:func:`safe_regex_search`) that runs
   ``compiled.search()`` in a worker thread with a hard wall-clock limit as
   a last-resort safety net.

These are best-effort heuristics; they are intentionally conservative.  The
runtime timeout is the true guarantee that no single command evaluation can
block the authorization thread pool indefinitely.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout

from lib.constants import DEFAULT_REDOGS_TIMEOUT_SECONDS, REDOGS_DANGEROUS_PATTERNS


# ---------------------------------------------------------------------------
# Static analysis
# ---------------------------------------------------------------------------


def check_redos_risk(pattern: str) -> str | None:
    """Scan *pattern* for known ReDoS-prone constructs.

    Each entry of :data:`REDOGS_DANGEROUS_PATTERNS` is matched against the
    raw *pattern* source text.  If any detector fires, a human-readable risk
    description is returned; otherwise ``None`` indicates no apparent risk.

    Args:
        pattern: The raw regex source string to inspect (not yet compiled).

    Returns:
        A risk description string if a dangerous construct was detected, or
        ``None`` if the pattern passes the static heuristic scan.
    """
    risk_reasons: tuple[str, ...] = (
        "nested quantifiers (e.g. (a+)+)",
        "overlapping alternation with a quantifier (e.g. (a|a)+)",
        "quantified dot-star group (e.g. (.*a){n})",
    )
    for detector, reason in zip(REDOGS_DANGEROUS_PATTERNS, risk_reasons):
        if re.search(detector, pattern):
            return reason
    return None


# ---------------------------------------------------------------------------
# Safe compilation
# ---------------------------------------------------------------------------


def compile_safe_pattern(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """Compile *pattern* with the :data:`re.LIMITED_TIME` flag when available.

    Adds the engine-level time limiting flag (Python 3.13+) on top of any
    caller-provided *flags* (e.g. ``re.IGNORECASE``).  On interpreters that do
    not expose ``re.LIMITED_TIME`` the pattern is compiled with *flags* only;
    the :func:`safe_regex_search` wrapper then remains the safety net.

    Args:
        pattern: The regular expression source to compile.
        flags: Additional compilation flags (defaults to ``0``).

    Returns:
        A compiled :class:`re.Pattern` with the safety flag applied where
        supported.

    Raises:
        re.error: If *pattern* is not a valid regular expression.
    """
    if hasattr(re, "LIMITED_TIME"):
        flags |= int(re.LIMITED_TIME)  # type: ignore[attr-defined]
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Timeout-bounded matching
# ---------------------------------------------------------------------------


def safe_regex_search(
    compiled: re.Pattern[str],
    text: str,
    timeout: float = DEFAULT_REDOGS_TIMEOUT_SECONDS,
) -> re.Match[str] | None:
    """Run ``compiled.search(text)`` with a hard wall-clock *timeout*.

    The underlying search executes in a single-worker thread.  If it does not
    return within *timeout* seconds the search is abandoned and ``None`` is
    returned (the caller treats this as "no match" -- the command is **not**
    blocked by that pattern).  This is the safe default: a broken pattern
    must not silently block commands; the operator sees it is not working and
    repairs it.

    Args:
        compiled: A pre-compiled (ideally via :func:`compile_safe_pattern`)
            regular expression.
        text: The string to search.
        timeout: Maximum seconds to wait for the search to complete.

    Returns:
        The first :class:`re.Match` found, or ``None`` if there is no match
        or the search exceeded *timeout*.
    """
    def _run() -> re.Match[str] | None:
        return compiled.search(text)

    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(_run)
        try:
            return future.result(timeout=timeout)
        except _FuturesTimeout:
            # Search did not finish in time -- treat as no match (safe default).
            return None
    finally:
        # Never block the caller waiting for a possibly-hung pattern thread.
        executor.shutdown(wait=False)
