"""Composite logger — fans out log entries to multiple targets.

Implements the composite pattern: a single :class:`~lib.loggers.BaseLogger`
that delegates ``log()``, ``close()``, and ``configure()`` calls to an
arbitrary number of underlying targets.

If a single target raises an exception, it is caught and the remaining
targets still receive the entry.  The ``entry`` dict is **never** modified
by the composite.
"""

from __future__ import annotations

import sys
import threading
from typing import Any

from lib.loggers import BaseLogger


class CompositeLogger(BaseLogger):
    """A BaseLogger that delegates to multiple underlying targets.

    Implements the composite pattern: all BaseLogger methods are
    forwarded to every child target.  If a single target raises an
    exception, it is caught and the remaining targets are still called.
    """

    def __init__(self, targets: list[BaseLogger]) -> None:
        """Initialize with a list of child loggers.

        Args:
            targets: Non-empty list of BaseLogger instances to delegate to.
                     An empty list is permitted but log() will be a no-op.
        """
        self._targets = list(targets)
        self._lock = threading.Lock()

    def log(self, entry: dict) -> None:
        """Forward entry to all child targets.

        Exceptions from individual targets are caught and logged to
        stderr (fallback) so one broken target does not prevent others
        from receiving the entry.  The entry dict is not modified.
        """
        for target in self._targets:
            try:
                target.log(entry)
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[CompositeLogger] target {target.__class__.__name__} "
                    f"raised {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )

    def close(self) -> None:
        """Close all child targets in reverse order.

        Exceptions from individual close() calls are caught so all
        targets get a chance to clean up.
        """
        for target in reversed(self._targets):
            try:
                target.close()
            except Exception as exc:  # noqa: BLE001
                print(
                    f"[CompositeLogger] close() on {target.__class__.__name__} "
                    f"raised {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )

    def configure(
        self,
        max_log_output: int | None = None,
        compress_rotated: bool | None = None,
    ) -> None:
        """Forward configure() to all child targets that support it.

        Each target's configure() is called independently; failures
        in one target do not prevent others from being updated.
        """
        for target in self._targets:
            if hasattr(target, "configure"):
                try:
                    target.configure(
                        max_log_output=max_log_output,
                        compress_rotated=compress_rotated,
                    )
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"[CompositeLogger] configure() on "
                        f"{target.__class__.__name__} raised "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )

    @property
    def targets(self) -> list[BaseLogger]:
        """Return a read-only view of the child targets."""
        return list(self._targets)
