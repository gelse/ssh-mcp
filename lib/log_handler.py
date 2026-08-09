"""Bridge between the standard :mod:`logging` module and :class:`FileLogger`.

The SSH MCP server has two logging paths:

1. **Structured events** — rich dicts written via
   :meth:`BaseLogger.log` (e.g. ``command_execution``,
   ``file_download``, ``config_reload``).
2. **Standard library logging** — diagnostics from this project
   (``stdlib_logger``), the MCP/uvicorn stack, and third-party
   libraries such as paramiko.

:class:`JSONLHandler` connects the two: it is a
:class:`logging.Handler` attached to the root logger that converts
every :class:`logging.LogRecord` into a structured JSONL entry and
forwards it to a :class:`FileLogger`.  This guarantees that
third-party library logs (uvicorn, paramiko, …) end up in the same
JSONL stream as the structured events, and that every entry carries
the correlation ``request_id`` plus ``log_level`` and
``log_format_version`` fields.
"""

from __future__ import annotations

import datetime
import logging

from lib.constants import LOG_FORMAT_VERSION
from lib.loggers import BaseLogger
from lib.request_context import get_request_id


# Records emitted by the graceful-degradation fallback logger must not be
# re-serialised back into the same FileLogger.  If the file write fails, the
# fallback logger emits to stderr, but its records still propagate to the
# root logger — which would route them straight back into this handler,
# producing infinite recursion.  Skipping them here breaks the cycle.
_FALLBACK_LOGGER_NAME_PREFIX = "ssh_mcp.file_logger"


class JSONLHandler(logging.Handler):
    """A :class:`logging.Handler` that writes records as JSONL via FileLogger.

    Every handled record is converted into a structured entry containing:

    - ``timestamp`` — ISO 8601 UTC timestamp of the log event
    - ``event`` — explicit event name from ``extra={"event": ...}``, or the
      logger name as a fallback
    - ``level`` — the Python log level, e.g. ``"INFO"`` / ``"WARNING"``
    - ``logger_name``, ``module``, ``funcName`` — provenance of the record
    - ``message`` — the formatted log message
    - ``request_id`` — the correlation ID from :func:`get_request_id`
    - ``log_level`` — the effective log level of the record
    - ``log_format_version`` — schema version (see
      :data:`lib.constants.LOG_FORMAT_VERSION`)

    Args:
        file_logger: The :class:`BaseLogger` backend entries are written to.
    """

    def __init__(self, file_logger: BaseLogger) -> None:
        super().__init__()
        self._file_logger = file_logger

    # ------------------------------------------------------------------
    # logging.Handler API
    # ------------------------------------------------------------------

    def emit(self, record: logging.LogRecord) -> None:
        """Convert *record* to a structured entry and write it to FileLogger.

        Failures are reported via :meth:`handleError` (the standard
        :mod:`logging` behaviour) instead of being raised, so logging
        never breaks application code.  Records from the
        graceful-degradation fallback logger are skipped to avoid
        infinite recursion.
        """
        try:
            if record.name.startswith(_FALLBACK_LOGGER_NAME_PREFIX):
                return
            entry = self._build_entry(record)
            self._file_logger.log(entry)
        except Exception:  # pragma: no cover - defensive; logging must not raise
            self.handleError(record)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_entry(record: logging.LogRecord) -> dict:
        """Build the structured JSONL entry for *record*."""
        event = getattr(record, "event", None)
        if not isinstance(event, str) or not event:
            # No explicit event attached; use the logger name so third-party
            # records (uvicorn, paramiko, …) remain identifiable.
            event = record.name

        return {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, tz=datetime.timezone.utc
            ).isoformat(),
            "event": event,
            "level": record.levelname,
            "logger_name": record.name,
            "module": record.module,
            "funcName": record.funcName,
            "message": record.getMessage(),
            "request_id": get_request_id(),
            "log_level": record.levelname,
            "log_format_version": LOG_FORMAT_VERSION,
        }
