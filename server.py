#!/usr/bin/env python3
"""
SSH MCP Server for Bifrost - Streamable HTTP transport.

Uses an application-factory pattern: ``create_app()`` builds a fully
configured FastMCP server with dependency injection via closures.
No filesystem I/O, networking, or thread spawning occurs at import time.
"""
import argparse
import asyncio
import atexit
import datetime
import json
import logging
import os
import signal
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import paramiko
from fastmcp import FastMCP
from starlette.middleware import Middleware

from lib.auth import AuthorizationManager, AuthResult
from lib.circuit_breaker import CircuitBreaker
from lib.config import build_default_config, ConfigManager
from lib.connection_pool import SSHConnectionPool
from lib.constants import (
    APP_NAME,
    DEFAULT_CHECK_COMMAND,
    DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    DEFAULT_COMPRESS_ROTATED,
    DEFAULT_CONFIG_DIR,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_LOG_OUTPUT,
    DEFAULT_MAX_OUTPUT_LENGTH,
    DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
    DEFAULT_MAX_SFTP_PATH_LENGTH,
    DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
    DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_RETRY_BACKOFF_BASE_SECONDS,
    DEFAULT_RETRY_MAX_ATTEMPTS,
    DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
    DEFAULT_SFTP_SANDBOX_ROOT,
    DEFAULT_SSH_EXECUTOR_MAX_WORKERS,
    DEFAULT_SSH_KEY_FILENAME,
    DEFAULT_SSH_PORT,
    DEFAULT_TRUSTED_PROXIES,
    DEFAULT_WATCHER_INTERVAL_SECONDS,
    HTTP_SERVICE_UNAVAILABLE,
    LOG_FORMAT_VERSION,
    MCP_SSH_CONFIG_PATH,
    MCP_SSH_LOG_DIR,
    MCP_SSH_SSH_KEY,
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
)
from lib.exceptions import (
    AuthorizationError,
    ConfigValidationError,
    FileTransferError,
    MCPSSHError,
    PathValidationError,
    ServiceUnavailableError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHTimeoutError,
)
from lib.file_transfer import FileTransferService
from lib.health import attach_health_endpoint
from lib.metrics import (
    AUTH_DENIALS_TOTAL,
    COMMAND_DURATION_SECONDS,
    REQUESTS_TOTAL,
    attach_metrics_endpoint,
)
from lib.log_handler import JSONLHandler
from lib.loggers import FileLogger, BaseLogger
from lib.rate_limiter import RateLimiter
from lib.request_context import (
    get_api_key,
    get_client_ip,
    get_request_id,
    RequestContextMiddleware,
)
from lib.ssh_client import SSHClientManager
from lib.sudo import SudoHandler
from lib.sanitize import (
    sanitize_command,
    sanitize_log_string,
    sanitize_target_name,
)


# ---------------------------------------------------------------------------
# Module-level constants (no I/O, no side effects)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).parent


def _graceful_shutdown(state: SimpleNamespace, timeout: float) -> None:
    """Release all runtime resources in the correct dependency order.

    Runs once (guarded by ``state._shutdown_done``) and is safe to call
    from the atexit path, a signal handler, or directly via
    :meth:`create_app().shutdown`.  Resources are released leaf-first so
    that nothing may log, connect, or reload after its dependencies are
    gone:

    1. Drain pending SSH work on the executor for at most *timeout*
       seconds, force-cancelling anything still queued afterwards.
    2. Stop the config hot-reload watcher.
    3. Stop the SSH connection pool (closing idle *and* active clients).
    4. Close the structured log file LAST.

    Args:
        state: The :class:`~types.SimpleNamespace` attached to the app.
        timeout: Maximum seconds to wait for in-flight SSH work before
                 force-cancelling the remainder.
    """
    if getattr(state, "_shutdown_done", False):
        return
    state._shutdown_done = True

    ssh_executor = getattr(state, "ssh_executor", None)
    if ssh_executor is not None:
        # Bounded drain: allow in-flight futures up to *timeout*, then
        # abandon any that are still running and cancel the queued ones.
        drain = threading.Thread(
            target=ssh_executor.shutdown,
            kwargs={"wait": True, "cancel_futures": True},
            name="ssh-executor-drain",
            daemon=True,
        )
        drain.start()
        drain.join(timeout=timeout)
        if drain.is_alive():
            ssh_executor.shutdown(wait=False, cancel_futures=True)

    config_manager = getattr(state, "config_manager", None)
    if config_manager is not None:
        config_manager.stop_watcher()

    ssh_connection_pool = getattr(state, "ssh_connection_pool", None)
    if ssh_connection_pool is not None:
        ssh_connection_pool.stop()

    file_logger = getattr(state, "file_logger", None)
    if file_logger is not None:
        file_logger.close()


def _run_server(
    app: FastMCP,
    rate_limiter: RateLimiter | None = None,
    trusted_proxies: list[str] | None = None,
    trusted_proxies_provider: Callable[[], list[str]] | None = None,
) -> None:
    """Run the MCP streamable-HTTP server and handle graceful shutdown.

    Launches ``app.run_http_async(...)`` as an asyncio task and installs
    SIGTERM/SIGINT handlers so the process shuts the app down cleanly via
    :meth:`create_app().shutdown` (bounded drain, then resource release)
    instead of being killed mid-request.

    Args:
        app: The FastMCP application returned by :func:`create_app`.
        rate_limiter: The per-IP rate limiter to wire into the request
            middleware (attach to ``app.state`` when present).
        trusted_proxies: IPs of reverse proxies trusted for
            ``X-Forwarded-For`` resolution (attach to ``app.state`` when
            present).  Used as a static fallback only when
            ``trusted_proxies_provider`` is not given.
        trusted_proxies_provider: Optional zero-argument callable returning
            the live trusted-proxy list, read from the hot-reloaded config
            manager so config changes take effect without a restart.  Takes
            precedence over the static *trusted_proxies* list.
    """
    async def _serve() -> None:
        loop = asyncio.get_running_loop()
        shutdown_event = asyncio.Event()

        def _request_shutdown() -> None:
            # From a signal handler: stop accepting new work immediately.
            shutdown_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, _request_shutdown)
            except NotImplementedError:
                # Non-UNIX platforms without signal-handler support.
                pass

        serve_task = asyncio.create_task(
            app.run_http_async(
                host="0.0.0.0",
                port=8080,
                transport="streamable-http",
                path="/mcp",
                middleware=[
                    Middleware(
                        RequestContextMiddleware,
                        rate_limiter=rate_limiter,
                        trusted_proxies=trusted_proxies,
                        trusted_proxies_provider=trusted_proxies_provider,
                    ),
                ],
            )
        )
        await shutdown_event.wait()
        serve_task.cancel()
        try:
            await serve_task
        except asyncio.CancelledError:
            pass
        finally:
            timeout = getattr(
                app.state,  # type: ignore[attr-defined]
                "shutdown_timeout",
                DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
            )
            app.shutdown()  # type: ignore[attr-defined]   # bounded + resource release

    asyncio.run(_serve())


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app(
    config_dir: str = DEFAULT_CONFIG_DIR,
    ssh_key_path: str = DEFAULT_SSH_KEY_FILENAME,
    log_dir: str = DEFAULT_LOG_DIR,
    max_command_output: int = DEFAULT_MAX_OUTPUT_LENGTH,
    fix_permissions: bool = False,
) -> FastMCP:
    """Create and configure the MCP-SSH FastMCP application.

    All filesystem I/O, thread spawning, and network setup is deferred
    to this factory so that importing ``server`` has no side effects.

    Args:
        config_dir: Directory containing ``ssh-mcp-config.json``.
        ssh_key_path: Default path to SSH private key (used as fallback
                      when a target does not specify its own key).
        log_dir: Directory for JSONL log files.
        max_command_output: Maximum command output size in bytes (used as
                            fallback when ``settings.max_output_length`` is
                            not present in config).
        fix_permissions: When ``True``, chmod the config and secrets files to
                         ``RESTRICTED_FILE_MODE`` (0o600) after loading.

    Returns:
        A configured :class:`~fastmcp.FastMCP` server instance ready to serve.
    """
    mcp = FastMCP(
        APP_NAME,
        instructions=(
            "Secure SSH command execution for Homelab. Use ssh_list_servers "
            "first, then ssh_execute_command."
        ),
    )

    # --- Initialize structured logger ---
    file_logger = FileLogger(log_dir)
    stdlib_logger = logging.getLogger(__name__)

    # --- Initialize configuration manager with graceful fallback ---
    try:
        config_manager = ConfigManager(
            config_dir, logger=file_logger, fix_permissions=fix_permissions
        )
        # Start hot-reload watcher (15-second polling)
        config_manager.start_watcher(polling_interval=DEFAULT_WATCHER_INTERVAL_SECONDS)
    except Exception:
        _fallback_log = logging.getLogger(__name__)
        _fallback_log.warning(
            "Cannot initialize ConfigManager from %s — falling back to "
            "bundled default config (read-only, no hot-reload). "
            "Ensure the config directory is writable by the container user.",
            config_dir,
            exc_info=True,
        )
        file_logger.log({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": "config.fallback",
            "success": False,
            "message": (
                "Cannot initialize ConfigManager from primary config dir — "
                "falling back to bundled default config (read-only, no hot-reload)"
            ),
            "config_dir": config_dir,
            "request_id": get_request_id(),
            "log_level": "WARNING",
            "log_format_version": LOG_FORMAT_VERSION,
        })
        # Fallback: load bundled default-config.json via ConfigManager
        # pointed at the project root (which is always readable).
        _fallback_config_dir = str(BASE_DIR)
        config_manager = ConfigManager(
            _fallback_config_dir,
            logger=file_logger,
            fix_permissions=fix_permissions,
        )
        _fallback_log.info(
            "Config loaded from fallback path: %s",
            config_manager.config_path,
        )
        file_logger.log({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event": "config.fallback",
            "success": True,
            "message": "Config loaded from fallback bundled default",
            "config_dir": config_dir,
            "config_path": str(config_manager.config_path),
            "request_id": get_request_id(),
            "log_level": "WARNING",
            "log_format_version": LOG_FORMAT_VERSION,
        })

    # --- Route standard-library logging through JSONLHandler ---
    # Attach a JSONLHandler to the root logger so logs from this module,
    # FastMCP, uvicorn, and paramiko all land in the same JSONL stream as
    # the structured FileLogger events.  The effective level comes from the
    # ``settings.log_level`` config key (validated by ConfigManager).
    root_logger = logging.getLogger()
    log_level_name = config_manager.data.get("settings", {}).get(
        "log_level", DEFAULT_LOG_LEVEL
    )
    root_logger.setLevel(log_level_name.upper())
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    root_logger.addHandler(JSONLHandler(file_logger))
    # uvicorn loggers default to propagate=False; force propagation so their
    # records reach the root JSONLHandler instead of stderr only.
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    # --- Attach metrics endpoint (health endpoint is attached later, once
    # the connection pool exists, so it can report pool statistics) ---
    attach_metrics_endpoint(mcp)

    # --- Initialize rate limiter (configurable from settings) ---
    rate_limit_settings = config_manager.data.get("settings", {}).get("rate_limit", {})
    rate_limiter = RateLimiter(
        max_requests=rate_limit_settings.get(
            "max_requests_per_minute", DEFAULT_RATE_LIMIT_REQUESTS
        ),
        window_seconds=rate_limit_settings.get(
            "window_seconds", DEFAULT_RATE_LIMIT_WINDOW_SECONDS
        ),
        cleanup_interval=rate_limit_settings.get(
            "cleanup_interval_seconds", RATE_LIMIT_CLEANUP_INTERVAL_SECONDS
        ),
    )

    # --- Initialize remaining services ---
    settings = config_manager.data.get("settings", {})
    # Apply log truncation / rotation-compression settings from config.
    file_logger.configure(
        max_log_output=settings.get(
            "max_log_output", DEFAULT_MAX_LOG_OUTPUT
        ),
        compress_rotated=settings.get(
            "compress_rotated", DEFAULT_COMPRESS_ROTATED
        ),
    )
    auth_manager = AuthorizationManager(config_manager)
    ssh_client_manager = SSHClientManager(
        retry_max_attempts=settings.get(
            "retry_max_attempts", DEFAULT_RETRY_MAX_ATTEMPTS
        ),
        retry_backoff_base_seconds=settings.get(
            "retry_backoff_base_seconds", DEFAULT_RETRY_BACKOFF_BASE_SECONDS
        ),
        circuit_breaker=CircuitBreaker(
            failure_threshold=settings.get(
                "circuit_breaker_failure_threshold",
                DEFAULT_CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            ),
            timeout_seconds=settings.get(
                "circuit_breaker_timeout_seconds",
                DEFAULT_CIRCUIT_BREAKER_TIMEOUT_SECONDS,
            ),
        ),
        logger=file_logger,
    )
    # --- Create and start the per-target SSH connection pool ---
    # The pool is created after the manager (it needs the manager to create
    # fresh connections) and attached to the manager so ``connect()``
    # reuses pooled connections instead of always opening a new one.
    ssh_connection_pool = SSHConnectionPool(
        ssh_client_manager=ssh_client_manager,
        max_connections_per_target=settings.get(
            "pool_max_connections_per_target",
            DEFAULT_POOL_MAX_CONNECTIONS_PER_TARGET,
        ),
        max_concurrent_ssh_connections=settings.get(
            "max_concurrent_ssh_connections",
            DEFAULT_MAX_CONCURRENT_SSH_CONNECTIONS,
        ),
        idle_timeout_seconds=settings.get(
            "pool_idle_timeout_seconds", DEFAULT_POOL_IDLE_TIMEOUT_SECONDS
        ),
        cleanup_interval_seconds=settings.get(
            "pool_cleanup_interval_seconds", DEFAULT_POOL_CLEANUP_INTERVAL_SECONDS
        ),
        config_manager=config_manager,
    )
    ssh_client_manager.set_connection_pool(ssh_connection_pool)
    ssh_connection_pool.start()
    # --- Create the SSH operation thread pool ---
    # Long-running SSH operations are offloaded to a dedicated executor so
    # that blocking network I/O never stalls the MCP request loop.
    ssh_executor = ThreadPoolExecutor(
        max_workers=DEFAULT_SSH_EXECUTOR_MAX_WORKERS,
        thread_name_prefix="ssh-executor",
    )
    sftp_settings = config_manager.data.get("settings", {}).get("sftp", {})
    file_transfer_service = FileTransferService(
        sandbox_root=sftp_settings.get("sandbox_root", DEFAULT_SFTP_SANDBOX_ROOT),
        max_path_length=sftp_settings.get("max_path_length", DEFAULT_MAX_SFTP_PATH_LENGTH),
    )

    # --- Emit startup log entry ---
    file_logger.log({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": "startup",
        "config_dir": config_dir,
        "log_dir": log_dir,
        "request_id": get_request_id(),
        "log_level": "INFO",
        "log_format_version": LOG_FORMAT_VERSION,
    })

    # --- Register MCP tools with closure-based dependency injection ---
    _register_tools(
        mcp=mcp,
        config_manager=config_manager,
        auth_manager=auth_manager,
        file_logger=file_logger,
        stdlib_logger=stdlib_logger,
        ssh_client_manager=ssh_client_manager,
        file_transfer_service=file_transfer_service,
        ssh_key_path=ssh_key_path,
        max_command_output=max_command_output,
        ssh_executor=ssh_executor,
    )

    # --- Store runtime objects for use in main() middleware wiring and
    # graceful shutdown. ---
    # fastmcp 3.4.x does not define a ``state`` attribute on FastMCP, so we
    # attach a lightweight namespace to carry the rate limiter, the trusted
    # proxy list, the SSH executor, the connection pool, the config manager,
    # and the file logger to main().
    shutdown_timeout = config_manager.data.get("settings", {}).get(
        "shutdown_timeout_seconds", DEFAULT_SHUTDOWN_TIMEOUT_SECONDS
    )
    trusted_proxies = settings.get(
        "trusted_proxies", DEFAULT_TRUSTED_PROXIES
    )

    mcp.state = SimpleNamespace(  # type: ignore[attr-defined]
        rate_limiter=rate_limiter,
        trusted_proxies=trusted_proxies,
        ssh_executor=ssh_executor,
        ssh_connection_pool=ssh_connection_pool,
        config_manager=config_manager,
        file_logger=file_logger,
        shutdown_timeout=shutdown_timeout,
        _shutdown_done=False,
    )

    # --- Attach health-check endpoint (after pool creation so it can
    # report live connection-pool statistics) ---
    attach_health_endpoint(mcp, logger=file_logger, connection_pool=ssh_connection_pool)

    # --- Attach a public shutdown() method for graceful teardown ---
    def shutdown() -> None:
        """Release runtime resources in dependency order (idempotent)."""
        _graceful_shutdown(
            mcp.state,  # type: ignore[attr-defined]
            getattr(mcp.state, "shutdown_timeout", DEFAULT_SHUTDOWN_TIMEOUT_SECONDS),
        )

    mcp.shutdown = shutdown  # type: ignore[attr-defined]

    # --- Register shutdown handler as an atexit fallback ---
    def _shutdown() -> None:
        _graceful_shutdown(
            mcp.state,  # type: ignore[attr-defined]
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
        )

    atexit.register(_shutdown)

    return mcp


# ---------------------------------------------------------------------------
# Tool registration (closure-based dependency injection)
# ---------------------------------------------------------------------------


def _register_tools(
    mcp: FastMCP,
    config_manager: ConfigManager,
    auth_manager: AuthorizationManager,
    file_logger: BaseLogger,
    stdlib_logger: logging.Logger,
    ssh_client_manager: SSHClientManager,
    file_transfer_service: FileTransferService,
    ssh_key_path: str,
    max_command_output: int,
    ssh_executor: ThreadPoolExecutor,
) -> None:
    """Register all MCP tools on the FastMCP instance.

    Each tool function is defined as a nested closure that captures its
    dependencies from *this* function's parameters — no module-level
    global access.
    """

    # ------------------------------------------------------------------
    # Internal helpers (closures over the DI parameters)
    # ------------------------------------------------------------------

    def _lookup_api_key_name(api_key: str | None) -> str | None:
        """Look up the human-readable name for *api_key* via config.

        **CRITICAL**: Never returns the raw API key value — only the name.
        Returns ``"unknown"`` if a key was provided but not recognised,
        or ``None`` if no key was supplied.
        """
        if not api_key:
            return None
        from lib.crypto import verify_api_key

        for entry in (
            config_manager.data.get("allowed_commands", {})
            .get("api_keys", [])
        ):
            if verify_api_key(api_key, entry["key_hash"]):
                return entry["name"]
        return "unknown"

    def _build_auth_target(target_name: str) -> tuple[dict, str | None]:
        """Build an auth-style target dict and return ``(target, password_or_none)``.

        Adapts the flat config format (``private_key`` / ``password`` on
        target) to the structured auth dict expected by
        :meth:`SSHClientManager.get_client`.
        """
        target = config_manager.get_ssh_target(target_name)
        if target is None:
            available = ", ".join(config_manager.list_ssh_targets())
            raise SSHConnectionError(
                f"Server '{target_name}' not found. Available: {available}"
            )

        key_path = target.get("private_key") or ssh_key_path
        password = target.get("password")

        auth_target: dict = {
            "host": target["host"],
            "port": target.get("port", DEFAULT_SSH_PORT),
            "username": target["username"],
        }

        if key_path and os.path.exists(os.path.expanduser(key_path)):
            auth_target["auth"] = {
                "type": "key",
                "key_filename": key_path,
            }
        elif password:
            auth_target["auth"] = {
                "type": "password",
                "password": password,
            }
        else:
            raise SSHConnectionError(
                f"SSH target '{target_name}' has neither a valid key "
                f"nor a password"
            )

        return auth_target, password

    # ------------------------------------------------------------------
    # Refactored helpers for tool handlers
    # ------------------------------------------------------------------

    def _authorize_command(
        target_name: str, command: str, sudo: bool
    ) -> tuple[AuthResult, dict]:
        """Check authorization and build a base log entry.

        The raw *command* and *target_name* are sanitized before the
        authorization check.  ``sanitize_command`` preserves ``\\n``/``\\r``
        so the downstream dangerous-pattern check can still reject
        newline/CR injection; ``sanitize_target_name`` enforces the
        ``[a-zA-Z0-9._-]{1,128}`` pattern and raises ``AuthorizationError``
        on invalid input, which the caller formats as a JSON denial.

        Returns:
            ``(auth_result, log_entry)`` — the caller is responsible for
            logging the denial or success message and returning early on
            denial.
        """
        command = sanitize_command(command)
        target_name = sanitize_target_name(target_name)

        source_ip = get_client_ip()
        api_key = get_api_key()
        api_key_name = _lookup_api_key_name(api_key)

        auth_result = auth_manager.check_command(
            command=command,
            target=target_name,
            source_ip=source_ip,
            api_key=api_key,
        )
        log_command = sanitize_log_string(command)
        log_target_name = sanitize_log_string(target_name)
        log_entry = {
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "event": "command.execute",
            "source_ip": source_ip,
            "api_key_name": api_key_name,
            "command": log_command,
            "target_name": log_target_name,
            "allowed": auth_result.allowed,
            "reason": auth_result.reason,
            "matched_via": auth_result.matched_via,
            "sudo": sudo,
            "request_id": get_request_id(),
            "log_level": "INFO",
            "log_format_version": LOG_FORMAT_VERSION,
        }
        return auth_result, log_entry

    def _authorize_file_op(
        target_name: str, verb: str, remote_path: str, event_type: str
    ) -> tuple[AuthResult, dict]:
        """Check file-operation authorization and build a base log entry.

        *verb* is the command being authorised (``"cat"`` for download,
        ``"tee"`` for upload).  *event_type* labels the log entry
        (``"file.download"`` or ``"file.upload"``).

        The raw *target_name* is sanitized before the authorization check.
        ``sanitize_command`` is not applied to *verb* because it is a
        constant string; instead the newline-sanitized *remote_path* is used
        in the log ``command`` field so user-supplied paths cannot poison the
        JSONL log.

        Returns:
            ``(auth_result, log_entry)``.
        """
        target_name = sanitize_target_name(target_name)
        remote_path_display = sanitize_log_string(remote_path)

        source_ip = get_client_ip()
        api_key = get_api_key()
        api_key_name = _lookup_api_key_name(api_key)

        auth_result = auth_manager.check_command(
            command=verb,
            target=target_name,
            source_ip=source_ip,
            api_key=api_key,
        )
        log_target_name = sanitize_log_string(target_name)
        log_entry = {
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "event": event_type,
            "source_ip": source_ip,
            "api_key_name": api_key_name,
            "command": f"{verb} {remote_path_display}",
            "target_name": log_target_name,
            "allowed": auth_result.allowed,
            "reason": auth_result.reason,
            "matched_via": auth_result.matched_via,
            "request_id": get_request_id(),
            "log_level": "INFO",
            "log_format_version": LOG_FORMAT_VERSION,
        }
        return auth_result, log_entry

    @staticmethod
    def _execute_ssh_command(
        client: paramiko.SSHClient,
        actual_command: str,
        timeout: int,
        max_output: int,
        sudo: bool,
        sudo_password: str | None,
    ) -> tuple[str, str, int]:
        """Run *actual_command* on *client* and return output.

        Returns:
            ``(stdout, stderr, exit_code)``.
        """
        try:
            stdin, stdout, stderr = client.exec_command(
                actual_command, timeout=timeout
            )
            if sudo and sudo_password:
                stdin.write(sudo_password + "\n")
                stdin.flush()
                stdin.close()
            out = stdout.read(max_output).decode("utf-8", errors="replace")
            err = stderr.read(max_output).decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            return out, err, exit_code
        except socket.timeout as exc:
            raise SSHTimeoutError(
                f"Command timed out after {timeout}s: {actual_command}"
            ) from exc

    @staticmethod
    def _format_execution_result(
        out: str, err: str, exit_code: int, max_output: int
    ) -> str:
        """Combine stdout, stderr, exit code, and truncation notice."""
        result = out
        if err:
            result += f"\n[STDERR]\n{err}"
        if exit_code != 0:
            result += f"\n[EXIT: {exit_code}]"
        if len(out) >= max_output:
            result += "\n[OUTPUT TRUNCATED]"
        return result

    def _finish_log_entry(
        log_entry: dict,
        start_time: float,
        exit_code: int,
        tool_name: str,
        output: str | None = None,
    ) -> int:
        """Finalise and write *log_entry*; return elapsed ms.

        Records the tool invocation in ``mcpssh_requests_total`` (status
        ``"success"`` for exit code 0, ``"error"`` otherwise) and observes
        ``mcpssh_command_duration_seconds`` using the entry's
        ``target_name`` as the target label.  When *output* is given it is
        attached to the entry before writing, so the FileLogger can apply
        the configured truncation limit.
        """
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        log_entry["execution_time_ms"] = elapsed_ms
        log_entry["exit_code"] = exit_code
        if output is not None:
            log_entry["output"] = output
        file_logger.log(log_entry)
        status = "success" if exit_code == 0 else "error"
        REQUESTS_TOTAL.labels(tool=tool_name, status=status).inc()
        COMMAND_DURATION_SECONDS.labels(
            target=log_entry.get("target_name", "unknown")
        ).observe(elapsed_ms / 1000.0)
        return elapsed_ms

    @staticmethod
    def _format_error(exc: MCPSSHError) -> dict:
        """Build a structured error response for an MCPSSHError.

        Returns a dict with the ``error`` flag, the concrete exception
        type name, a human-readable message, a ``retryable`` flag, and a
        ``status_code`` reflecting the intended HTTP status (503 for a
        :class:`ServiceUnavailableError`, 200 otherwise).  The
        ``request_id`` is taken from the current request context so errors
        can be correlated with logs.
        """
        status_code: int = (
            HTTP_SERVICE_UNAVAILABLE
            if isinstance(exc, ServiceUnavailableError)
            else 200
        )
        return {
            "error": True,
            "error_type": type(exc).__name__,
            "message": str(exc),
            "retryable": isinstance(exc, SSHTimeoutError),
            "status_code": status_code,
            "request_id": get_request_id(),
        }

    # ------------------------------------------------------------------
    # Tool definitions
    # ------------------------------------------------------------------

    @mcp.tool()
    def ssh_list_servers() -> str:
        """
        List all available SSH target servers.
        Returns JSON with server IDs and their connection details
        (without secrets).
        """
        targets = config_manager.list_ssh_targets()
        result = {}
        for tid in targets:
            t = config_manager.get_ssh_target(tid)
            result[tid] = {
                "host": t["host"],
                "port": t.get("port", DEFAULT_SSH_PORT),
                "username": t["username"],
            }
        return json.dumps(result, indent=2)

    @mcp.tool()
    def ssh_list_allowed_commands(server_name: str) -> str:
        """
        List all commands the current client is allowed to execute on a
        given server.

        Considers all applicable layers: default rules, API key rules,
        and network rules.  Returns a sorted, deduplicated list of allowed
        command base names.  If the wildcard ``"*"`` is allowed via any
        layer, returns just ``"*"``.

        Does NOT check block_patterns — block patterns may further
        restrict commands at execution time.

        Args:
            server_name: The identifier of the SSH server (as configured)

        Returns:
            JSON-formatted list of allowed command base names, or error
            message
        """
        target_name = sanitize_target_name(server_name)
        source_ip = get_client_ip()
        api_key = get_api_key()

        commands = auth_manager.list_allowed_commands(
            target=target_name,
            source_ip=source_ip,
            api_key=api_key,
        )

        return json.dumps(commands)

    @mcp.tool()
    def ssh_execute_command(
        server_name: str,
        command: str,
        timeout: int = 30,
        sudo: bool = False,
    ) -> str:
        """
        Execute a command on a remote SSH server.

        The command is validated against the layered authorization chain:
        block_patterns -> default -> API key -> network -> deny.

        When sudo=True, the command is wrapped with ``sudo -S -p ''``
        (if the target has a password) or ``sudo -n`` (for passwordless
        sudo).  The authorization check runs against the **unwrapped**
        command, not sudo.  Raw ``'sudo'`` in the command string is always
        blocked by block_patterns.

        Args:
            server_name: The identifier of the SSH server (as configured)
            command: The command to execute (must not contain 'sudo')
            timeout: Command timeout in seconds (1-300)
            sudo: If True, execute the command with sudo on the remote
                  host.  Requires the SSH target to have a password
                  configured or NOPASSWD sudoers entry.

        Returns:
            Command output (stdout + stderr combined) or auth denial
            reason
        """
        # --- Sanitize command before any validation/auth/eval ---
        command = sanitize_command(command)
        target_name = sanitize_target_name(server_name)

        # --- Validate sudo usage ---
        sudo_error = SudoHandler.validate_sudo(command, sudo)
        if sudo_error is not None:
            return json.dumps(
                _format_error(
                    AuthorizationError(sudo_error)
                )
            )

        # --- Authorization check ---
        auth_result, log_entry = _authorize_command(
            target_name, command, sudo
        )

        if not auth_result.allowed:
            stdlib_logger.warning(
                "AUTH DENIED: target=%s command=%s sudo=%s source_ip=%s "
                "matched_via=%s reason=%s",
                target_name,
                command,
                sudo,
                log_entry["source_ip"],
                auth_result.matched_via,
                auth_result.reason,
            )
            file_logger.log(
                {
                    **log_entry,
                    "event": "auth.deny",
                    "level": "WARNING",
                    "log_level": "WARNING",
                    "message": f"Command rejected: {auth_result.reason}",
                }
            )
            REQUESTS_TOTAL.labels(
                tool="ssh_execute_command", status="denied"
            ).inc()
            AUTH_DENIALS_TOTAL.labels(reason=auth_result.reason).inc()
            file_logger.log(log_entry)
            return json.dumps(
                _format_error(
                    AuthorizationError(
                        f"Command rejected: {auth_result.reason}"
                    )
                )
            )

        stdlib_logger.info(
            "AUTH ALLOWED: target=%s command=%s sudo=%s source_ip=%s "
            "matched_via=%s",
            target_name,
            command,
            sudo,
            log_entry["source_ip"],
            auth_result.matched_via,
        )
        file_logger.log(
            {
                **log_entry,
                "event": "auth.check",
                "message": "Authorization check passed",
            }
        )

        # --- Resolve timeout / output caps ---
        max_timeout = (
            config_manager.data.get("settings", {})
            .get("command_timeout_max", DEFAULT_COMMAND_TIMEOUT_SECONDS)
        )
        if timeout > max_timeout:
            timeout = max_timeout

        max_output = (
            config_manager.data.get("settings", {})
            .get("max_output_length", max_command_output)
        )

        # --- Execute ---
        # The SSH round-trip is blocking, so it runs on the dedicated
        # ``ssh_executor`` thread pool; ``.result()`` re-raises any tool
        # exception into the except-chain below.
        start_time = time.monotonic()
        try:
            def _ssh_operation() -> str:
                auth_target, sudo_password = _build_auth_target(target_name)
                with ssh_client_manager.connect(auth_target) as client:
                    actual_command = SudoHandler.wrap_sudo_command(
                        command, sudo, sudo_password
                    )
                    out, err, exit_code = _execute_ssh_command(
                        client, actual_command, timeout, max_output,
                        sudo, sudo_password,
                    )
                    _finish_log_entry(
                        log_entry, start_time, exit_code,
                        "ssh_execute_command", output=out,
                    )
                    return _format_execution_result(
                        out, err, exit_code, max_output
                    )
            return ssh_executor.submit(_ssh_operation).result()
        except SSHAuthenticationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_execute_command")
            return json.dumps(_format_error(e))
        except SSHTimeoutError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_execute_command")
            return json.dumps(_format_error(e))
        except AuthorizationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_execute_command")
            return json.dumps(_format_error(e))
        except MCPSSHError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_execute_command")
            return json.dumps(_format_error(e))
        except Exception as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_execute_command")
            return json.dumps(
                _format_error(
                    MCPSSHError(f"Internal server error: {e}")
                )
            )

    @mcp.tool()
    def ssh_check_connection(server_name: str, timeout: int = 10) -> str:
        """Check SSH connectivity to a remote server.

        Executes the target's configured checkcommand (default: 'echo ping')
        to verify that SSH authentication and connectivity work.  This is a
        lightweight diagnostic tool — it does NOT go through the full
        authorization chain for the checkcommand itself, but it DOES require
        the target to exist and the SSH credentials to be valid.

        Args:
            server_name: The identifier of the SSH server (as configured)
            timeout: Connection and command timeout in seconds (1-30)

        Returns:
            JSON with success, output, error, exit_code, and checkcommand
        """
        target_name = sanitize_target_name(server_name)

        # Resolve timeout
        timeout = max(1, min(timeout, 30))

        # Read the checkcommand from config
        target = config_manager.get_ssh_target(target_name)
        if target is None:
            available = ", ".join(config_manager.list_ssh_targets())
            return json.dumps(
                _format_error(
                    SSHConnectionError(
                        f"Server '{target_name}' not found. Available: {available}"
                    )
                )
            )

        checkcommand = target.get("checkcommand", DEFAULT_CHECK_COMMAND)

        # Build log entry (no full auth check — this is a connectivity test)
        source_ip = get_client_ip()
        api_key = get_api_key()
        api_key_name = _lookup_api_key_name(api_key)
        log_entry = {
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "event": "connection.check",
            "source_ip": source_ip,
            "api_key_name": api_key_name,
            "command": sanitize_log_string(checkcommand),
            "target_name": sanitize_log_string(target_name),
            "request_id": get_request_id(),
            "log_level": "INFO",
            "log_format_version": LOG_FORMAT_VERSION,
        }

        start_time = time.monotonic()
        try:
            def _ssh_operation() -> str:
                auth_target, _ = _build_auth_target(target_name)
                with ssh_client_manager.connect(auth_target) as client:
                    out, err, exit_code = _execute_ssh_command(
                        client, checkcommand, timeout,
                        max_command_output, sudo=False, sudo_password=None,
                    )
                    _finish_log_entry(
                        log_entry, start_time, exit_code,
                        "ssh_check_connection", output=out,
                    )
                    result = {
                        "success": exit_code == 0,
                        "output": out.strip(),
                        "error": err.strip() if err else None,
                        "exit_code": exit_code,
                        "checkcommand": checkcommand,
                    }
                    return json.dumps(result)
            return ssh_executor.submit(_ssh_operation).result()
        except SSHAuthenticationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_check_connection")
            return json.dumps(_format_error(e))
        except SSHTimeoutError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_check_connection")
            return json.dumps(_format_error(e))
        except SSHConnectionError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_check_connection")
            return json.dumps(_format_error(e))
        except MCPSSHError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_check_connection")
            return json.dumps(_format_error(e))
        except Exception as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_check_connection")
            return json.dumps(
                _format_error(
                    MCPSSHError(f"Internal server error: {e}")
                )
            )

    @mcp.tool()
    def ssh_download_file(server_name: str, remote_path: str) -> str:
        """
        Download a file from a remote SSH server.

        Requires authorization equivalent to executing
        ``cat <remote_path>``.  The authorization chain is:
        block_patterns -> default -> API key -> network -> deny.

        Args:
            server_name: The identifier of the SSH server (as configured)
            remote_path: Absolute path to the file on the remote server

        Returns:
            File contents as a string, or auth denial reason
        """
        target_name = sanitize_target_name(server_name)

        auth_result, log_entry = _authorize_file_op(
            target_name, "cat", remote_path, "file.download"
        )

        if not auth_result.allowed:
            stdlib_logger.warning(
                "AUTH DENIED (download): target=%s path=%s source_ip=%s "
                "matched_via=%s",
                target_name,
                remote_path,
                log_entry["source_ip"],
                auth_result.matched_via,
            )
            file_logger.log(
                {
                    **log_entry,
                    "event": "auth.deny",
                    "level": "WARNING",
                    "log_level": "WARNING",
                    "message": f"Download rejected: {auth_result.reason}",
                }
            )
            REQUESTS_TOTAL.labels(
                tool="ssh_download_file", status="denied"
            ).inc()
            AUTH_DENIALS_TOTAL.labels(reason=auth_result.reason).inc()
            file_logger.log(log_entry)
            return json.dumps(
                _format_error(
                    AuthorizationError(
                        f"Download rejected: {auth_result.reason}"
                    )
                )
            )

        stdlib_logger.info(
            "AUTH ALLOWED (download): target=%s path=%s matched_via=%s",
            target_name,
            remote_path,
            auth_result.matched_via,
        )
        file_logger.log(
            {
                **log_entry,
                "event": "auth.check",
                "message": "Authorization check passed",
            }
        )

        # --- Execute download via FileTransferService ---
        # The SSH round-trip is blocking, so it runs on the dedicated
        # ``ssh_executor`` thread pool; ``.result()`` re-raises any tool
        # exception into the except-chain below.
        start_time = time.monotonic()
        try:
            def _ssh_operation() -> str:
                auth_target, _ = _build_auth_target(target_name)
                with ssh_client_manager.connect(auth_target) as client:
                    _filename, content_bytes = (
                        file_transfer_service.download_file(
                            client, remote_path
                        )
                    )
                    content = content_bytes.decode(
                        "utf-8", errors="replace"
                    )
                    _finish_log_entry(
                        log_entry, start_time, 0, "ssh_download_file"
                    )
                    return content
            return ssh_executor.submit(_ssh_operation).result()
        except SSHAuthenticationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_download_file")
            return json.dumps(_format_error(e))
        except SSHTimeoutError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_download_file")
            return json.dumps(_format_error(e))
        except AuthorizationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_download_file")
            return json.dumps(_format_error(e))
        except MCPSSHError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_download_file")
            return json.dumps(_format_error(e))
        except Exception as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_download_file")
            return json.dumps(
                _format_error(
                    MCPSSHError(f"Internal server error: {e}")
                )
            )

    @mcp.tool()
    def ssh_upload_file(
        server_name: str,
        remote_path: str,
        content: str,
        permissions: str = "0644",
    ) -> str:
        """
        Upload a file to a remote SSH server.

        Requires authorization equivalent to executing
        ``tee <remote_path>``.  The authorization chain is:
        block_patterns -> default -> API key -> network -> deny.

        Args:
            server_name: The identifier of the SSH server (as configured)
            remote_path: Absolute path to write the file to on the remote
                         server
            content: The file contents to write
            permissions: File permissions as an octal string
                         (e.g. ``"0644"``)

        Returns:
            Success message or auth denial reason
        """
        target_name = sanitize_target_name(server_name)

        auth_result, log_entry = _authorize_file_op(
            target_name, "tee", remote_path, "file.upload"
        )

        if not auth_result.allowed:
            stdlib_logger.warning(
                "AUTH DENIED (upload): target=%s path=%s source_ip=%s "
                "matched_via=%s",
                target_name,
                remote_path,
                log_entry["source_ip"],
                auth_result.matched_via,
            )
            file_logger.log(
                {
                    **log_entry,
                    "event": "auth.deny",
                    "level": "WARNING",
                    "log_level": "WARNING",
                    "message": f"Upload rejected: {auth_result.reason}",
                }
            )
            REQUESTS_TOTAL.labels(
                tool="ssh_upload_file", status="denied"
            ).inc()
            AUTH_DENIALS_TOTAL.labels(reason=auth_result.reason).inc()
            file_logger.log(log_entry)
            return json.dumps(
                _format_error(
                    AuthorizationError(
                        f"Upload rejected: {auth_result.reason}"
                    )
                )
            )

        stdlib_logger.info(
            "AUTH ALLOWED (upload): target=%s path=%s matched_via=%s",
            target_name,
            remote_path,
            auth_result.matched_via,
        )
        file_logger.log(
            {
                **log_entry,
                "event": "auth.check",
                "message": "Authorization check passed",
            }
        )

        # --- Execute upload ---
        # The SSH round-trip is blocking, so it runs on the dedicated
        # ``ssh_executor`` thread pool; ``.result()`` re-raises any tool
        # exception into the except-chain below.
        start_time = time.monotonic()
        try:
            def _ssh_operation() -> str:
                auth_target, _ = _build_auth_target(target_name)
                with ssh_client_manager.connect(auth_target) as client:
                    content_bytes = content.encode("utf-8")
                    file_transfer_service.upload_file(
                        client, remote_path, content_bytes
                    )
                    sftp = client.open_sftp()
                    try:
                        sftp.chmod(remote_path, int(permissions, 8))
                    finally:
                        sftp.close()
                    _finish_log_entry(
                        log_entry, start_time, 0, "ssh_upload_file"
                    )
                    return (
                        f"OK: Uploaded {len(content_bytes)} bytes to "
                        f"{remote_path}"
                    )
            return ssh_executor.submit(_ssh_operation).result()
        except SSHAuthenticationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_upload_file")
            return json.dumps(_format_error(e))
        except SSHTimeoutError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_upload_file")
            return json.dumps(_format_error(e))
        except AuthorizationError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_upload_file")
            return json.dumps(_format_error(e))
        except MCPSSHError as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_upload_file")
            return json.dumps(_format_error(e))
        except Exception as e:
            _finish_log_entry(log_entry, start_time, -1, "ssh_upload_file")
            return json.dumps(
                _format_error(
                    MCPSSHError(f"Internal server error: {e}")
                )
            )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the MCP-SSH server.

    Supports both CLI arguments and environment variables (env vars serve
    as defaults, CLI args take precedence):

    ================  =======================  =====================
    CLI Flag           Environment Variable     Default
    ================  =======================  =====================
    ``--config``       ``MCP_SSH_CONFIG_PATH``  ``/config``
    ``--ssh-key``      ``MCP_SSH_SSH_KEY``      ``ssh_key``
    ``--log-dir``      ``MCP_SSH_LOG_DIR``      ``/logs``
    ``--max-output``   ``MAX_OUTPUT_LENGTH``    ``50000``
    ``--fix-permissions``  —                    disabled (``False``)
    ``--print-default-config``  —               — (prints to stdout, exits)
    ================  =======================  =====================

    The legacy variable names (``CONFIG_DIR``, ``SSH_KEY_PATH``, and
    ``LOG_DIR``) remain supported as fallbacks.
    """
    parser = argparse.ArgumentParser(description="MCP-SSH Server")
    parser.add_argument(
        "--config",
        default=os.environ.get(
            MCP_SSH_CONFIG_PATH, os.environ.get("CONFIG_DIR", DEFAULT_CONFIG_DIR)
        ),
        help=f"Path to configuration directory (default: {DEFAULT_CONFIG_DIR})",
    )
    parser.add_argument(
        "--ssh-key",
        default=os.environ.get(
            MCP_SSH_SSH_KEY,
            os.environ.get("SSH_KEY_PATH", DEFAULT_SSH_KEY_FILENAME),
        ),
        help=f"Path to SSH private key (default: {DEFAULT_SSH_KEY_FILENAME})",
    )
    parser.add_argument(
        "--log-dir",
        default=os.environ.get(
            MCP_SSH_LOG_DIR, os.environ.get("LOG_DIR", DEFAULT_LOG_DIR)
        ),
        help=f"Directory for log files (default: {DEFAULT_LOG_DIR})",
    )
    parser.add_argument(
        "--max-output",
        type=int,
        default=int(
            os.environ.get("MAX_OUTPUT_LENGTH", str(DEFAULT_MAX_OUTPUT_LENGTH))
        ),
        help=f"Maximum command output size in bytes (default: {DEFAULT_MAX_OUTPUT_LENGTH})",
    )
    parser.add_argument(
        "--fix-permissions",
        action="store_true",
        help=(
            "Chmod the config and secrets files to 0o600 on startup, "
            "correcting group/world-readable permissions"
        ),
    )
    parser.add_argument(
        "--print-default-config",
        action="store_true",
        help="Print the generated default configuration as JSON to stdout and exit",
    )

    args = parser.parse_args()

    if args.print_default_config:
        print(json.dumps(build_default_config(), indent=2))
        return

    app = create_app(
        config_dir=args.config,
        ssh_key_path=args.ssh_key,
        log_dir=args.log_dir,
        max_command_output=args.max_output,
        fix_permissions=args.fix_permissions,
    )

    rate_limiter = getattr(app.state, "rate_limiter", None)
    trusted_proxies = getattr(app.state, "trusted_proxies", DEFAULT_TRUSTED_PROXIES)
    config_manager = getattr(app.state, "config_manager", None)

    def _trusted_proxies_provider() -> list[str]:
        """Read the live trusted-proxy list from the hot-reloaded config."""
        if config_manager is None:
            return trusted_proxies
        settings = config_manager.data.get("settings", {})
        return settings.get("trusted_proxies", DEFAULT_TRUSTED_PROXIES)

    _run_server(
        app,
        rate_limiter=rate_limiter,
        trusted_proxies=trusted_proxies,
        trusted_proxies_provider=_trusted_proxies_provider,
    )


if __name__ == "__main__":
    main()
