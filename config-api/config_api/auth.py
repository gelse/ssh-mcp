"""Bearer token and session cookie authentication dependency.

Provides a FastAPI dependency that validates Bearer tokens *or* session
cookies on protected routes.  Bearer tokens use timing-safe comparison
(hmac.compare_digest); session cookies use an in-memory session store
with configurable max-age expiry.

The API token is loaded once at startup from the CONFIG_API_TOKEN
environment variable via load_token(), and stored in a module-level
variable for subsequent reads by get_token() and verify_token().
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets
import time

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from lib.constants import (
    CONFIG_API_SESSION_COOKIE_NAME,
    CONFIG_API_SESSION_ID_LENGTH,
    CONFIG_API_SESSION_MAX_AGE_SECONDS,
)

logger = logging.getLogger(__name__)

_token: str | None = None

_security = HTTPBearer()

# ---------------------------------------------------------------------------
# In-memory session store  (session_id → creation timestamp)
# ---------------------------------------------------------------------------

_sessions: dict[str, float] = {}


def load_token() -> str:
    """Load the API token from CONFIG_API_TOKEN env var.

    Raises:
        RuntimeError: If the variable is not set or is empty.

    Returns:
        The loaded token string.
    """
    logger.debug("load_token entry")
    global _token
    token = os.environ.get("CONFIG_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "CONFIG_API_TOKEN environment variable is required but not set"
        )
    _token = token
    logger.debug("load_token exit: token loaded (length=%d)", len(token))
    return token


def get_token() -> str:
    """Return the loaded token.

    Raises:
        RuntimeError: If load_token() has not been called yet.

    Returns:
        The token string.
    """
    if _token is None:
        logger.debug("get_token: token not loaded")
        raise RuntimeError("Token not loaded — call load_token() first")
    logger.debug("get_token exit: token retrieved (length=%d)", len(_token))
    return _token


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------


def create_session() -> str:
    """Create a new session and return its ID.

    Generates a cryptographically random session ID, stores it in the
    in-memory session store with the current timestamp, and returns it.

    Returns:
        A random hex string of ``CONFIG_API_SESSION_ID_LENGTH`` bytes.
    """
    session_id = secrets.token_hex(CONFIG_API_SESSION_ID_LENGTH)
    _sessions[session_id] = time.time()
    logger.debug(
        "create_session: created session %s (store size=%d)",
        session_id[:8],
        len(_sessions),
    )
    return session_id


def validate_session(session_id: str) -> bool:
    """Check whether a session ID is valid and not expired.

    A session is valid when it exists in the store *and* its age is
    within ``CONFIG_API_SESSION_MAX_AGE_SECONDS``.

    Args:
        session_id: The session ID to validate.

    Returns:
        ``True`` if the session is valid and not expired.
    """
    created = _sessions.get(session_id)
    if created is None:
        return False
    if time.time() - created > CONFIG_API_SESSION_MAX_AGE_SECONDS:
        # Expired — remove eagerly.
        del _sessions[session_id]
        logger.debug(
            "validate_session: session %s expired, removed", session_id[:8],
        )
        return False
    return True


def revoke_session(session_id: str) -> None:
    """Revoke (invalidate) a session by removing it from the store.

    This is a no-op if the session ID does not exist.

    Args:
        session_id: The session ID to revoke.
    """
    removed = _sessions.pop(session_id, None)
    if removed is not None:
        logger.debug(
            "revoke_session: revoked session %s (store size=%d)",
            session_id[:8],
            len(_sessions),
        )


def cleanup_expired_sessions() -> None:
    """Remove all expired sessions from the in-memory store.

    Iterates the session store once, evicting entries whose age exceeds
    ``CONFIG_API_SESSION_MAX_AGE_SECONDS``.
    """
    now = time.time()
    expired = [
        sid for sid, created in _sessions.items()
        if now - created > CONFIG_API_SESSION_MAX_AGE_SECONDS
    ]
    for sid in expired:
        del _sessions[sid]
    if expired:
        logger.debug(
            "cleanup_expired_sessions: removed %d session(s)", len(expired),
        )


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------


async def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> str:
    """FastAPI dependency that validates a session cookie *or* Bearer token.

    The function checks for a valid session cookie first.  If no cookie
    (or an invalid/expired one) is present, it falls back to validating
    the ``Authorization: Bearer <token>`` header using timing-safe
    comparison (``hmac.compare_digest``).

    Args:
        request: The incoming Starlette request (used to read cookies).
        credentials: Parsed Authorization header from HTTPBearer scheme.
            ``None`` when the header is missing or malformed.

    Returns:
        The validated token string on success (always the API token).

    Raises:
        HTTPException: 401 if neither a valid session cookie nor a
            valid Bearer token is provided.
    """
    logger.debug("verify_token entry")

    # --- 1. Try session cookie auth ---
    session_id = request.cookies.get(CONFIG_API_SESSION_COOKIE_NAME)
    if session_id and validate_session(session_id):
        logger.debug("verify_token: session cookie validated")
        return get_token()

    # --- 2. Fall back to Bearer header auth ---
    if credentials is not None:
        expected = get_token()
        provided = credentials.credentials

        if hmac.compare_digest(expected, provided):
            logger.debug("verify_token exit: token validated via Bearer")
            return provided

    logger.debug("verify_token: no valid auth found, rejecting")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )
