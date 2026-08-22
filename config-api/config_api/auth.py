"""Bearer token authentication dependency.

Provides a FastAPI dependency that validates Bearer tokens on protected
routes using timing-safe comparison (hmac.compare_digest).

The token is loaded once at startup from the CONFIG_API_TOKEN environment
variable via load_token(), and stored in a module-level variable for
subsequent reads by verify_token().
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_token: str | None = None

_security = HTTPBearer()


def load_token() -> str:
    """Load the API token from CONFIG_API_TOKEN env var.

    Raises:
        RuntimeError: If the variable is not set or is empty.

    Returns:
        The loaded token string.
    """
    global _token
    token = os.environ.get("CONFIG_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "CONFIG_API_TOKEN environment variable is required but not set"
        )
    _token = token
    return token


def get_token() -> str:
    """Return the loaded token.

    Raises:
        RuntimeError: If load_token() has not been called yet.

    Returns:
        The token string.
    """
    if _token is None:
        raise RuntimeError("Token not loaded — call load_token() first")
    return _token


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(_security),
) -> str:
    """FastAPI dependency that validates the Bearer token.

    Uses hmac.compare_digest() for timing-safe comparison to prevent
    timing attacks (same approach as lib/crypto.py).

    Args:
        credentials: Parsed Authorization header from HTTPBearer scheme.

    Returns:
        The validated token string on success.

    Raises:
        HTTPException: 401 if the token is invalid.
    """
    expected = get_token()
    provided = credentials.credentials

    if not hmac.compare_digest(expected, provided):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return provided
