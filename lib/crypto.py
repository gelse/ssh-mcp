"""Cryptographic utilities for API key hashing and verification.

Provides PBKDF2-HMAC-SHA256 based key hashing with per-key random salts,
timing-safe comparison via :func:`secrets.compare_digest`, and backward
compatibility with legacy SHA-256 hashed keys.
"""

from __future__ import annotations

import hashlib
import secrets

from lib.constants import (
    PBKDF2_ALGO,
    PBKDF2_HASH_FUNC,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
)

# Format string for the new PBKDF2 hash prefix (without salt and hash)
_PBKDF2_PREFIX = f"{PBKDF2_ALGO}:{PBKDF2_HASH_FUNC}:{PBKDF2_ITERATIONS}$"


def hash_api_key(key: str) -> str:
    """Hash an API key using PBKDF2-HMAC-SHA256 with a random per-key salt.

    Args:
        key: The plaintext API key to hash.

    Returns:
        A string in the format
        ``pbkdf2:sha256:100000$<salt_hex>$<hash_hex>`` where *salt_hex*
        is 32 hex characters (16 bytes) and *hash_hex* is 64 hex
        characters (32 bytes).
    """
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    hash_bytes = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_FUNC,
        key.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"{_PBKDF2_PREFIX}{salt.hex()}${hash_bytes.hex()}"


def verify_api_key(key: str, stored_hash: str) -> bool:
    """Verify an API key against a stored hash string.

    Supports two formats:

    * **PBKDF2** (new): ``pbkdf2:sha256:100000$<salt_hex>$<hash_hex>``
    * **SHA-256** (legacy): ``sha256:<64_hex_chars>``

    Comparison is performed with :func:`secrets.compare_digest` to
    resist timing attacks.

    Args:
        key: The plaintext API key to verify.
        stored_hash: A hash string in one of the supported formats.

    Returns:
        ``True`` if *key* matches *stored_hash*, ``False`` otherwise.
    """
    # New PBKDF2 format
    if stored_hash.startswith(_PBKDF2_PREFIX):
        rest = stored_hash[len(_PBKDF2_PREFIX):]
        try:
            salt_hex, hash_hex = rest.split("$", 1)
        except ValueError:
            return False
        try:
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)
        except (ValueError, TypeError):
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_FUNC,
            key.encode("utf-8"),
            salt,
            PBKDF2_ITERATIONS,
        )
        return secrets.compare_digest(computed_hash, expected_hash)

    # Legacy SHA-256 format
    if stored_hash.startswith("sha256:"):
        expected = stored_hash[len("sha256:"):]
        computed = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return secrets.compare_digest(computed.encode(), expected.encode())

    return False
