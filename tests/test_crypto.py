"""Direct unit tests for :mod:`lib.crypto` (API-key hashing/verification).

Covers the PBKDF2 output format, round-trip verification, legacy
SHA-256 verification, random per-key salts, and malformed inputs.
"""

from __future__ import annotations

import hashlib

import pytest

from lib.constants import (
    PBKDF2_ALGO,
    PBKDF2_HASH_FUNC,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT_BYTES,
)
from lib.crypto import hash_api_key, verify_api_key

# sha256("test") — a legacy-format hash used in the sample config.
LEGACY_SHA256_TEST = (
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

EXPECTED_PREFIX = f"{PBKDF2_ALGO}:{PBKDF2_HASH_FUNC}:{PBKDF2_ITERATIONS}"


class TestHashApiKey:
    """Tests for hash_api_key() output format."""

    def test_prefix_matches_expected_format(self):
        """The hash prefix is pbkdf2:sha256:100000."""
        h = hash_api_key("some-key")
        prefix, _rest = h.split("$", 1)
        assert prefix == EXPECTED_PREFIX

    def test_three_dollar_parts(self):
        """Output has exactly three $-separated parts (prefix, salt, hash)."""
        h = hash_api_key("some-key")
        parts = h.split("$")
        assert len(parts) == 3

    def test_salt_is_16_bytes_hex(self):
        """The salt part is 32 hex characters (16 bytes) of valid hex."""
        h = hash_api_key("some-key")
        salt_hex = h.split("$")[1]
        assert len(salt_hex) == PBKDF2_SALT_BYTES * 2
        bytes.fromhex(salt_hex)  # must be valid hex

    def test_hash_is_32_bytes_hex(self):
        """The hash part is 64 hex characters (32 bytes) of valid hex."""
        h = hash_api_key("some-key")
        hash_hex = h.split("$")[2]
        assert len(hash_hex) == 32 * 2
        bytes.fromhex(hash_hex)  # must be valid hex

    def test_salt_is_random_per_hash(self):
        """Two hashes of the same key use different random salts."""
        h1 = hash_api_key("same-key")
        h2 = hash_api_key("same-key")
        salt1 = h1.split("$")[1]
        salt2 = h2.split("$")[1]
        assert salt1 != salt2
        assert h1 != h2

    def test_empty_key_hashes(self):
        """An empty key still produces a valid-format hash."""
        h = hash_api_key("")
        assert h.split("$")[0] == EXPECTED_PREFIX


class TestVerifyApiKey:
    """Tests for verify_api_key() success/failure paths."""

    def test_round_trip_success(self):
        """A freshly hashed key verifies successfully."""
        h = hash_api_key("my-api-key")
        assert verify_api_key("my-api-key", h) is True

    def test_wrong_key_fails(self):
        """A wrong key does not verify against a PBKDF2 hash."""
        h = hash_api_key("right-key")
        assert verify_api_key("wrong-key", h) is False

    def test_verify_uses_salt_from_stored_hash(self):
        """The salt embedded in the stored hash is used for verification."""
        h = hash_api_key("roundtrip-key")
        # Deterministic recomputation with the same salt must match.
        prefix, salt_hex, _ = h.split("$")
        recomputed = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_FUNC,
            "roundtrip-key".encode("utf-8"),
            bytes.fromhex(salt_hex),
            PBKDF2_ITERATIONS,
        ).hex()
        assert verify_api_key("roundtrip-key", f"{prefix}${salt_hex}${recomputed}") is True

    def test_empty_key_round_trip(self):
        """An empty key round-trips correctly (and differs from non-empty)."""
        h = hash_api_key("")
        assert verify_api_key("", h) is True
        assert verify_api_key("x", h) is False

    def test_legacy_sha256_verifies(self):
        """Legacy sha256: format hashes still verify."""
        assert verify_api_key("test", LEGACY_SHA256_TEST) is True

    def test_legacy_sha256_wrong_key_fails(self):
        """A wrong key against a legacy sha256: hash fails."""
        assert verify_api_key("wrong", LEGACY_SHA256_TEST) is False

    def test_unknown_format_returns_false(self):
        """Unrecognised hash formats are rejected."""
        assert verify_api_key("key", "not-a-hash") is False
        assert verify_api_key("key", "") is False

    def test_malformed_pbkdf2_returns_false(self):
        """Malformed PBKDF2 strings are rejected without raising."""
        assert verify_api_key("key", "pbkdf2:sha256:100000") is False
        assert verify_api_key("key", "pbkdf2:sha256:100000$deadbeef") is False

    def test_pbkdf2_invalid_hex_returns_false(self):
        """Non-hex salt/hash parts are rejected without raising."""
        assert verify_api_key("key", "pbkdf2:sha256:100000$zz$zz") is False

    def test_legacy_sha256_nonmatching_digest_fails(self):
        """A legacy sha256: value that is not the key's digest fails."""
        assert verify_api_key("key", "sha256:nothex") is False

    def test_verify_api_key_uses_timing_safe_comparison(self):
        """Verify secrets.compare_digest is used for timing-safe comparison."""
        from unittest.mock import patch

        key = "test-key-123"
        stored_hash = hash_api_key(key)
        with patch("lib.crypto.secrets.compare_digest", return_value=True) as mock_cd:
            result = verify_api_key(key, stored_hash)
            assert mock_cd.called
            assert result is True
