# 04a - Upgrade API Key Hashing to PBKDF2 with Timing-Safe Comparison

**Parent Plan**: [04-security.md](plans/04-security.md)

## Objective
Replace the current `sha256(key.encode()).hexdigest()` API key hashing with PBKDF2-HMAC-SHA256, per-key random salts, and `secrets.compare_digest()` for timing-safe comparison.

## Context
Current hashing in [`server.py:88`](server.py:88) uses unsalted SHA-256 and `==` comparison. This is vulnerable to rainbow tables and timing attacks.

## Implementation Steps
1. Create `lib/crypto.py`:
   - `hash_api_key(key: str) -> str` — generates `pbkdf2:sha256:100000$<salt_hex>$<hash_hex>`
   - `verify_api_key(key: str, stored_hash: str) -> bool` — extracts params, recomputes, uses `secrets.compare_digest()`
2. Update config validator in [`lib/config.py`](lib/config.py:1) to accept both old `sha256:` and new `pbkdf2:` prefix formats
3. Add key length validation: 1-1024 characters, printable ASCII only
4. Update existing `default-config.json` keys to PBKDF2 format
5. Test: known key verifies against its stored hash, wrong key fails, timing test
6. Test: old `sha256:` format still works for backward compatibility

## Dependencies
- None

## Acceptance Criteria
- `lib/crypto.py` exports `hash_api_key()` and `verify_api_key()` 
- New keys stored as `pbkdf2:sha256:100000$<salt>$<hash>`
- Uses `secrets.compare_digest()` for comparison
- Old `sha256:` format still verified (backward compat)
- Key length and character validation enforced
