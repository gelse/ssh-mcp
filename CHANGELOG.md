# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Sudoers drop-in generator: `GET /api/config/ssh_targets/{name}/sudoers`
  turns the configured `sudo_allowed` grants into an `/etc/sudoers.d` file
  with paths resolved on the host; response lists resolved, unresolved,
  skipped and invalid commands.
- Per-credential removal in the Config API: a target's `password` or
  `private_key` can now be deleted with an explicit `null`; missing or
  empty keeps the stored value, and deleting the last credential is refused.
- Dashboard: a "Sudoers" button per SSH target plus per-field removal
  checkboxes that clear the corresponding input while ticked.
- Duplicate command names are refused when editing allowed-command rules.

### Changed

- Config API writes are now read-modify-write for secrets: missing or `""`
  keeps the stored credential, explicit `null` deletes it, any value
  replaces it.

### Security

- Sudoers generation validates every interpolated name and path against
  `SUDOERS_*` patterns; `commands: ["*"]` with `sudo_allowed: ["*"]` is
  skipped rather than rendered as `ALL`.
- Bare absolute paths are emitted with no argument wildcard, which is
  unsupported by sudo-rs before 0.2.9.

## [0.3.0] - 2026-09-14

### Added

- Fine-grained `sudo_allowed` control per authorization rule (#65)
- Examples directory with validated configs and client examples (#69)
- CONTRIBUTING guide (#73)
- ARCHITECTURE.md with diagrams and design rationale (#71)
- Document `ssh_<verb>_<noun>` MCP tool naming convention (#60)

### Fixed

- Bind dual-stack socket to fix IPv6 healthcheck failure (#77)
- Fix Docker healthcheck: probe 127.0.0.1 instead of localhost (#72)
- Narrow startup exception handling and make default-config creation atomic (#64)

### Security

- Enforce body size limits via ASGI middleware (#62)
- Restrict API key charset to non-space printable ASCII `0x21-0x7E` (#61)

### Changed

- Rewrite README as human-facing front page, split reference docs (#78)
- Replace explicit boolean checks with idiomatic truthiness (#74)
- Refactor test_server.py to remove duplicated test logic (#63)
- Add testing branch support to Docker workflow (#66)

## [0.2.2] - 2026-08-30

### Security
- Sanitize catch-all exception handlers to avoid leaking internal details (#28)
- Add `user_message` to `MCPSSHError` and all subclasses for safe external error display (#31)
- Use `user_message` in `_format_error` to prevent internal details leaking (#31)
- Sanitize error messages in Config API routes (#32)
- Self-host Tailwind CSS to eliminate CDN supply-chain risk (#33)
- Escape `target.port` in Edit Target modal `innerHTML` to prevent XSS (#34)
- Refactor `showModal` to eliminate XSS surface via `innerHTML` (#37)
- Mask API key input and add show/hide toggle (#36)

### Added
- CIDR host-bits warning in config-api (#30)
- Document `ssh_<verb>_<noun>` MCP tool naming convention (#46)

### Fixed
- Fix `allowed_commands` partial write merging in config API (#38)
- Make `CONFIG_API_SESSION_COOKIE_SECURE` configurable via env var (#39)
- Fix cookie-secure falsy parser and update security docs (#39)
- Session-based authentication for Config API with cookie auth endpoints (#39)

## [0.2.1] - 2026-08-26

Initial tagged release.

## [0.2.0] - 2026-08-26

Initial public release.

[0.3.0]: https://github.com/gelse/ssh-mcp/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/gelse/ssh-mcp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/gelse/ssh-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/gelse/ssh-mcp/releases/tag/v0.2.0
