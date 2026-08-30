# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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

### Fixed
- Fix `allowed_commands` partial write merging in config API (#38)
- Make `CONFIG_API_SESSION_COOKIE_SECURE` configurable via env var (#39)
- Fix cookie-secure falsy parser and update security docs (#39)
- Session-based authentication for Config API with cookie auth endpoints (#39)

## [0.2.1] - 2026-08-26

Initial tagged release.

## [0.2.0] - 2026-08-26

Initial public release.

[0.2.2]: https://github.com/gelse/ssh-mcp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/gelse/ssh-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/gelse/ssh-mcp/releases/tag/v0.2.0
