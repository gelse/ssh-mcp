# Contributing to mcp-ssh

Thanks for your interest in contributing to **mcp-ssh**.

## Prerequisites

- Python 3.13 (see [`.python-version`](.python-version))
- Docker (required for integration tests)
- `make`

## Development Setup

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip install --require-hashes -r requirements-dev.txt
```

The `config-api/` subdirectory has its own virtualenv and tests.
Run them with `make config-test`.

## Running Tests

```bash
# Unit tests (full suite)
make test

# Config API tests
make config-test

# Integration tests (requires Docker + docker Python SDK)
make integrationtest
```

Integration tests build the `mcp-ssh:test` Docker image and run
on a dedicated `mcp-ssh-test-net` bridge network.
Clean up with `make clean-test`.

Fast inner loop:

```bash
.venv/bin/python -m pytest tests/test_<module>.py -x
```

Coverage tooling is not currently configured.

## Code Style

Formatting follows [`.editorconfig`](.editorconfig) defaults:

- **Python:** 4-space indent, 88-char lines (convention)
- **Markdown:** 2-space indent, 120-char lines (`max_line_length`)

There is no lint or type-check tooling (no `ruff`, `mypy`, `pyright`,
or `flake8`). See
[`AGENTS.md#coding-conventions`](AGENTS.md#coding-conventions) for
the full conventions table.

## Dependency Management

Dependencies are hash-locked via `pip-compile --generate-hashes
--no-reuse-hashes` run inside `python:3.13-alpine` so that hashes
match the runtime wheels. Never hand-edit `requirements*.txt`.
There is no `pyproject.toml`; the project uses raw pip + requirements
files.

## Git Workflow

- Create a feature branch from `testing`.
- Open a PR targeting `testing`. Never push directly to `main` or
  `testing`.
- Write short, imperative-mood commit messages — one commit per task.
- Delete the branch after merge.

## Continuous Integration

Three GitHub Actions workflows run on every push/PR:

- **Unit tests** on every push
  (`.github/workflows/test.yml`)
- **Integration tests** on `release*` tags
  (`.github/workflows/integration.yml`)
- **Docker build+push** to GHCR on `main`, `testing`, `v*` tags
  (`.github/workflows/docker.yaml`)

## Adding a New Tool

See [`AGENTS.md#adding-a-tool`](AGENTS.md#adding-a-tool) for
handler conventions and
[`AGENTS.md#file-touch-checklist`](AGENTS.md#file-touch-checklist)
for the full list of files to create or modify. Tool naming follows
[`README.md#tool-naming-convention`](README.md#tool-naming-convention).

Key handler conventions:

- `@mcp.tool()` decorator; return type `-> str`
- Closure DI — capture dependencies from `_register_tools()`, not
  globals
- Catch `MCPSSHError`, return JSON via `_format_error` — never raise
  from tool handlers

## Security

Consult [`docs/SECURITY.md`](docs/SECURITY.md) before modifying
crypto, auth, command_security, file_transfer, sudo, request_context,
secrets, or sanitize modules.
