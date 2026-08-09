# 10a - Lock Dependencies, Pin Base Image, Add Audit & SBOM

**Parent Plan**: [10-dependency-hygiene-supply-chain.md](plans/10-dependency-hygiene-supply-chain.md)

## Objective
Create `requirements.in` / `requirements.txt` with hashed, pinned dependencies. Pin the Docker base image by digest. Add `pip-audit` to CI and generate SBOM.

## Implementation Steps
1. Create `requirements.in` with direct dependencies (fastmcp, paramiko)
2. Generate `requirements.txt` with `pip-compile --generate-hashes requirements.in`
3. Pin Docker base image: `python:3.13-alpine@sha256:...`
4. Add `--no-cache-dir --require-hashes -r requirements.txt` to Dockerfile pip install
5. Create `.github/workflows/audit.yml` (or equivalent CI config): run `pip-audit` on PR, fail on critical
6. Add SBOM generation to Docker build: install `cyclonedx-bom` and run `cyclonedx-py requirements requirements.txt --of JSON -o sbom.json`
7. Create `renovate.json` with config for automated dependency updates
8. Add `.python-version` with `3.13`
9. Create `.editorconfig` with consistent formatting rules

## Dependencies
- None

## Acceptance Criteria
- `requirements.txt` with `--generate-hashes` for all deps
- Base image pinned by digest
- CI runs `pip-audit`
- SBOM generated at build time
- Renovate configured for auto-updates
- `.python-version` and `.editorconfig` present
