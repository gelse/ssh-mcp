# 10 - Dependency Hygiene & Supply Chain

## Current State Analysis

### Direct Dependencies (from Dockerfile)

| Package | Version | Purpose | Risk Level |
|---------|---------|---------|------------|
| `fastmcp` | unpinned | MCP server framework | HIGH |
| `paramiko` | unpinned | SSH client library | MEDIUM |
| `python:3.13-alpine` | 3.13 | Base image | LOW |

### Issues

#### 1. No Version Pinning
[Dockerfile:14](Dockerfile:14): `RUN pip install fastmcp paramiko` — no version constraints. Each build may get different versions. A breaking change in fastmcp or paramiko could silently break production.

#### 2. No Hash Verification
No `--require-hashes` or lock file (`requirements.txt` with hashes, `Pipfile.lock`, `poetry.lock`). Supply chain attack via PyPI compromise would go undetected.

#### 3. No Dependency Audit
No `pip-audit` or `safety` scan in CI. Vulnerabilities in transitive dependencies won't be caught.

#### 4. Alpine Base Image Float
`python:3.13-alpine` — no digest pin. `python:3.13-alpine@sha256:...` would provide reproducible builds.

#### 5. No SBOM
No Software Bill of Materials generated during build. Cannot trace what's in the image.

#### 6. FastMCP is a Heavy Framework
FastMCP likely pulls in Starlette, Uvicorn, Pydantic, and many transitive dependencies. The attack surface is large for what's essentially a JSON-RPC wrapper.

#### 7. No Virtual Environment
Packages installed globally in the Docker image. While acceptable in a container, a venv would isolate from system Python packages.

#### 8. No `.python-version` or `.tool-versions`
No mechanism to pin the Python version for local development.

### Transitive Dependency Risk

FastMCP's dependency tree (estimated):
```
fastmcp
├── starlette          (HTTP framework)
├── uvicorn            (ASGI server)
├── pydantic           (data validation)
├── httpx              (HTTP client — may be needed for fastmcp client)
├── anyio              (async I/O)
└── ... (many more)
```

Paramiko's dependency tree:
```
paramiko
├── cryptography       (crypto primitives — security critical)
├── bcrypt             (key derivation)
├── pynacl             (Ed25519 support)
└── six (potentially)
```

The `cryptography` package is security-critical. A vulnerability there directly impacts SSH key security.

### Supply Chain Hardening Recommendations

1. **Lock Dependencies with Hashes**
   - Create `requirements.in` with direct dependencies
   - Generate `requirements.txt` with `pip-compile --generate-hashes`
   - Pin all transitive dependencies with SHA-256 hashes

2. **Pin Base Image Digest**
   ```dockerfile
   FROM python:3.13-alpine@sha256:abc123...
   ```

3. **Add Dependency Audit to CI**
   - Run `pip-audit` on every PR
   - Fail build on critical/high vulnerabilities
   - Document accepted exceptions

4. **Generate SBOM**
   - Use `syft` or `cyclonedx-python` to generate SBOM
   - Attach to releases
   - Format: CycloneDX or SPDX

5. **Dependabot/Renovate Configuration**
   - Add `.github/dependabot.yml` or `renovate.json`
   - Auto-PR for dependency updates
   - Group non-breaking updates

6. **Minimal Base Image**
   - Consider `python:3.13-slim` instead of alpine (glibc vs musl compatibility)
   - Or stick with alpine but document musl considerations

7. **Add `.python-version`**
   - Pin Python 3.13 for local development
   - Use with pyenv or similar

8. **Vulnerability Scanning in CI**
   - Trivy or Grype scan of built Docker image
   - Fail on critical CVEs

9. **Evaluate FastMCP Alternatives**
   - Consider `mcp` (official SDK) vs FastMCP
   - Evaluate dependency footprint tradeoffs
   - Document the decision

### Acceptance Criteria
- `requirements.txt` with `--generate-hashes` for all dependencies
- Base image pinned by digest
- CI runs `pip-audit` and fails on critical vulnerabilities
- SBOM generated and attached to releases
- Docker image scanned with Trivy/Grype in CI
- Dependabot or Renovate configured for automated updates
- `.python-version` file present
