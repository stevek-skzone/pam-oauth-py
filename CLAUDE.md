# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pam-oauth-py is a Python PAM (Pluggable Authentication Modules) module that enables OAuth2/OIDC JWT-based authentication on Linux systems. It integrates via `pam_python.so`, validates JWTs against OIDC provider JWKS endpoints, and checks claims match the PAM username. Licensed under MIT.

## Build & Test Commands

```bash
uv sync                                                    # Install all dependencies
uv run pytest tests/ -v                                    # Run tests
uv run pytest tests/ -v --cov=pam_oauth2 --cov-report=term-missing  # Tests with coverage
uv run ruff check src/ tests/                              # Lint
uv run ruff check --fix src/ tests/                        # Lint with auto-fix
```

## Architecture

- `pam_oauth2.py` — Top-level shim loaded by `pam_python.so`, re-exports PAM entry points
- `src/pam_oauth2/pam_sm.py` — PAM entry points (`pam_sm_authenticate`, etc.), fail-closed design
- `src/pam_oauth2/config.py` — Parses `key=value` PAM args into a frozen dataclass
- `src/pam_oauth2/discovery.py` — Fetches OIDC `.well-known/openid-configuration`
- `src/pam_oauth2/jwks_cache.py` — Filesystem JWKS cache at `/var/cache/pam_oauth2/<hash>/` with TTL and atomic writes
- `src/pam_oauth2/token_validator.py` — JWT signature + claims validation with cache-bust retry for key rotation
- `src/pam_oauth2/logging.py` — Syslog wrapper (LOG_AUTH facility)

## Key Design Decisions

- **Asymmetric algorithms only**: HS256/none explicitly blocked; algorithm from config, never from token
- **HTTPS enforced** on issuer URL and jwks_uri
- **Fail closed**: entire `pam_sm_authenticate` wrapped in try/except returning PAM_AUTH_ERR
- **No token content in logs**; only success/failure + error category
- **Atomic cache writes**: tempfile + rename to prevent partial reads

## Dependencies

- `PyJWT[crypto]>=2.8.0` — JWT decode/verify with RSA/EC support
- `requests>=2.31.0` — HTTP for discovery + JWKS fetch
- Dev: `pytest`, `pytest-cov`, `ruff`, `responses`
