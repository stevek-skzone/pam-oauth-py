# pam-oauth-py

A Python PAM module that authenticates users by validating OAuth2/OIDC JWT tokens. It integrates with Linux PAM via [`pam_python`](http://pam-python.sourceforge.net/), fetches keys from your OIDC provider's JWKS endpoint, and verifies that the token's claims match the PAM user.

## How it works

```
pam_python.so  -->  pam_oauth2.py (shim)  -->  pam_sm_authenticate()
```

1. PAM arguments (`issuer=`, `aud=`, etc.) are parsed from the PAM config line.
2. The username is read from PAM and the JWT is obtained from `authtok` (set by a prior module, e.g. `pam_unix`) or by prompting the user via PAM conversation.
3. The OIDC discovery document is fetched from `<issuer>/.well-known/openid-configuration` to locate the JWKS URI.
4. The JWKS is fetched (or read from a local filesystem cache) and the signing key matching the token's `kid` header is selected.
5. The JWT signature is verified and standard claims (`iss`, `aud`, `exp`) are validated.
6. A configurable claim (default: `sub`) is checked against the PAM username.
7. `PAM_SUCCESS` or `PAM_AUTH_ERR` is returned. Any unexpected error results in `PAM_AUTH_ERR` (fail closed).

## Requirements

- Python >= 3.9
- [`pam_python`](http://pam-python.sourceforge.net/) installed on the target system (`libpam-python` on Debian/Ubuntu)
- Network access from the PAM host to the OIDC issuer's discovery and JWKS endpoints

## Installation

### Install pam_python

```bash
# Debian/Ubuntu
sudo apt-get install libpam-python

# RHEL/CentOS (from source — see pam_python docs)
```

### Install pam-oauth2

```bash
# Clone and install into a dedicated directory
sudo mkdir -p /opt/pam-oauth2
cd /opt/pam-oauth2
git clone https://github.com/yourorg/pam-oauth-py.git .
uv sync --frozen
```

The module needs two things at runtime:

- The `pam_oauth2.py` shim file (entry point for pam_python)
- The `pam_oauth2` package and its dependencies (`PyJWT[crypto]`, `requests`)

If you install with `uv sync`, the virtual environment at `.venv/` contains everything. You can alternatively `pip install .` into a system or dedicated virtualenv.

### Create the JWKS cache directory

```bash
sudo mkdir -p /var/cache/pam_oauth2
sudo chmod 755 /var/cache/pam_oauth2
```

The module caches JWKS responses here as `/var/cache/pam_oauth2/<sha256-prefix>/jwks.json`. The process running PAM (e.g. `sshd`) needs write access to this directory. If the cache directory is not writable, the module still works -- it just fetches JWKS on every authentication.

## PAM configuration

Add a line to the relevant PAM service file (e.g. `/etc/pam.d/sshd`):

```
auth  sufficient  pam_python.so  /opt/pam-oauth2/pam_oauth2.py  issuer=https://login.example.com  aud=myapp
```

### Configuration parameters

All parameters are passed as `key=value` pairs after the module path.

| Parameter     | Required | Default  | Description |
|---------------|----------|----------|-------------|
| `issuer`      | Yes      | --       | OIDC issuer URL. **Must be HTTPS.** |
| `aud`         | Yes      | --       | Expected `aud` claim in the JWT. Also accepts `audience` as an alias. |
| `login_field` | No       | `sub`    | JWT claim to match against the PAM username. |
| `cache_ttl`   | No       | `3600`   | JWKS cache lifetime in seconds. Set to `0` to disable caching. |
| `algorithm`   | No       | `RS256`  | JWT signing algorithm. Must be asymmetric (see below). |

### Supported algorithms

RSA: `RS256`, `RS384`, `RS512`
EC: `ES256`, `ES384`, `ES512`
RSA-PSS: `PS256`, `PS384`, `PS512`

Symmetric algorithms (`HS256`, `HS384`, `HS512`) and `none` are **explicitly blocked** and will cause a configuration error. The algorithm is always taken from the PAM configuration, never from the token header.

### Full example

```
# /etc/pam.d/sshd
# Try OAuth JWT first; fall back to normal password auth
auth  sufficient  pam_python.so  /opt/pam-oauth2/pam_oauth2.py  issuer=https://login.example.com  aud=ssh-prod  login_field=email  cache_ttl=1800  algorithm=RS256
auth  required    pam_unix.so
```

In this setup:
- Users can authenticate with a JWT as their password. The JWT's `email` claim must match their Linux username.
- If the JWT is invalid or not provided, normal password authentication is attempted via `pam_unix`.

## Using with SSH

When using with OpenSSH, the client sends the JWT as the password:

```bash
# Interactive (paste the token at the password prompt)
ssh user@host

# Non-interactive
sshpass -p "$(cat token.jwt)" ssh user@host
```

Make sure `PasswordAuthentication yes` is set in `/etc/ssh/sshd_config` (or `KbdInteractiveAuthentication yes` depending on your PAM/SSH setup).

## Logging

All log output goes to syslog under the `LOG_AUTH` facility with the tag `pam_oauth2`. No token content is ever logged -- only success/failure and error categories.

```bash
# View auth logs
sudo journalctl -t pam_oauth2
# or
sudo grep pam_oauth2 /var/log/auth.log
```

Example log entries:

```
pam_oauth2[12345]: authentication succeeded for user 'alice'
pam_oauth2[12345]: authentication failed for user 'bob': token has expired
pam_oauth2[12345]: configuration error: issuer must use HTTPS: http://bad.example.com
```

## Security properties

- **Fail closed**: The entire `pam_sm_authenticate` function is wrapped in a try/except. Any unexpected error returns `PAM_AUTH_ERR` (authentication denied).
- **Asymmetric algorithms only**: HS256/HS384/HS512 and `none` are blocked at configuration parsing time. The algorithm is read from PAM config, never from the token header. Token header algorithm is verified to match the configured algorithm before signature verification.
- **HTTPS enforced**: Both the issuer URL and the `jwks_uri` from the discovery document must use HTTPS.
- **Issuer validation**: The `issuer` field in the OIDC discovery document must match the configured issuer (per RFC 8414 section 3.3).
- **Atomic cache writes**: JWKS cache files are written via `tempfile.mkstemp` + `os.rename` on the same filesystem, preventing partial reads by concurrent PAM processes.
- **No sensitive data in logs**: Token content is never logged. Only usernames, success/failure status, and error categories appear in syslog.
- **Key rotation handling**: If the token's `kid` is not found in the cached JWKS, the cache is invalidated and JWKS is re-fetched once before failing. This handles key rotation without requiring manual cache clearing.

## Development

### Prerequisites

- Python >= 3.9
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Setup

```bash
git clone https://github.com/yourorg/pam-oauth-py.git
cd pam-oauth-py
uv sync
```

This installs all runtime and dev dependencies into `.venv/`.

### Running tests

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage report
uv run pytest tests/ -v --cov=pam_oauth2 --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_config.py -v

# Run a specific test
uv run pytest tests/test_token_validator.py::TestValidateToken::test_valid_token -v
```

Tests do **not** require `pam_python`, a running OIDC provider, or root access. All HTTP calls are mocked with the [`responses`](https://github.com/getsentry/responses) library, and cryptographic operations use real RSA keys generated at test time.

### Linting

```bash
# Check for issues
uv run ruff check src/ tests/

# Auto-fix what can be fixed
uv run ruff check --fix src/ tests/
```

### Project structure

```
pam-oauth-py/
├── pyproject.toml                 # Project config (uv/hatch, dependencies, tool settings)
├── pam_oauth2.py                  # Thin shim loaded by pam_python.so
├── src/pam_oauth2/
│   ├── __init__.py
│   ├── pam_sm.py                  # PAM entry points (pam_sm_authenticate, etc.)
│   ├── config.py                  # Parse key=value PAM args into frozen dataclass
│   ├── discovery.py               # Fetch OIDC .well-known/openid-configuration
│   ├── jwks_cache.py              # Filesystem JWKS cache with TTL
│   ├── token_validator.py         # JWT signature + claims validation
│   └── logging.py                 # Syslog wrapper (LOG_AUTH facility)
└── tests/
    ├── conftest.py                # RSA key fixtures, JWT factory, mock pamh
    ├── test_config.py             # Config parsing and validation (15 tests)
    ├── test_discovery.py          # OIDC discovery (9 tests)
    ├── test_jwks_cache.py         # Filesystem cache (8 tests)
    ├── test_token_validator.py    # JWT validation + key rotation (11 tests)
    ├── test_pam_sm.py             # PAM entry points (13 tests)
    └── test_integration.py        # End-to-end with mocked HTTP (11 tests)
```

### Architecture

The module is split into focused layers so each can be tested independently:

**`config.py`** -- Parses the PAM argument list (`argv[1:]`) into a frozen `PamOAuth2Config` dataclass. Validates HTTPS on the issuer URL, rejects blocked algorithms, and checks `cache_ttl` is a non-negative integer. Raises `ConfigError` on any invalid input.

**`discovery.py`** -- Fetches the OIDC discovery document from `<issuer>/.well-known/openid-configuration`. Validates the response's `issuer` field matches the configured issuer (RFC 8414) and that `jwks_uri` uses HTTPS. Raises `DiscoveryError` on failure.

**`jwks_cache.py`** -- Manages a filesystem cache at `/var/cache/pam_oauth2/<sha256_prefix>/jwks.json`. Reads check file `mtime` against the configured TTL. Writes use `tempfile.mkstemp()` + `os.rename()` for atomicity. Cache failures are non-fatal (the module falls back to live fetching).

**`token_validator.py`** -- Orchestrates the full validation flow: reads the JWT header to extract `kid` and verify the algorithm, looks up the key in JWKS (with one cache-bust retry on `kid` miss), verifies the signature with `PyJWT`, validates `iss`/`aud`/`exp` claims, and checks the `login_field` claim matches the PAM username. Raises `TokenValidationError` on failure.

**`pam_sm.py`** -- Implements the PAM entry points called by `pam_python.so`. `pam_sm_authenticate` is the main function: it parses config, obtains the token, calls `validate_token`, and returns `PAM_SUCCESS` or `PAM_AUTH_ERR`. The entire function is wrapped in a catch-all exception handler that returns `PAM_AUTH_ERR` (fail closed).

**`pam_oauth2.py`** (root shim) -- Re-exports all `pam_sm_*` functions from the package. This file is what `pam_python.so` loads directly.

### Test fixtures

The test suite in `tests/conftest.py` provides shared fixtures:

- **`rsa_private_key` / `rsa_public_key`** -- A 2048-bit RSA key pair generated once per test session.
- **`jwk_dict` / `jwks_response`** -- The public key formatted as a JWK dict and wrapped in a JWKS `{"keys": [...]}` response.
- **`make_jwt`** -- A factory function that creates signed JWTs with customizable `sub`, `iss`, `aud`, `exp`, `kid`, and arbitrary extra claims.
- **`mock_pamh`** -- A `MockPamHandle` dataclass that mimics the `pam_python` `pamh` object, supporting `get_user()`, `authtok`, `Message()`, and `conversation()`.

### Adding a new test

Tests follow a consistent pattern. HTTP calls are mocked with `@responses.activate` and the JWKS cache is redirected to `tmp_path` via an autouse fixture:

```python
@responses.activate
def test_my_scenario(self, make_jwt, config, jwks_response):
    # Set up mock HTTP responses
    responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
    responses.get(JWKS_URI, json=jwks_response)

    # Create a token and validate
    token = make_jwt(sub="alice", extra_claims={"email": "alice@example.com"})
    claims = validate_token(token, "alice", config)
    assert claims["sub"] == "alice"
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `PyJWT[crypto]` >= 2.8.0 | JWT decoding/verification with `cryptography` backend for RSA/EC |
| `requests` >= 2.31.0 | HTTP client for OIDC discovery and JWKS fetching |
| `pytest` >= 7.0 | Test runner |
| `pytest-cov` >= 4.0 | Coverage reporting |
| `ruff` >= 0.4.0 | Linting and import sorting |
| `responses` >= 0.25.0 | HTTP request mocking for tests |

## Troubleshooting

### "configuration error: issuer must use HTTPS"

The `issuer` parameter must be an `https://` URL. HTTP is not supported for security reasons.

### "configuration error: algorithm not allowed (symmetric/none)"

You specified `algorithm=HS256` (or HS384/HS512/none). Only asymmetric algorithms are supported. Use `RS256` (default) or another supported algorithm.

### "authentication failed: token has expired"

The JWT's `exp` claim is in the past. Ensure the token is fresh and that the PAM host's system clock is accurate (use NTP).

### "authentication failed: login_field mismatch"

The JWT claim specified by `login_field` doesn't match the Linux username. For example, if `login_field=email` and the token has `"email": "alice@example.com"`, the Linux username must be exactly `alice@example.com`.

### "authentication failed: no matching key found for kid"

The signing key ID in the token doesn't match any key in the OIDC provider's JWKS. This can happen if the provider rotated keys and the cache is stale (the module retries once automatically) or if the token was signed by a different provider.

### Cache permissions

If you see `jwks cache write failed` in syslog, ensure the PAM process has write access to `/var/cache/pam_oauth2/`. The module continues to work without caching, but will fetch JWKS on every authentication attempt.

```bash
# Fix permissions (adjust user/group to match your PAM service)
sudo chown root:root /var/cache/pam_oauth2
sudo chmod 755 /var/cache/pam_oauth2
```

## License

MIT -- see [LICENSE](LICENSE).
