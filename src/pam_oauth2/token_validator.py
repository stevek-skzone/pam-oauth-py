"""JWT token validation with JWKS fetching and caching."""

from __future__ import annotations

import jwt
import requests

from .config import PamOAuth2Config
from .discovery import get_jwks_uri
from .jwks_cache import invalidate_cache, read_cached_jwks, write_cached_jwks
from .logging import log_debug

JWKS_FETCH_TIMEOUT = 10


class TokenValidationError(Exception):
    pass


def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch the JWKS document from the given URI."""
    try:
        resp = requests.get(jwks_uri, timeout=JWKS_FETCH_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        raise TokenValidationError(f"failed to fetch JWKS: {exc}") from exc
    except ValueError as exc:
        raise TokenValidationError(f"JWKS is not valid JSON: {exc}") from exc


def _get_jwks(config: PamOAuth2Config) -> dict:
    """Get JWKS, using cache if available."""
    cached = read_cached_jwks(config.issuer, config.cache_ttl)
    if cached is not None:
        return cached

    jwks_uri = get_jwks_uri(config.issuer)
    jwks = _fetch_jwks(jwks_uri)
    write_cached_jwks(config.issuer, jwks)
    return jwks


def _find_key(jwks: dict, kid: str) -> dict | None:
    """Find the key with the matching kid in the JWKS."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


def validate_token(token: str, username: str, config: PamOAuth2Config) -> dict:
    """Validate a JWT token and return the decoded claims.

    Steps:
    1. Decode the JWT header to get the kid
    2. Look up the key in cached JWKS
    3. On kid miss, cache-bust and re-fetch JWKS once (handles key rotation)
    4. Verify signature with the matched key
    5. Validate standard claims (iss, aud, exp)
    6. Check that login_field claim matches the PAM username

    Raises TokenValidationError on any failure.
    """
    # Decode header without verification to get kid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as exc:
        raise TokenValidationError(f"invalid token header: {exc}") from exc

    kid = unverified_header.get("kid")
    if not kid:
        raise TokenValidationError("token header missing 'kid'")

    token_alg = unverified_header.get("alg", "")
    if token_alg != config.algorithm:
        raise TokenValidationError(
            f"token algorithm mismatch: token={token_alg}, config={config.algorithm}"
        )

    # Get JWKS and find matching key
    jwks = _get_jwks(config)
    key_data = _find_key(jwks, kid)

    # Cache-bust retry once on kid miss (key rotation scenario)
    if key_data is None:
        log_debug(f"kid '{kid}' not in cached JWKS, re-fetching")
        invalidate_cache(config.issuer)
        jwks = _get_jwks(config)
        key_data = _find_key(jwks, kid)

    if key_data is None:
        raise TokenValidationError(f"no matching key found for kid '{kid}'")

    # Build the public key from JWK
    try:
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm
        alg = config.algorithm
        if alg.startswith("RS") or alg.startswith("PS"):
            public_key = RSAAlgorithm.from_jwk(key_data)
        elif alg.startswith("ES"):
            public_key = ECAlgorithm.from_jwk(key_data)
        else:
            raise TokenValidationError(f"unsupported algorithm family: {alg}")
    except (ValueError, KeyError) as exc:
        raise TokenValidationError(f"invalid JWK data: {exc}") from exc

    # Verify signature and standard claims
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=config.algorithms_list(),
            audience=config.audience,
            issuer=config.issuer,
            options={
                "require": ["exp", "iss", "aud"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenValidationError("token has expired") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenValidationError(f"invalid audience: {exc}") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenValidationError(f"invalid issuer: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenValidationError(f"token validation failed: {exc}") from exc

    # Check login_field matches PAM username
    login_value = claims.get(config.login_field)
    if login_value is None:
        raise TokenValidationError(
            f"token missing login_field claim '{config.login_field}'"
        )
    if str(login_value) != username:
        raise TokenValidationError(
            f"login_field mismatch: claim '{config.login_field}'="
            f"'{login_value}', pam_user='{username}'"
        )

    return claims
