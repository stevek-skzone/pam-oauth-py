"""Tests for JWT token validation."""

import time

import pytest
import responses

from pam_oauth2 import jwks_cache
from pam_oauth2.config import PamOAuth2Config
from pam_oauth2.token_validator import TokenValidationError, validate_token

ISSUER = "https://login.example.com"
DISCOVERY_URL = "https://login.example.com/.well-known/openid-configuration"
JWKS_URI = "https://login.example.com/.well-known/jwks.json"


@pytest.fixture
def config():
    return PamOAuth2Config(
        issuer=ISSUER,
        audience="myapp",
        login_field="sub",
        cache_ttl=3600,
        algorithm="RS256",
    )


@pytest.fixture(autouse=True)
def _use_tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))


def _mock_discovery_and_jwks(jwks_response):
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER, "jwks_uri": JWKS_URI},
    )
    responses.get(JWKS_URI, json=jwks_response)


class TestValidateToken:
    @responses.activate
    def test_valid_token(self, make_jwt, config, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        token = make_jwt()
        claims = validate_token(token, "testuser", config)
        assert claims["sub"] == "testuser"
        assert claims["iss"] == ISSUER
        assert claims["aud"] == "myapp"

    @responses.activate
    def test_custom_login_field(self, make_jwt, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        cfg = PamOAuth2Config(
            issuer=ISSUER,
            audience="myapp",
            login_field="email",
            cache_ttl=3600,
            algorithm="RS256",
        )
        token = make_jwt(extra_claims={"email": "alice@example.com"})
        claims = validate_token(token, "alice@example.com", cfg)
        assert claims["email"] == "alice@example.com"

    @responses.activate
    def test_expired_token(self, make_jwt, config, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        token = make_jwt(exp=time.time() - 100)
        with pytest.raises(TokenValidationError, match="token has expired"):
            validate_token(token, "testuser", config)

    @responses.activate
    def test_wrong_audience(self, make_jwt, config, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        token = make_jwt(aud="wrong-app")
        with pytest.raises(TokenValidationError, match="invalid audience"):
            validate_token(token, "testuser", config)

    @responses.activate
    def test_wrong_issuer(self, make_jwt, config, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        token = make_jwt(iss="https://evil.example.com")
        with pytest.raises(TokenValidationError, match="invalid issuer"):
            validate_token(token, "testuser", config)

    @responses.activate
    def test_username_mismatch(self, make_jwt, config, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        token = make_jwt(sub="otheruser")
        with pytest.raises(TokenValidationError, match="login_field mismatch"):
            validate_token(token, "testuser", config)

    @responses.activate
    def test_missing_login_field_claim(self, make_jwt, jwks_response):
        _mock_discovery_and_jwks(jwks_response)
        cfg = PamOAuth2Config(
            issuer=ISSUER,
            audience="myapp",
            login_field="email",
            cache_ttl=3600,
            algorithm="RS256",
        )
        token = make_jwt()  # no email claim
        with pytest.raises(TokenValidationError, match="missing login_field"):
            validate_token(token, "testuser", cfg)

    def test_invalid_token_format(self, config):
        with pytest.raises(TokenValidationError, match="invalid token header"):
            validate_token("not-a-jwt", "testuser", config)

    @responses.activate
    def test_algorithm_mismatch(self, make_jwt, config, jwks_response):
        """Token signed with different alg than config should be rejected."""
        _mock_discovery_and_jwks(jwks_response)
        # The make_jwt signs with RS256, but config expects ES256
        cfg = PamOAuth2Config(
            issuer=ISSUER,
            audience="myapp",
            login_field="sub",
            cache_ttl=3600,
            algorithm="ES256",
        )
        token = make_jwt()
        with pytest.raises(TokenValidationError, match="token algorithm mismatch"):
            validate_token(token, "testuser", cfg)


class TestJWKSCacheBustRetry:
    @responses.activate
    def test_key_rotation_retry(self, make_jwt, config, rsa_private_key, jwk_dict):
        """When kid is not in cached JWKS, should re-fetch and find the new key."""
        # First JWKS response has a different key
        old_jwks = {"keys": [{"kty": "RSA", "kid": "old-key-99", "n": "abc", "e": "AQAB"}]}
        new_jwks = {"keys": [jwk_dict]}

        # Discovery is called twice (once for initial, once for cache-bust)
        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(JWKS_URI, json=old_jwks)
        responses.get(JWKS_URI, json=new_jwks)

        token = make_jwt(kid="test-key-1")
        claims = validate_token(token, "testuser", config)
        assert claims["sub"] == "testuser"

    @responses.activate
    def test_unknown_kid_after_retry(self, make_jwt, config, jwks_response):
        """If kid is still not found after retry, should fail."""
        wrong_jwks = {"keys": [{"kty": "RSA", "kid": "other-key", "n": "abc", "e": "AQAB"}]}

        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(JWKS_URI, json=wrong_jwks)
        responses.get(JWKS_URI, json=wrong_jwks)

        token = make_jwt()
        with pytest.raises(TokenValidationError, match="no matching key found"):
            validate_token(token, "testuser", config)
