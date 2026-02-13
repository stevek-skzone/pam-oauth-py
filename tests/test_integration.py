"""End-to-end integration tests with mocked HTTP and real crypto."""

import time

import pytest
import responses
from conftest import MockPamHandle

from pam_oauth2 import jwks_cache
from pam_oauth2.pam_sm import PAM_AUTH_ERR, PAM_SUCCESS, pam_sm_authenticate

ISSUER = "https://login.example.com"
DISCOVERY_URL = "https://login.example.com/.well-known/openid-configuration"
JWKS_URI = "https://login.example.com/.well-known/jwks.json"

ARGV = [
    "/opt/pam-oauth2/pam_oauth2.py",
    f"issuer={ISSUER}",
    "aud=myapp",
    "login_field=sub",
]


@pytest.fixture(autouse=True)
def _use_tmp_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))


def _setup_http(jwks_response):
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER, "jwks_uri": JWKS_URI},
    )
    responses.get(JWKS_URI, json=jwks_response)


class TestEndToEnd:
    @responses.activate
    def test_full_auth_flow_authtok(self, make_jwt, jwks_response):
        """Full flow: config parse → discovery → JWKS fetch → JWT validate → success."""
        _setup_http(jwks_response)

        pamh = MockPamHandle(user="testuser", authtok=make_jwt())
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_SUCCESS

    @responses.activate
    def test_full_auth_flow_conversation(self, make_jwt, jwks_response):
        """Token obtained via PAM conversation."""
        _setup_http(jwks_response)

        pamh = MockPamHandle(user="testuser", _conv_responses=[make_jwt()])
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_SUCCESS

    @responses.activate
    def test_expired_token_rejected(self, make_jwt, jwks_response):
        _setup_http(jwks_response)

        token = make_jwt(exp=time.time() - 300)
        pamh = MockPamHandle(user="testuser", authtok=token)
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_wrong_audience_rejected(self, make_jwt, jwks_response):
        _setup_http(jwks_response)

        token = make_jwt(aud="other-app")
        pamh = MockPamHandle(user="testuser", authtok=token)
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_wrong_issuer_rejected(self, make_jwt, jwks_response):
        _setup_http(jwks_response)

        token = make_jwt(iss="https://evil.example.com")
        pamh = MockPamHandle(user="testuser", authtok=token)
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_user_mismatch_rejected(self, make_jwt, jwks_response):
        _setup_http(jwks_response)

        token = make_jwt(sub="alice")
        pamh = MockPamHandle(user="bob", authtok=token)
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_email_login_field(self, make_jwt, jwks_response):
        """Use email as login_field."""
        _setup_http(jwks_response)

        argv = [*ARGV[:3], "login_field=email"]
        token = make_jwt(extra_claims={"email": "alice@example.com"})
        pamh = MockPamHandle(user="alice@example.com", authtok=token)
        result = pam_sm_authenticate(pamh, 0, argv)
        assert result == PAM_SUCCESS

    @responses.activate
    def test_jwks_caching(self, make_jwt, jwks_response):
        """Second auth should use cached JWKS — only one HTTP call pair."""
        _setup_http(jwks_response)

        pamh1 = MockPamHandle(user="testuser", authtok=make_jwt())
        assert pam_sm_authenticate(pamh1, 0, ARGV) == PAM_SUCCESS

        # Second call — JWKS is cached, no additional HTTP needed
        pamh2 = MockPamHandle(user="testuser", authtok=make_jwt())
        assert pam_sm_authenticate(pamh2, 0, ARGV) == PAM_SUCCESS

        # Discovery called once, JWKS called once
        assert len(responses.calls) == 2

    def test_garbage_token_rejected(self):
        pamh = MockPamHandle(user="testuser", authtok="garbage.token.here")
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    def test_bad_config_rejected(self):
        bad_argv = ["/opt/pam-oauth2/pam_oauth2.py", "issuer=http://insecure.com", "aud=myapp"]
        pamh = MockPamHandle(user="testuser", authtok="token")
        result = pam_sm_authenticate(pamh, 0, bad_argv)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_key_rotation_handled(self, make_jwt, jwk_dict, jwks_response):
        """Simulate key rotation: first JWKS has old key, re-fetch has new key."""
        old_jwks = {"keys": [{"kty": "RSA", "kid": "old-key", "n": "abc", "e": "AQAB"}]}

        # Two discovery calls + two JWKS calls (initial + cache-bust)
        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(DISCOVERY_URL, json={"issuer": ISSUER, "jwks_uri": JWKS_URI})
        responses.get(JWKS_URI, json=old_jwks)
        responses.get(JWKS_URI, json=jwks_response)

        token = make_jwt()
        pamh = MockPamHandle(user="testuser", authtok=token)
        result = pam_sm_authenticate(pamh, 0, ARGV)
        assert result == PAM_SUCCESS
