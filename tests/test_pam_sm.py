"""Tests for PAM entry points."""

from unittest.mock import patch

import pytest
import responses

from pam_oauth2 import jwks_cache
from pam_oauth2.pam_sm import (
    PAM_AUTH_ERR,
    PAM_IGNORE,
    PAM_SUCCESS,
    pam_sm_acct_mgmt,
    pam_sm_authenticate,
    pam_sm_chauthtok,
    pam_sm_close_session,
    pam_sm_open_session,
    pam_sm_setcred,
)

ISSUER = "https://login.example.com"
DISCOVERY_URL = "https://login.example.com/.well-known/openid-configuration"
JWKS_URI = "https://login.example.com/.well-known/jwks.json"

ARGV = [
    "/opt/pam-oauth2/pam_oauth2.py",
    f"issuer={ISSUER}",
    "aud=myapp",
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


class TestPamSmAuthenticate:
    @responses.activate
    def test_success_with_authtok(self, mock_pamh, make_jwt, jwks_response):
        _setup_http(jwks_response)
        mock_pamh.authtok = make_jwt()
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_SUCCESS

    @responses.activate
    def test_success_with_conversation(self, mock_pamh, make_jwt, jwks_response):
        _setup_http(jwks_response)
        mock_pamh.authtok = None
        mock_pamh._conv_responses = [make_jwt()]
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_SUCCESS

    def test_bad_config(self, mock_pamh):
        result = pam_sm_authenticate(mock_pamh, 0, ["/path/to/module"])
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_expired_token(self, mock_pamh, make_jwt, jwks_response):
        _setup_http(jwks_response)
        import time
        mock_pamh.authtok = make_jwt(exp=time.time() - 100)
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_wrong_user(self, mock_pamh, make_jwt, jwks_response):
        _setup_http(jwks_response)
        mock_pamh.user = "wronguser"
        mock_pamh.authtok = make_jwt(sub="testuser")
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    def test_no_token(self, mock_pamh):
        mock_pamh.authtok = None
        mock_pamh._conv_responses = [""]
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    def test_no_user(self, mock_pamh):
        mock_pamh.user = ""
        mock_pamh.authtok = "some-token"
        result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR

    @responses.activate
    def test_fail_closed_on_unexpected_error(self, mock_pamh, make_jwt, jwks_response):
        """Any unexpected exception should result in PAM_AUTH_ERR."""
        _setup_http(jwks_response)
        mock_pamh.authtok = make_jwt()
        with patch(
            "pam_oauth2.pam_sm.validate_token",
            side_effect=RuntimeError("boom"),
        ):
            result = pam_sm_authenticate(mock_pamh, 0, ARGV)
        assert result == PAM_AUTH_ERR


class TestOtherPamEntryPoints:
    def test_setcred(self, mock_pamh):
        assert pam_sm_setcred(mock_pamh, 0, ARGV) == PAM_SUCCESS

    def test_acct_mgmt(self, mock_pamh):
        assert pam_sm_acct_mgmt(mock_pamh, 0, ARGV) == PAM_IGNORE

    def test_open_session(self, mock_pamh):
        assert pam_sm_open_session(mock_pamh, 0, ARGV) == PAM_SUCCESS

    def test_close_session(self, mock_pamh):
        assert pam_sm_close_session(mock_pamh, 0, ARGV) == PAM_SUCCESS

    def test_chauthtok(self, mock_pamh):
        assert pam_sm_chauthtok(mock_pamh, 0, ARGV) == PAM_IGNORE
