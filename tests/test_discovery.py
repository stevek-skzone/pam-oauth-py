"""Tests for OIDC discovery document fetching."""

import pytest
import requests
import responses

from pam_oauth2.discovery import DiscoveryError, get_jwks_uri

ISSUER = "https://login.example.com"
DISCOVERY_URL = "https://login.example.com/.well-known/openid-configuration"
JWKS_URI = "https://login.example.com/.well-known/jwks.json"


@responses.activate
def test_successful_discovery():
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER, "jwks_uri": JWKS_URI},
    )
    assert get_jwks_uri(ISSUER) == JWKS_URI


@responses.activate
def test_trailing_slash_normalized():
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER + "/", "jwks_uri": JWKS_URI},
    )
    assert get_jwks_uri(ISSUER) == JWKS_URI


@responses.activate
def test_issuer_mismatch():
    responses.get(
        DISCOVERY_URL,
        json={"issuer": "https://evil.example.com", "jwks_uri": JWKS_URI},
    )
    with pytest.raises(DiscoveryError, match="issuer mismatch"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_missing_issuer_field():
    responses.get(
        DISCOVERY_URL,
        json={"jwks_uri": JWKS_URI},
    )
    with pytest.raises(DiscoveryError, match="missing 'issuer' field"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_missing_jwks_uri():
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER},
    )
    with pytest.raises(DiscoveryError, match="missing 'jwks_uri' field"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_http_jwks_uri_rejected():
    responses.get(
        DISCOVERY_URL,
        json={"issuer": ISSUER, "jwks_uri": "http://login.example.com/jwks.json"},
    )
    with pytest.raises(DiscoveryError, match="jwks_uri must use HTTPS"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_http_error():
    responses.get(DISCOVERY_URL, status=500)
    with pytest.raises(DiscoveryError, match="failed to fetch"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_invalid_json():
    responses.get(DISCOVERY_URL, body="not json", content_type="text/plain")
    with pytest.raises(DiscoveryError, match="not valid JSON"):
        get_jwks_uri(ISSUER)


@responses.activate
def test_connection_error():
    responses.get(DISCOVERY_URL, body=requests.ConnectionError("refused"))
    with pytest.raises(DiscoveryError, match="failed to fetch"):
        get_jwks_uri(ISSUER)
