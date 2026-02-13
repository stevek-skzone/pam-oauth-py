"""Shared test fixtures: RSA keys, JWT factory, mock PAM handle."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# RSA key fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_public_key(rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture(scope="session")
def rsa_public_key_pem(rsa_public_key):
    return rsa_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(scope="session")
def jwk_dict(rsa_public_key):
    """Return a JWK dict for the test RSA key with kid='test-key-1'."""
    from jwt.algorithms import RSAAlgorithm
    jwk = RSAAlgorithm.to_jwk(rsa_public_key, as_dict=True)
    jwk["kid"] = "test-key-1"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return jwk


@pytest.fixture(scope="session")
def jwks_response(jwk_dict):
    """Return a JWKS dict with a single key."""
    return {"keys": [jwk_dict]}


# ---------------------------------------------------------------------------
# JWT factory
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def make_jwt(rsa_private_key):
    """Factory to create signed JWTs with customizable claims."""
    def _make(
        sub: str = "testuser",
        iss: str = "https://login.example.com",
        aud: str = "myapp",
        exp: float | None = None,
        kid: str = "test-key-1",
        algorithm: str = "RS256",
        extra_claims: dict | None = None,
    ) -> str:
        now = time.time()
        payload = {
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "exp": exp if exp is not None else now + 3600,
            "iat": now,
        }
        if extra_claims:
            payload.update(extra_claims)
        return jwt.encode(
            payload,
            rsa_private_key,
            algorithm=algorithm,
            headers={"kid": kid},
        )
    return _make


# ---------------------------------------------------------------------------
# Mock PAM handle
# ---------------------------------------------------------------------------

@dataclass
class MockConvMessage:
    msg_style: int
    msg: str


@dataclass
class MockConvResponse:
    resp: str
    resp_retcode: int = 0


@dataclass
class MockPamHandle:
    """Minimal mock of the pam_python pamh object."""
    user: str = "testuser"
    authtok: str | None = None
    _conv_responses: list[str] = field(default_factory=list)
    ruser: str | None = None

    class Message:
        PAM_PROMPT_ECHO_OFF = 1
        PAM_PROMPT_ECHO_ON = 2
        PAM_ERROR_MSG = 3
        PAM_TEXT_INFO = 4

        def __init__(self, msg_style: int = 0, msg: str = ""):
            self.msg_style = msg_style
            self.msg = msg

    PAM_SUCCESS = 0
    PAM_AUTH_ERR = 7
    PAM_USER_UNKNOWN = 10
    PAM_IGNORE = 25
    PAM_PROMPT_ECHO_OFF = 1

    def conversation(self, msg):
        if self._conv_responses:
            resp_text = self._conv_responses.pop(0)
        else:
            resp_text = ""
        return MockConvResponse(resp=resp_text)

    def get_user(self, prompt=None):
        return self.user


@pytest.fixture
def mock_pamh():
    return MockPamHandle()
