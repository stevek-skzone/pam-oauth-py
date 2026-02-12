"""Tests for PAM argument parsing and config validation."""

import pytest

from pam_oauth2.config import ConfigError, parse_args


def _argv(*args: str) -> list[str]:
    """Build an argv list with a dummy module path as argv[0]."""
    return ["/opt/pam-oauth2/pam_oauth2.py", *args]


class TestParseArgs:
    def test_minimal_valid(self):
        cfg = parse_args(_argv("issuer=https://login.example.com", "aud=myapp"))
        assert cfg.issuer == "https://login.example.com"
        assert cfg.audience == "myapp"
        assert cfg.login_field == "sub"
        assert cfg.cache_ttl == 3600
        assert cfg.algorithm == "RS256"

    def test_all_fields(self):
        cfg = parse_args(_argv(
            "issuer=https://login.example.com",
            "aud=myapp",
            "login_field=email",
            "cache_ttl=600",
            "algorithm=ES256",
        ))
        assert cfg.login_field == "email"
        assert cfg.cache_ttl == 600
        assert cfg.algorithm == "ES256"

    def test_audience_alias(self):
        cfg = parse_args(_argv("issuer=https://login.example.com", "audience=myapp"))
        assert cfg.audience == "myapp"

    def test_algorithms_list(self):
        cfg = parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "algorithm=ES384"))
        assert cfg.algorithms_list() == ["ES384"]

    def test_frozen(self):
        cfg = parse_args(_argv("issuer=https://login.example.com", "aud=myapp"))
        with pytest.raises(AttributeError):
            cfg.issuer = "https://other.example.com"


class TestConfigErrors:
    def test_missing_issuer(self):
        with pytest.raises(ConfigError, match="missing required argument: issuer"):
            parse_args(_argv("aud=myapp"))

    def test_missing_audience(self):
        with pytest.raises(ConfigError, match="missing required argument: aud"):
            parse_args(_argv("issuer=https://login.example.com"))

    def test_http_issuer(self):
        with pytest.raises(ConfigError, match="issuer must use HTTPS"):
            parse_args(_argv("issuer=http://login.example.com", "aud=myapp"))

    def test_no_scheme_issuer(self):
        with pytest.raises(ConfigError, match="issuer must use HTTPS"):
            parse_args(_argv("issuer=login.example.com", "aud=myapp"))

    def test_hs256_blocked(self):
        with pytest.raises(ConfigError, match="algorithm not allowed"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "algorithm=HS256"))

    def test_none_algorithm_blocked(self):
        with pytest.raises(ConfigError, match="algorithm not allowed"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "algorithm=none"))

    def test_unsupported_algorithm(self):
        with pytest.raises(ConfigError, match="unsupported algorithm"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "algorithm=XYZ"))

    def test_invalid_cache_ttl(self):
        with pytest.raises(ConfigError, match="cache_ttl must be an integer"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "cache_ttl=abc"))

    def test_negative_cache_ttl(self):
        with pytest.raises(ConfigError, match="cache_ttl must be non-negative"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "cache_ttl=-1"))

    def test_invalid_arg_format(self):
        with pytest.raises(ConfigError, match="invalid argument"):
            parse_args(_argv("issuer=https://login.example.com", "aud=myapp", "badarg"))
