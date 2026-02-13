"""Tests for filesystem JWKS cache."""

import os
import time

from pam_oauth2 import jwks_cache
from pam_oauth2.jwks_cache import invalidate_cache, read_cached_jwks, write_cached_jwks

ISSUER = "https://login.example.com"
SAMPLE_JWKS = {"keys": [{"kty": "RSA", "kid": "test-key-1"}]}


def test_write_and_read(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)
    result = read_cached_jwks(ISSUER, ttl=3600)
    assert result == SAMPLE_JWKS


def test_cache_miss_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    assert read_cached_jwks(ISSUER, ttl=3600) is None


def test_cache_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)

    # Backdate the file modification time
    cache_path = os.path.join(
        str(tmp_path),
        jwks_cache._cache_dir(ISSUER).split("/")[-1],
        "jwks.json",
    )
    old_time = time.time() - 7200
    os.utime(cache_path, (old_time, old_time))

    assert read_cached_jwks(ISSUER, ttl=3600) is None


def test_invalidate(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)
    assert read_cached_jwks(ISSUER, ttl=3600) is not None

    invalidate_cache(ISSUER)
    assert read_cached_jwks(ISSUER, ttl=3600) is None


def test_invalidate_nonexistent(tmp_path, monkeypatch):
    """Invalidating a non-existent cache should not raise."""
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    invalidate_cache(ISSUER)


def test_atomic_write_creates_directory(tmp_path, monkeypatch):
    cache_base = tmp_path / "deep" / "nested"
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(cache_base))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)
    assert read_cached_jwks(ISSUER, ttl=3600) == SAMPLE_JWKS


def test_corrupt_cache_file(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)

    # Corrupt the file
    cache_path = os.path.join(
        str(tmp_path),
        jwks_cache._cache_dir(ISSUER).split("/")[-1],
        "jwks.json",
    )
    with open(cache_path, "w") as f:
        f.write("not json{{{")

    assert read_cached_jwks(ISSUER, ttl=3600) is None


def test_zero_ttl_always_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(jwks_cache, "CACHE_BASE", str(tmp_path))
    write_cached_jwks(ISSUER, SAMPLE_JWKS)
    # With ttl=0, even a fresh file is expired (age > 0)
    assert read_cached_jwks(ISSUER, ttl=0) is None
