"""Filesystem-based JWKS cache with TTL and atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time

from .logging import log_debug

CACHE_BASE = "/var/cache/pam_oauth2"


def _cache_dir(issuer: str) -> str:
    h = hashlib.sha256(issuer.encode()).hexdigest()[:16]
    return os.path.join(CACHE_BASE, h)


def _cache_path(issuer: str) -> str:
    return os.path.join(_cache_dir(issuer), "jwks.json")


def read_cached_jwks(issuer: str, ttl: int) -> dict | None:
    """Read JWKS from the filesystem cache if present and not expired.

    Returns the parsed JWKS dict, or None on cache miss / expired / error.
    """
    path = _cache_path(issuer)
    try:
        stat = os.stat(path)
    except OSError:
        log_debug("jwks cache miss (file not found)")
        return None

    age = time.time() - stat.st_mtime
    if age > ttl:
        log_debug(f"jwks cache expired (age={age:.0f}s, ttl={ttl}s)")
        return None

    try:
        with open(path) as f:
            data = json.load(f)
        log_debug("jwks cache hit")
        return data
    except (OSError, ValueError):
        log_debug("jwks cache miss (read/parse error)")
        return None


def write_cached_jwks(issuer: str, jwks: dict) -> None:
    """Atomically write JWKS data to the filesystem cache.

    Uses tempfile + rename on the same filesystem to prevent partial reads.
    Creates the cache directory if it doesn't exist.
    """
    cache_dir = _cache_dir(issuer)
    try:
        os.makedirs(cache_dir, mode=0o755, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=cache_dir, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(jwks, f)
            os.rename(tmp_path, _cache_path(issuer))
            log_debug("jwks cache written")
        except BaseException:
            # Clean up temp file on any error
            try:
                os.unlink(tmp_path)
            except OSError:
                # Best-effort cleanup: ignore errors deleting temporary cache file
                pass
            raise
    except OSError as exc:
        # Cache write failure is non-fatal
        log_debug(f"jwks cache write failed: {exc}")


def invalidate_cache(issuer: str) -> None:
    """Remove the cached JWKS file for the given issuer."""
    path = _cache_path(issuer)
    try:
        os.unlink(path)
        log_debug("jwks cache invalidated")
    except OSError:
        pass
