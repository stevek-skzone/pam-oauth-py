"""Parse PAM module arguments into a validated configuration."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

SAFE_ALGORITHMS = frozenset({
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
})
BLOCKED_ALGORITHMS = frozenset({"HS256", "HS384", "HS512", "none"})

_DEFAULTS = {
    "login_field": "sub",
    "cache_ttl": "3600",
    "algorithm": "RS256",
}


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class PamOAuth2Config:
    issuer: str
    audience: str
    login_field: str
    cache_ttl: int
    algorithm: str

    def algorithms_list(self) -> list[str]:
        return [self.algorithm]


def parse_args(argv: list[str]) -> PamOAuth2Config:
    """Parse key=value PAM arguments into a PamOAuth2Config.

    argv[0] is the module path (skipped). Remaining items are key=value pairs.
    """
    raw: dict[str, str] = dict(_DEFAULTS)

    for arg in argv[1:]:
        if "=" not in arg:
            raise ConfigError(f"invalid argument (expected key=value): {arg}")
        key, value = arg.split("=", 1)
        raw[key] = value

    # Required fields
    if "issuer" not in raw:
        raise ConfigError("missing required argument: issuer")
    if "aud" not in raw and "audience" not in raw:
        raise ConfigError("missing required argument: aud")

    issuer = raw["issuer"]
    audience = raw.get("aud") or raw.get("audience", "")
    login_field = raw["login_field"]
    algorithm = raw["algorithm"]

    # Validate issuer URL is HTTPS
    parsed = urlparse(issuer)
    if parsed.scheme != "https":
        raise ConfigError(f"issuer must use HTTPS: {issuer}")
    if not parsed.hostname:
        raise ConfigError(f"issuer must have a hostname: {issuer}")

    # Validate algorithm
    if algorithm in BLOCKED_ALGORITHMS:
        raise ConfigError(f"algorithm not allowed (symmetric/none): {algorithm}")
    if algorithm not in SAFE_ALGORITHMS:
        raise ConfigError(f"unsupported algorithm: {algorithm}")

    # Validate cache_ttl
    try:
        cache_ttl = int(raw["cache_ttl"])
    except ValueError:
        raise ConfigError(f"cache_ttl must be an integer: {raw['cache_ttl']}")
    if cache_ttl < 0:
        raise ConfigError(f"cache_ttl must be non-negative: {cache_ttl}")

    return PamOAuth2Config(
        issuer=issuer,
        audience=audience,
        login_field=login_field,
        cache_ttl=cache_ttl,
        algorithm=algorithm,
    )
