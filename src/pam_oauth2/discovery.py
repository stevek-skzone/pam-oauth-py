"""OIDC discovery: fetch .well-known/openid-configuration."""

from __future__ import annotations

from urllib.parse import urlparse

import requests

from .logging import log_debug

DISCOVERY_TIMEOUT = 10


class DiscoveryError(Exception):
    pass


def get_jwks_uri(issuer: str) -> str:
    """Fetch the OIDC discovery document and return the jwks_uri.

    Validates that the discovery document's ``issuer`` field matches the
    configured issuer (RFC 8414) and that jwks_uri uses HTTPS.
    """
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    log_debug(f"fetching OIDC discovery from {discovery_url}")

    try:
        resp = requests.get(discovery_url, timeout=DISCOVERY_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise DiscoveryError(f"failed to fetch discovery document: {exc}") from exc

    try:
        doc = resp.json()
    except ValueError as exc:
        raise DiscoveryError(f"discovery document is not valid JSON: {exc}") from exc

    # Validate issuer matches (RFC 8414 section 3.3)
    doc_issuer = doc.get("issuer")
    if doc_issuer is None:
        raise DiscoveryError("discovery document missing 'issuer' field")
    if doc_issuer.rstrip("/") != issuer.rstrip("/"):
        raise DiscoveryError(
            f"issuer mismatch: configured={issuer}, discovery={doc_issuer}"
        )

    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise DiscoveryError("discovery document missing 'jwks_uri' field")

    parsed = urlparse(jwks_uri)
    if parsed.scheme != "https":
        raise DiscoveryError(f"jwks_uri must use HTTPS: {jwks_uri}")

    return jwks_uri
