"""Identity Provider (IdP) and Resource Server utilities for awesome-python-auth.

Mirrors the ``IdProviderConfig``, ``ResourceServerConfig``, ``JwksService``,
and ``JwksClient`` from awesome-node-auth.

IdP mode
--------
When ``AuthConfig.id_provider`` is set, this instance acts as a central
Identity Provider:

- Generates (or loads) an RSA-2048 keypair and signs JWTs with **RS256**.
- Exposes a public ``GET /.well-known/jwks.json`` endpoint so downstream
  Resource Servers can verify tokens without sharing a secret.

Resource Server mode
--------------------
When ``AuthConfig.resource_server`` is set, this instance validates incoming
tokens against a remote JWKS endpoint (issued by a central IdP) instead of a
local HS256 secret.

Usage — IdP side::

    from awesome_python_auth import AuthConfig
    from awesome_python_auth.idp import IdProviderConfig

    config = AuthConfig(
        access_token_secret="...",
        id_provider=IdProviderConfig(
            enabled=True,
            # private_key="-----BEGIN PRIVATE KEY-----\\n...",  # optional
            issuer="https://auth.myplatform.com",
            token_expiry=2592000,   # 30 days in seconds
        ),
    )

Usage — Resource Server side::

    from awesome_python_auth import AuthConfig
    from awesome_python_auth.idp import ResourceServerConfig

    config = AuthConfig(
        access_token_secret="...",       # still required; unused in RS mode
        resource_server=ResourceServerConfig(
            enabled=True,
            jwks_url="https://auth.myplatform.com/.well-known/jwks.json",
            issuer="https://auth.myplatform.com",
        ),
    )
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import warnings
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class IdProviderConfig:
    """Configuration for Identity Provider (IdP) mode.

    When *enabled* (or when *private_key* is provided), the auth router:

    - Signs access and refresh tokens with **RS256** using the configured RSA
      keypair (auto-generated at startup when none is supplied — dev only).
    - Exposes ``GET /.well-known/jwks.json`` with the corresponding public key
      so Resource Servers can verify tokens without a shared secret.

    Parameters
    ----------
    enabled:
        Activate IdP mode.  Also activates automatically when *private_key* is
        set.  Default: ``False``.
    private_key:
        PEM-encoded RSA private key.  When omitted an ephemeral RSA-2048
        keypair is auto-generated at startup (for development only — tokens
        are invalidated on restart).
    public_key:
        PEM-encoded RSA public key.  Automatically derived from *private_key*
        when omitted.
    jwks_path:
        URL path at which the JWKS endpoint is served.
        Default: ``'/.well-known/jwks.json'``.
    issuer:
        ``iss`` claim embedded in every IdP-issued JWT.  Resource Servers
        validate this claim.  Example: ``'https://auth.myplatform.com'``.
    token_expiry:
        Access-token lifetime in seconds for IdP-issued tokens.
        Default: ``2592000`` (30 days).
    refresh_token_expiry:
        Refresh-token lifetime in seconds for IdP-issued tokens.
        Default: ``7776000`` (90 days).
    """

    enabled: bool = False
    private_key: str | None = None
    public_key: str | None = None
    jwks_path: str = "/.well-known/jwks.json"
    issuer: str | None = None
    token_expiry: int = 2592000       # 30 days
    refresh_token_expiry: int = 7776000  # 90 days


@dataclass
class ResourceServerConfig:
    """Configuration for Resource Server (RS) mode.

    When *enabled*, the auth dependencies validate incoming tokens against a
    remote JWKS endpoint (issued by a central IdP) instead of a local HS256
    secret.

    Parameters
    ----------
    enabled:
        Activate Resource Server mode.  Default: ``False``.
    jwks_url:
        Full URL of the IdP's JWKS endpoint.
        Example: ``'https://auth.myplatform.com/.well-known/jwks.json'``.
    issuer:
        Expected ``iss`` claim.  When set, tokens with a different issuer are
        rejected.
    jwks_cache_ttl:
        Public-key cache TTL in seconds.  Default: ``3600`` (1 hour).
    jwks_fetch_timeout:
        Timeout for JWKS fetch requests in seconds.  Default: ``5``.
    """

    enabled: bool = False
    jwks_url: str = ""
    issuer: str | None = None
    jwks_cache_ttl: int = 3600      # 1 hour
    jwks_fetch_timeout: float = 5.0


# ---------------------------------------------------------------------------
# JWK types
# ---------------------------------------------------------------------------


class JWK:
    """A single JSON Web Key (RSA public key in JWK format)."""

    def __init__(
        self,
        *,
        kty: str,
        use: str,
        alg: str,
        kid: str,
        n: str,
        e: str,
    ) -> None:
        self.kty = kty
        self.use = use
        self.alg = alg
        self.kid = kid
        self.n = n
        self.e = e

    def to_dict(self) -> dict[str, str]:
        return {
            "kty": self.kty,
            "use": self.use,
            "alg": self.alg,
            "kid": self.kid,
            "n": self.n,
            "e": self.e,
        }


# ---------------------------------------------------------------------------
# JwksService — keypair management and format conversion
# ---------------------------------------------------------------------------


class JwksService:
    """Utility class for RSA keypair management and JWK format conversion.

    All methods are static — no instance is required.
    """

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """Generate an RSA-2048 keypair.

        Returns
        -------
        tuple[str, str]
            ``(private_key_pem, public_key_pem)`` — PEM-encoded strings.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_pem, public_pem

    @staticmethod
    def derive_public_key(private_key_pem: str) -> str:
        """Derive the PEM-encoded public key from a PEM-encoded private key."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(private_key_pem.encode(), password=None)
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @staticmethod
    def public_key_to_jwk(public_key_pem: str, kid: str = "provisioner-key-1") -> JWK:
        """Convert a PEM-encoded RSA public key to a :class:`JWK` object."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        import base64

        pub = load_pem_public_key(public_key_pem.encode())
        if not isinstance(pub, RSAPublicKey):
            raise ValueError("Only RSA public keys are supported")

        pub_numbers = pub.public_numbers()

        def _int_to_base64url(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            raw = n.to_bytes(length, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return JWK(
            kty="RSA",
            use="sig",
            alg="RS256",
            kid=kid,
            n=_int_to_base64url(pub_numbers.n),
            e=_int_to_base64url(pub_numbers.e),
        )

    @staticmethod
    def build_jwks_document(
        public_key_pem: str,
        kid: str = "provisioner-key-1",
    ) -> dict[str, Any]:
        """Build a full JWKS document from a PEM-encoded RSA public key."""
        jwk = JwksService.public_key_to_jwk(public_key_pem, kid)
        return {"keys": [jwk.to_dict()]}

    @staticmethod
    def jwk_to_public_key_pem(jwk: JWK | dict[str, str]) -> str:
        """Convert a JWK to a PEM-encoded RSA public key string."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.rsa import (
            RSAPublicNumbers,
        )
        from cryptography.hazmat.backends import default_backend

        if isinstance(jwk, JWK):
            n_b64, e_b64 = jwk.n, jwk.e
        else:
            n_b64, e_b64 = jwk["n"], jwk["e"]

        def _b64url_to_int(s: str) -> int:
            padded = s + "=" * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        n = _b64url_to_int(n_b64)
        e = _b64url_to_int(e_b64)
        pub = RSAPublicNumbers(e, n).public_key(default_backend())
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()


# ---------------------------------------------------------------------------
# JwksClient — cached HTTP client for remote JWKS endpoints
# ---------------------------------------------------------------------------

_EPHEMERAL_WARNING_EMITTED = False


class JwksClient:
    """Cached JWKS client for Resource Server use.

    Fetches and caches the public keys from a remote JWKS URL.
    Uses stale-while-revalidate: returns the cached document immediately
    when available, then refreshes in the background when the TTL expires.

    Parameters
    ----------
    jwks_url:
        Full URL of the JWKS endpoint.
    cache_ttl:
        Cache TTL in seconds.  Default: ``3600``.
    fetch_timeout:
        HTTP fetch timeout in seconds.  Default: ``5``.
    """

    def __init__(
        self,
        jwks_url: str,
        *,
        cache_ttl: float = 3600.0,
        fetch_timeout: float = 5.0,
    ) -> None:
        self.jwks_url = jwks_url
        self._cache_ttl = cache_ttl
        self._fetch_timeout = fetch_timeout
        self._cached_document: dict[str, Any] | None = None
        self._cache_expiry: float = 0.0
        self._fetch_lock = asyncio.Lock()

    async def get_jwks(self) -> dict[str, Any]:
        """Return the JWKS document, fetching from remote if the cache is stale."""
        now = time.monotonic()
        if self._cached_document and now < self._cache_expiry:
            return self._cached_document

        async with self._fetch_lock:
            # Double-checked locking
            now = time.monotonic()
            if self._cached_document and now < self._cache_expiry:
                return self._cached_document

            doc = await self._fetch()
            self._cached_document = doc
            self._cache_expiry = time.monotonic() + self._cache_ttl
            return doc

    async def get_key(self, kid: str) -> dict[str, str] | None:
        """Find a JWK by its key ID (``kid``).  Returns ``None`` if not found."""
        doc = await self.get_jwks()
        for k in doc.get("keys", []):
            if k.get("kid") == kid:
                return k
        return None

    def invalidate_cache(self) -> None:
        """Force-invalidate the cache so the next call fetches fresh keys."""
        self._cached_document = None
        self._cache_expiry = 0.0

    async def _fetch(self) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(self.jwks_url, timeout=self._fetch_timeout)
            resp.raise_for_status()
            doc = resp.json()
            if not isinstance(doc.get("keys"), list):
                raise ValueError(f"Invalid JWKS document from {self.jwks_url}: missing 'keys' array")
            return doc


# ---------------------------------------------------------------------------
# Resolve / initialise IdP keypair (called by router + jwt_utils)
# ---------------------------------------------------------------------------

_ephemeral_warning_emitted: bool = False


def resolve_idp_keypair(cfg: IdProviderConfig) -> tuple[str, str]:
    """Return ``(private_key_pem, public_key_pem)`` for the IdP config.

    If no key is configured an ephemeral keypair is auto-generated (with a
    one-time warning) and stored back into *cfg* so subsequent calls reuse it.
    """
    global _ephemeral_warning_emitted

    if not cfg.private_key:
        if not _ephemeral_warning_emitted:
            warnings.warn(
                "[awesome-python-auth] IdP mode: no private_key configured — "
                "auto-generating an ephemeral RSA-2048 keypair.  "
                "All tokens will be invalidated on restart.  "
                "Set id_provider.private_key in production.",
                stacklevel=3,
            )
            _ephemeral_warning_emitted = True

        priv, pub = JwksService.generate_keypair()
        cfg.private_key = priv
        cfg.public_key = pub
        return priv, pub

    if not cfg.public_key:
        cfg.public_key = JwksService.derive_public_key(cfg.private_key)

    return cfg.private_key, cfg.public_key
