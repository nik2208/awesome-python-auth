"""JWT creation and verification utilities for awesome-python-auth.

Supports both HS256 (shared-secret, default) and RS256 (RSA, IdP mode).
"""

from __future__ import annotations

import secrets
import time
from typing import Any, TYPE_CHECKING

import jwt

if TYPE_CHECKING:
    from .idp import JwksClient

_ALGORITHM = "HS256"
_RS256_ALGORITHM = "RS256"
_IDP_KEY_ID = "provisioner-key-1"


# ---------------------------------------------------------------------------
# HS256 helpers (unchanged public API)
# ---------------------------------------------------------------------------


def create_access_token(
    payload: dict[str, Any],
    secret: str,
    expires_in_seconds: int = 900,  # 15 minutes
) -> str:
    """Create a signed HS256 JWT access token."""
    now = int(time.time())
    data = {
        **payload,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    return jwt.encode(data, secret, algorithm=_ALGORITHM)


def create_refresh_token(
    user_id: str,
    session_handle: str,
    secret: str,
    expires_in_seconds: int = 604800,  # 7 days
) -> str:
    """Create a signed HS256 JWT refresh token."""
    now = int(time.time())
    data = {
        "sub": user_id,
        "sessionHandle": session_handle,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    return jwt.encode(data, secret, algorithm=_ALGORITHM)


def create_temp_token(
    user_id: str,
    secret: str,
    purpose: str = "2fa",
    expires_in_seconds: int = 300,  # 5 minutes
) -> str:
    """Create a short-lived temporary token (used for 2FA flows)."""
    now = int(time.time())
    data = {
        "sub": user_id,
        "purpose": purpose,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    return jwt.encode(data, secret, algorithm=_ALGORITHM)


def decode_token(token: str, secret: str) -> dict[str, Any]:
    """Decode and verify an HS256 JWT.  Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, secret, algorithms=[_ALGORITHM])


# ---------------------------------------------------------------------------
# RS256 helpers (IdP mode)
# ---------------------------------------------------------------------------


def create_idp_access_token(
    payload: dict[str, Any],
    private_key_pem: str,
    expires_in_seconds: int = 2592000,  # 30 days
    issuer: str | None = None,
) -> str:
    """Create an RS256-signed JWT access token for IdP mode.

    Parameters
    ----------
    payload:
        JWT claims (e.g. from ``AuthUser.to_jwt_payload()``).
    private_key_pem:
        PEM-encoded RSA private key.
    expires_in_seconds:
        Token lifetime.  Default: 30 days.
    issuer:
        Optional ``iss`` claim to embed.
    """
    now = int(time.time())
    # Build claims without jwt-internal fields so we can add them cleanly
    base = {k: v for k, v in payload.items() if k not in ("iat", "exp", "iss")}
    if issuer:
        base["iss"] = issuer
    base["iat"] = now
    base["exp"] = now + expires_in_seconds
    return jwt.encode(
        base,
        private_key_pem,
        algorithm=_RS256_ALGORITHM,
        headers={"kid": _IDP_KEY_ID},
    )


def create_idp_refresh_token(
    payload: dict[str, Any],
    private_key_pem: str,
    expires_in_seconds: int = 7776000,  # 90 days
    issuer: str | None = None,
) -> str:
    """Create an RS256-signed JWT refresh token for IdP mode.

    Parameters
    ----------
    payload:
        JWT claims (typically a subset of the access token claims).
    private_key_pem:
        PEM-encoded RSA private key.
    expires_in_seconds:
        Token lifetime.  Default: 90 days.
    issuer:
        Optional ``iss`` claim to embed.
    """
    now = int(time.time())
    claims: dict[str, Any] = {**payload}
    if issuer:
        claims["iss"] = issuer
    return jwt.encode(
        {**claims, "iat": now, "exp": now + expires_in_seconds},
        private_key_pem,
        algorithm=_RS256_ALGORITHM,
        headers={"kid": _IDP_KEY_ID},
    )


async def decode_token_with_jwks(
    token: str,
    jwks_client: "JwksClient",
    expected_issuer: str | None = None,
) -> dict[str, Any]:
    """Verify an RS256 JWT against a remote JWKS endpoint.

    Steps:
    1. Decode without verifying to extract the ``kid`` header.
    2. Fetch the matching public key from the JWKS client (with caching).
    3. Verify the token signature and expiry.
    4. Optionally validate the ``iss`` claim.

    :param token: Raw JWT string.
    :param jwks_client: A :class:`~awesome_python_auth.idp.JwksClient` instance.
    :param expected_issuer: When set, tokens with a mismatched ``iss`` are rejected.
    :raises jwt.PyJWTError: On signature/expiry/issuer validation failure.
    :raises ValueError: When the ``kid`` header is missing or key not found.
    """
    from .idp import JwksService

    # Decode without verifying to extract kid
    unverified = jwt.decode(token, options={"verify_signature": False})
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise ValueError("Token is missing the 'kid' header — not an RS256 IdP token")

    jwk = await jwks_client.get_key(kid)
    if jwk is None:
        # Key not found — try once more after cache invalidation (key rotation)
        jwks_client.invalidate_cache()
        jwk = await jwks_client.get_key(kid)
        if jwk is None:
            raise ValueError(f"Unknown signing key: kid={kid!r}")

    public_key_pem = JwksService.jwk_to_public_key_pem(jwk)
    payload: dict[str, Any] = jwt.decode(
        token,
        public_key_pem,
        algorithms=[_RS256_ALGORITHM],
    )

    if expected_issuer and payload.get("iss") != expected_issuer:
        raise jwt.InvalidTokenError(
            f"Token issuer mismatch: expected {expected_issuer!r}, got {payload.get('iss')!r}"
        )

    return payload


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(32)


def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate a cryptographically random opaque token (for email links, etc.)."""
    return secrets.token_urlsafe(nbytes)
