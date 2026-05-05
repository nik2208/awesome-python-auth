"""JWT creation and verification utilities for awesome-python-auth."""

from __future__ import annotations

import secrets
import time
from typing import Any

import jwt

_ALGORITHM = "HS256"


def create_access_token(
    payload: dict[str, Any],
    secret: str,
    expires_in_seconds: int = 900,  # 15 minutes
) -> str:
    """Create a signed JWT access token."""
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
    """Create a signed JWT refresh token."""
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
    """Decode and verify a JWT.  Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, secret, algorithms=[_ALGORITHM])


def generate_csrf_token() -> str:
    """Generate a cryptographically random CSRF token."""
    return secrets.token_urlsafe(32)


def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate a cryptographically random opaque token (for email links, etc.)."""
    return secrets.token_urlsafe(nbytes)
