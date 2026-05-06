"""FastAPI dependency helpers for awesome-python-auth.

Usage::

    from awesome_python_auth import get_current_user, require_auth, require_roles
    from fastapi import Depends

    @router.get("/profile")
    async def profile(user: AuthUser = Depends(require_auth)):
        return user.to_api_dict()

    @router.delete("/admin-only")
    async def admin(user: AuthUser = Depends(require_roles(["admin"]))):
        ...
"""

from __future__ import annotations

from typing import Annotated, Any

import jwt
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .exceptions import forbidden, not_authenticated
from .models import AuthUser

_bearer_scheme = HTTPBearer(auto_error=False)

# Name of the access-token cookie set by the auth server.
_ACCESS_TOKEN_COOKIE = "access-token"

# Request-state key where the resolved AuthUser is stored by middleware.
_REQUEST_STATE_KEY = "awesome_auth_user"

# Thread-local registry filled by AuthConfigurator so the dependencies can
# read the JWT secret without being passed config explicitly.
_registry: dict[str, Any] = {}


def _register_secret(secret: str) -> None:
    """Called by AuthConfigurator to register the JWT secret globally."""
    _registry["access_token_secret"] = secret


def _register_resource_server(config: Any) -> None:
    """Register a ResourceServerConfig so JWKS-based verification is used."""
    from .idp import JwksClient
    _registry["resource_server"] = config
    _registry["jwks_client"] = JwksClient(
        config.jwks_url,
        cache_ttl=float(config.jwks_cache_ttl),
        fetch_timeout=float(config.jwks_fetch_timeout),
    )


def _get_secret() -> str:
    secret = _registry.get("access_token_secret")
    if not secret:
        raise RuntimeError(
            "awesome-python-auth: JWT secret not registered.  "
            "Make sure to call AuthConfigurator(config, store) before using "
            "the dependency functions."
        )
    return secret


# ---------------------------------------------------------------------------
# Core token extraction
# ---------------------------------------------------------------------------


def _extract_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    """Return the raw JWT from either the Authorization header or the cookie."""
    # 1. Bearer header (native clients — Flutter / mobile)
    if credentials is not None:
        return credentials.credentials
    # 2. HttpOnly access-token cookie (web clients — Angular)
    return request.cookies.get(_ACCESS_TOKEN_COOKIE)


def _decode_hs256(token: str, secret: str) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def _decode_any(token: str) -> dict:
    """Decode a JWT using HS256 or RS256/JWKS depending on configuration."""
    rs_cfg = _registry.get("resource_server")
    jwks_client = _registry.get("jwks_client")

    if rs_cfg is not None and rs_cfg.enabled and jwks_client is not None:
        # Resource Server mode — verify against remote JWKS
        from .jwt_utils import decode_token_with_jwks
        try:
            return await decode_token_with_jwks(
                token,
                jwks_client,
                expected_issuer=getattr(rs_cfg, "issuer", None),
            )
        except (ValueError, jwt.PyJWTError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc) or "Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Default — HS256
    secret = _get_secret()
    return _decode_hs256(token, secret)


# ---------------------------------------------------------------------------
# Public dependency functions
# ---------------------------------------------------------------------------


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)] = None,
) -> AuthUser | None:
    """Return the authenticated user or ``None`` when unauthenticated.

    Checks the ``Authorization: Bearer`` header first, then falls back to the
    ``access-token`` HttpOnly cookie (set by the auth server for web clients).

    Supports both HS256 (default) and RS256 (Resource Server mode when
    ``AuthConfig.resource_server`` is configured).

    Register this with ``Depends(get_current_user)`` on routes where you want
    optional authentication.
    """
    token = _extract_token(request, credentials)
    if not token:
        return None
    payload = await _decode_any(token)
    return AuthUser.from_jwt_payload(payload)


async def require_auth(
    user: Annotated[AuthUser | None, Depends(get_current_user)] = None,
) -> AuthUser:
    """Return the authenticated user or raise 401.

    Use with ``Depends(require_auth)`` on protected routes.
    """
    if user is None:
        raise not_authenticated()
    return user


def require_roles(roles: list[str]):
    """Return a FastAPI dependency that enforces role membership.

    Usage::

        @router.get("/admin")
        async def admin_only(user = Depends(require_roles(["admin"]))):
            ...
    """

    async def _dep(
        user: Annotated[AuthUser, Depends(require_auth)],
    ) -> AuthUser:
        user_roles = set(user.roles or [])
        if user.role:
            user_roles.add(user.role)
        if not user_roles.intersection(roles):
            raise forbidden(f"Required role(s): {', '.join(roles)}")
        return user

    return _dep


def require_admin():
    """Return a FastAPI dependency that enforces admin privileges."""

    async def _dep(
        user: Annotated[AuthUser, Depends(require_auth)],
    ) -> AuthUser:
        if not user.is_admin:
            raise forbidden("Admin privileges required")
        return user

    return _dep
