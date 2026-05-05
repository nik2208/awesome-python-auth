"""
awesome-python-auth
===================
FastAPI authentication library compatible with:
- ng-awesome-node-auth (Angular)
- awesome-node-auth-flutter (Dart/Flutter)

Usage::

    from awesome_python_auth import AuthConfigurator, AuthConfig, UserStore

    config = AuthConfig(
        api_prefix="/api/auth",
        access_token_secret="your-secret",
    )
    configurator = AuthConfigurator(config, user_store)
    app.include_router(configurator.router())
"""

from .config import AuthConfig, AuthConfigurator
from .dependencies import get_current_user, require_auth, require_roles
from .models import AuthUser, SessionInfo, UserStore, SettingsStore
from .middleware import CsrfMiddleware
from .exceptions import AuthError, NotAuthenticatedError, ForbiddenError

__all__ = [
    "AuthConfig",
    "AuthConfigurator",
    "AuthUser",
    "SessionInfo",
    "UserStore",
    "SettingsStore",
    "CsrfMiddleware",
    "get_current_user",
    "require_auth",
    "require_roles",
    "AuthError",
    "NotAuthenticatedError",
    "ForbiddenError",
]
