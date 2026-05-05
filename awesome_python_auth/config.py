"""Configuration dataclass for awesome-python-auth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from .models import StoredUser, UserStore


@dataclass
class AuthConfig:
    """Configuration for the awesome-python-auth backend.

    Parameters
    ----------
    api_prefix:
        URL prefix where the auth router will be mounted.
        Must match the ``apiPrefix`` setting in ``ng-awesome-node-auth`` /
        ``AuthOptions.apiPrefix`` in ``awesome-node-auth-flutter``.
        Default: ``"/api/auth"``.
    access_token_secret:
        Secret used to sign JWT access tokens.  Keep this private.
    access_token_expires_in:
        Access-token lifetime in seconds.  Default: 900 (15 minutes).
    refresh_token_expires_in:
        Refresh-token lifetime in seconds.  Default: 604800 (7 days).
    cookie_secure:
        Set the ``Secure`` flag on auth cookies.  Default: ``True``.
        Set to ``False`` only during local HTTP development.
    cookie_same_site:
        ``SameSite`` attribute for auth cookies.  Default: ``"lax"``.
    cookie_domain:
        Optional domain for auth cookies.  Leave ``None`` for same-origin.
    totp_issuer:
        Issuer name shown in authenticator apps.  Default: ``"awesome-python-auth"``.
    ui_config:
        Static UI configuration returned by ``GET /ui/config``.
    email:
        Optional email configuration dict.  Keys depend on the provider.
        Pass ``{"enabled": True}`` to signal that email sending is active.

    Hooks
    -----
    The following optional async callables allow you to plug in side-effects
    without subclassing the router:

    on_forgot_password(user, token):
        Called with the ``StoredUser`` and the raw reset token.  Send the email here.

    on_send_verification_email(user, token):
        Called with the ``StoredUser`` and the raw verification token.

    on_request_email_change(user, new_email, token):
        Called when a user requests an email address change.

    on_magic_link_send(email, temp_token, mode):
        Called when a magic-link send is requested.

    on_magic_link_verify(token, mode) -> user_id | None:
        Called with the raw magic-link token.  Return the user ID to log in, or
        ``None`` to reject.

    on_sms_send(email, temp_token, mode):
        Called when an SMS OTP send is requested.

    on_sms_verify(user_id, temp_token, code, mode) -> user_id | None:
        Called to verify an SMS OTP.  Return the user ID on success.

    on_link_request(email, provider, current_user):
        Called when account-linking is initiated.

    on_link_verify(token, provider, login_after_linking) -> user_id | None:
        Called to verify an account-linking token.
    """

    api_prefix: str = "/api/auth"
    access_token_secret: str = ""
    access_token_expires_in: int = 900
    refresh_token_expires_in: int = 604800
    cookie_secure: bool = True
    cookie_same_site: str = "lax"
    cookie_domain: str | None = None
    totp_issuer: str | None = None
    ui_config: dict[str, Any] | None = None
    email: dict[str, Any] | None = None

    # ── Hooks ────────────────────────────────────────────────────────────────
    on_forgot_password: Any = None
    on_send_verification_email: Any = None
    on_request_email_change: Any = None
    on_magic_link_send: Any = None
    on_magic_link_verify: Any = None
    on_sms_send: Any = None
    on_sms_verify: Any = None
    on_link_request: Any = None
    on_link_verify: Any = None


# Import here to avoid circular dependency
from .router import AuthConfigurator  # noqa: E402

__all__ = ["AuthConfig", "AuthConfigurator"]
