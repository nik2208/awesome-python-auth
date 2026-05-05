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
from .mailer import MailerConfig, MailerService, TemplateStore
from .api_keys import ApiKey, ApiKeyService, ApiKeyStore, InMemoryApiKeyStore
from .webhooks import (
    WebhookConfig,
    WebhookStore,
    InMemoryWebhookStore,
    WebhookSender,
    OutgoingWebhookEvent,
)
from .sse import SseManager, StreamEvent
from .tools import AuthTools, TelemetryStore, TelemetryEvent, InMemoryTelemetryStore
from .tools_router import build_tools_router
from .ui_router import build_ui_router

__all__ = [
    # Core
    "AuthConfig",
    "AuthConfigurator",
    "AuthUser",
    "SessionInfo",
    "UserStore",
    "SettingsStore",
    "CsrfMiddleware",
    # Dependencies
    "get_current_user",
    "require_auth",
    "require_roles",
    # Exceptions
    "AuthError",
    "NotAuthenticatedError",
    "ForbiddenError",
    # Mailer
    "MailerConfig",
    "MailerService",
    "TemplateStore",
    # API keys
    "ApiKey",
    "ApiKeyService",
    "ApiKeyStore",
    "InMemoryApiKeyStore",
    # Webhooks
    "WebhookConfig",
    "WebhookStore",
    "InMemoryWebhookStore",
    "WebhookSender",
    "OutgoingWebhookEvent",
    # SSE
    "SseManager",
    "StreamEvent",
    # Tools (telemetry + SSE + webhooks)
    "AuthTools",
    "TelemetryStore",
    "TelemetryEvent",
    "InMemoryTelemetryStore",
    "build_tools_router",
    # UI
    "build_ui_router",
]
