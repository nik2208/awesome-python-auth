# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-05

### Added

- Initial release of `awesome-python-auth`.
- FastAPI authentication library fully compatible with [ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth) (Angular) and [awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter) (Flutter).
- Cookie-based auth (HttpOnly `access-token` + `refresh-token`) for Angular/web clients.
- Bearer token auth (`X-Auth-Strategy: bearer`) for Flutter native clients.
- CSRF protection via `CsrfMiddleware`.
- TOTP two-factor authentication.
- Magic-link and SMS/OTP login flows.
- Password reset, email verification, and email change flows.
- Session management (list & revoke sessions).
- Account linking for OAuth providers.
- RBAC support via `RolesPermissionsStore`.
- Multi-tenancy support via `TenantStore`.
- Token store with TTL (`TokenStore`).
- Linked accounts store (`LinkedAccountsStore`, `PendingLinkStore`).
- Admin router (`build_admin_router`).
- UI router (`build_ui_router`) serving bundled HTML/CSS/JS assets.
- Tools router (`build_tools_router`) with Server-Sent Events (`SseManager`).
- API key support (`ApiKeyService`).
- Webhook sender (`WebhookSender`).
- In-memory store implementations for all extension points.
- GitHub Actions CI (Python 3.11 & 3.12) and PyPI publish via OIDC Trusted Publishing.
