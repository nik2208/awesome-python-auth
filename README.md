# awesome-python-auth

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**FastAPI authentication library** that replicates the [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) Node.js backend in Python.

Fully compatible with:
- **[ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth)** — Angular client library
- **[awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter)** — Flutter/Dart client library

Supports **both authentication strategies** used by those clients:
| Platform | Strategy | Token |
|---|---|---|
| Angular / Web | Cookie (HttpOnly) + CSRF | `access-token` cookie + `X-CSRF-Token` header |
| Flutter Native (iOS/Android/Desktop) | Bearer token | `Authorization: Bearer <token>` + `X-Auth-Strategy: bearer` |

---

## Installation

```bash
pip install awesome-python-auth
```

---

## Quick Start

```python
from fastapi import FastAPI
from awesome_python_auth import AuthConfig, AuthConfigurator, CsrfMiddleware
from awesome_python_auth.models import InMemoryUserStore

app = FastAPI()

# 1. Configure
user_store = InMemoryUserStore()
config = AuthConfig(
    api_prefix="/api/auth",
    access_token_secret="your-secret-here",  # must match the Angular/Flutter client config
)

# 2. Add CSRF middleware (required for Angular web clients)
app.add_middleware(CsrfMiddleware, api_prefix="/api/auth")

# 3. Mount the auth router
configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())
```

Point Angular/Flutter clients at `http://your-server/api/auth` — no other changes needed.

---

## AuthConfig

```python
from awesome_python_auth import AuthConfig

config = AuthConfig(
    api_prefix="/api/auth",          # Must match client's apiPrefix
    access_token_secret="secret",   # JWT signing secret (keep private!)
    access_token_expires_in=900,    # Access token lifetime (seconds, default 15 min)
    refresh_token_expires_in=604800,# Refresh token lifetime (seconds, default 7 days)
    cookie_secure=True,             # Set Secure flag on cookies (False for local HTTP)
    cookie_same_site="lax",         # SameSite cookie attribute
    cookie_domain=None,             # Cookie domain (None = same origin)
    totp_issuer="My App",           # Shown in authenticator apps
    ui_config={"theme": "dark"},    # Static UI config returned by GET /ui/config
)
```

---

## Custom User Store

Implement `UserStore` to connect to your database:

```python
from awesome_python_auth import UserStore
from awesome_python_auth.models import StoredUser

class MySQLUserStore(UserStore):
    async def get_by_email(self, email: str) -> StoredUser | None:
        row = await db.fetchone("SELECT * FROM users WHERE email = ?", [email])
        return StoredUser(**row) if row else None

    async def get_by_id(self, user_id: str) -> StoredUser | None:
        row = await db.fetchone("SELECT * FROM users WHERE id = ?", [user_id])
        return StoredUser(**row) if row else None

    async def create(self, user: StoredUser) -> StoredUser:
        await db.execute("INSERT INTO users ...", [...])
        return user

    async def update(self, user: StoredUser) -> StoredUser:
        await db.execute("UPDATE users SET ...", [...])
        return user

    async def delete(self, user_id: str) -> None:
        await db.execute("DELETE FROM users WHERE id = ?", [user_id])
```

---

## Protecting Your Routes

```python
from fastapi import Depends, FastAPI
from awesome_python_auth import get_current_user, require_auth, require_roles
from awesome_python_auth.models import AuthUser

app = FastAPI()

# Optional auth (returns None when unauthenticated)
@app.get("/public")
async def public(user: AuthUser | None = Depends(get_current_user)):
    return {"user": user}

# Required auth (raises 401 when unauthenticated)
@app.get("/profile")
async def profile(user: AuthUser = Depends(require_auth)):
    return user.to_api_dict()

# Role-based access
@app.delete("/admin-only")
async def admin_only(user: AuthUser = Depends(require_roles(["admin"]))):
    return {"ok": True}
```

---

## API Endpoints

All endpoints are mounted under `api_prefix` (default: `/api/auth`).

### Session
| Method | Path | Description |
|---|---|---|
| `GET` | `/me` | Return the current authenticated user |
| `POST` | `/login` | Login with email + password |
| `POST` | `/register` | Create a new account |
| `POST` | `/logout` | Logout and clear cookies |
| `POST` | `/refresh` | Refresh the access token |
| `PATCH` | `/profile` | Update first/last name |
| `DELETE` | `/account` | Delete the current account |

### Password
| Method | Path | Description |
|---|---|---|
| `POST` | `/forgot-password` | Initiate password recovery |
| `POST` | `/reset-password` | Reset password with token |
| `POST` | `/change-password` | Change password (authenticated) |
| `POST` | `/send-verification-email` | Resend email verification |
| `GET` | `/verify-email?token=` | Verify email address |
| `POST` | `/change-email/request` | Request email address change |
| `POST` | `/change-email/confirm` | Confirm email address change |

### Two-Factor Authentication (TOTP)
| Method | Path | Description |
|---|---|---|
| `POST` | `/2fa/setup` | Begin TOTP setup (returns QR code + secret) |
| `POST` | `/2fa/verify-setup` | Confirm TOTP setup |
| `POST` | `/2fa/verify` | Verify TOTP code during login |
| `POST` | `/2fa/disable` | Disable TOTP |

### Magic Link
| Method | Path | Description |
|---|---|---|
| `POST` | `/magic-link/send` | Send a magic-link email |
| `POST` | `/magic-link/verify` | Verify magic-link token |

### SMS / OTP
| Method | Path | Description |
|---|---|---|
| `POST` | `/sms/send` | Send an SMS OTP |
| `POST` | `/sms/verify` | Verify SMS OTP |
| `POST` | `/add-phone` | Add phone number to account |

### Sessions
| Method | Path | Description |
|---|---|---|
| `GET` | `/sessions` | List all active sessions |
| `DELETE` | `/sessions/{handle}` | Revoke a session |

### Account Linking
| Method | Path | Description |
|---|---|---|
| `POST` | `/link-request` | Initiate account linking |
| `POST` | `/link-verify` | Verify linking token |
| `GET` | `/linked-accounts` | List linked OAuth providers |
| `DELETE` | `/linked-accounts/{provider}/{id}` | Unlink a provider |

### Utilities
| Method | Path | Description |
|---|---|---|
| `GET` | `/ui/config` | UI configuration (theme, branding) |
| `GET` | `/tools/stream` | Server-Sent Events stream |

---

## Hooks / Callbacks

Plug in side-effects (email sending, SMS, OAuth) without subclassing:

```python
from awesome_python_auth.models import StoredUser

async def send_password_reset_email(user: StoredUser, token: str) -> None:
    link = f"https://myapp.com/reset-password?token={token}"
    await email_client.send(user.email, "Reset your password", link)

async def verify_magic_link(token: str, mode: str) -> str | None:
    """Return user_id on success, None on failure."""
    return await magic_link_store.verify(token)

config = AuthConfig(
    access_token_secret="secret",
    on_forgot_password=send_password_reset_email,
    on_send_verification_email=send_verification_email,
    on_magic_link_send=send_magic_link_email,
    on_magic_link_verify=verify_magic_link,
    on_sms_send=send_sms_otp,
    on_sms_verify=verify_sms_otp,
    on_link_request=handle_link_request,
    on_link_verify=handle_link_verify,
)
```

---

## Custom `on_register` hook

```python
async def my_on_register(user: StoredUser) -> StoredUser:
    user.role = "user"
    await user_store.create(user)
    await send_welcome_email(user.email)
    return user

app.include_router(configurator.router(on_register=my_on_register))
```

---

## CSRF Middleware

The `CsrfMiddleware` is required when Angular web clients are used. It:

1. Sets a `csrf-token` cookie (readable by JavaScript) on every response.
2. Validates the `X-CSRF-Token` request header for mutating requests (POST, PATCH, DELETE) to `api_prefix`.
3. Automatically skips validation for auth-flow endpoints (login, register, etc.) and for Bearer-token requests from native clients.

```python
app.add_middleware(
    CsrfMiddleware,
    api_prefix="/api/auth",
    cookie_secure=True,     # Set False for local HTTP development
    cookie_same_site="lax",
)
```

---

## Complete Example

```python
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from awesome_python_auth import (
    AuthConfig, AuthConfigurator, CsrfMiddleware, require_auth,
)
from awesome_python_auth.models import AuthUser, InMemoryUserStore

user_store = InMemoryUserStore()

config = AuthConfig(
    api_prefix="/api/auth",
    access_token_secret=os.environ["JWT_SECRET"],
    cookie_secure=False,  # True in production
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token", "X-Auth-Strategy"],
)

app.add_middleware(CsrfMiddleware, api_prefix="/api/auth", cookie_secure=False)

configurator = AuthConfigurator(config, user_store)
app.include_router(configurator.router())

@app.get("/api/todos")
async def todos(user: AuthUser = Depends(require_auth)):
    return {"todos": [], "user": user.email}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
```

---

## Angular Integration (`ng-awesome-node-auth`)

```typescript
// app.config.ts
import { provideAuth, provideAuthUi } from 'ng-awesome-node-auth';

export const appConfig: ApplicationConfig = {
  providers: [
    provideAuth({ apiPrefix: '/api/auth' }),
    provideAuthUi(),
  ]
};
```

No other changes needed — the Angular library sends cookies + CSRF headers automatically.

---

## Flutter Integration (`awesome-node-auth-flutter`)

```dart
// Native (iOS/Android/Desktop)
final auth = AuthClient(AuthOptions(
  apiPrefix: 'http://your-server/api/auth',
));
await auth.checkSession();

// Login
final result = await auth.login('user@example.com', 'password');
```

The Flutter library uses `X-Auth-Strategy: bearer` on native platforms — the Python library detects this and returns tokens in the response body instead of setting cookies.

---

## License

MIT