"""Pydantic models and abstract store interfaces for awesome-python-auth."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, EmailStr, Field


# ---------------------------------------------------------------------------
# Auth-related data models
# ---------------------------------------------------------------------------


class AuthUser(BaseModel):
    """Represents the authenticated user.  Mirrors AuthUser in ng/flutter libs."""

    sub: str = Field(description="Stable unique user identifier (JWT subject).")
    email: str
    is_email_verified: bool = False
    id: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    name: str | None = None
    phone_number: str | None = None
    role: str | None = None
    login_provider: str | None = None
    is_totp_enabled: bool | None = None
    has_password: bool | None = None
    last_login: datetime | None = None
    metadata: dict[str, Any] | None = None
    roles: list[str] | None = None
    permissions: list[str] | None = None
    is_admin: bool | None = None
    tenant_id: str | None = None

    def to_jwt_payload(self) -> dict[str, Any]:
        """Return a dict suitable for embedding in a JWT access-token payload."""
        payload: dict[str, Any] = {
            "sub": self.sub,
            "email": self.email,
            "isEmailVerified": self.is_email_verified,
        }
        if self.id is not None:
            payload["id"] = self.id
        if self.first_name is not None:
            payload["firstName"] = self.first_name
        if self.last_name is not None:
            payload["lastName"] = self.last_name
        if self.name is not None:
            payload["name"] = self.name
        if self.phone_number is not None:
            payload["phoneNumber"] = self.phone_number
        if self.role is not None:
            payload["role"] = self.role
        if self.login_provider is not None:
            payload["loginProvider"] = self.login_provider
        if self.is_totp_enabled is not None:
            payload["isTotpEnabled"] = self.is_totp_enabled
        if self.has_password is not None:
            payload["hasPassword"] = self.has_password
        if self.last_login is not None:
            payload["lastLogin"] = self.last_login.isoformat()
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        if self.roles is not None:
            payload["roles"] = self.roles
        if self.permissions is not None:
            payload["permissions"] = self.permissions
        if self.is_admin is not None:
            payload["isAdmin"] = self.is_admin
        if self.tenant_id is not None:
            payload["tenantId"] = self.tenant_id
        return payload

    @classmethod
    def from_jwt_payload(cls, payload: dict[str, Any]) -> "AuthUser":
        """Build an AuthUser from a JWT payload dict (camelCase keys)."""
        last_login: datetime | None = None
        if payload.get("lastLogin"):
            try:
                last_login = datetime.fromisoformat(payload["lastLogin"])
            except ValueError:
                pass
        return cls(
            sub=payload["sub"],
            email=payload["email"],
            is_email_verified=payload.get("isEmailVerified", False),
            id=payload.get("id"),
            first_name=payload.get("firstName"),
            last_name=payload.get("lastName"),
            name=payload.get("name"),
            phone_number=payload.get("phoneNumber"),
            role=payload.get("role"),
            login_provider=payload.get("loginProvider"),
            is_totp_enabled=payload.get("isTotpEnabled"),
            has_password=payload.get("hasPassword"),
            last_login=last_login,
            metadata=payload.get("metadata"),
            roles=payload.get("roles"),
            permissions=payload.get("permissions"),
            is_admin=payload.get("isAdmin"),
            tenant_id=payload.get("tenantId"),
        )

    def to_api_dict(self) -> dict[str, Any]:
        """Serialise to the camelCase JSON shape expected by Angular/Flutter clients."""
        data: dict[str, Any] = {
            "sub": self.sub,
            "email": self.email,
            "isEmailVerified": self.is_email_verified,
        }
        if self.id is not None:
            data["id"] = self.id
        if self.first_name is not None:
            data["firstName"] = self.first_name
        if self.last_name is not None:
            data["lastName"] = self.last_name
        if self.name is not None:
            data["name"] = self.name
        if self.phone_number is not None:
            data["phoneNumber"] = self.phone_number
        if self.role is not None:
            data["role"] = self.role
        if self.login_provider is not None:
            data["loginProvider"] = self.login_provider
        if self.is_totp_enabled is not None:
            data["isTotpEnabled"] = self.is_totp_enabled
        if self.has_password is not None:
            data["hasPassword"] = self.has_password
        if self.last_login is not None:
            data["lastLogin"] = self.last_login.isoformat()
        if self.metadata is not None:
            data["metadata"] = self.metadata
        if self.roles is not None:
            data["roles"] = self.roles
        if self.permissions is not None:
            data["permissions"] = self.permissions
        if self.is_admin is not None:
            data["isAdmin"] = self.is_admin
        if self.tenant_id is not None:
            data["tenantId"] = self.tenant_id
        return data


class SessionInfo(BaseModel):
    """Active session entry returned by the /sessions endpoint."""

    handle: str = Field(description="Unique session identifier.")
    user_id: str
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime | None = None
    last_active_at: datetime | None = None
    is_current: bool = False

    def to_api_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "sessionHandle": self.handle,
            "userId": self.user_id,
            "isCurrent": self.is_current,
        }
        if self.user_agent is not None:
            data["userAgent"] = self.user_agent
        if self.ip_address is not None:
            data["ipAddress"] = self.ip_address
        if self.created_at is not None:
            data["createdAt"] = self.created_at.isoformat()
        if self.last_active_at is not None:
            data["lastActiveAt"] = self.last_active_at.isoformat()
        return data


class TotpSetupData(BaseModel):
    """Data returned when initialising TOTP 2FA."""

    secret: str
    qr_code: str  # data URL (image/png;base64)


# ---------------------------------------------------------------------------
# Request bodies (matching the camelCase field names sent by Angular/Flutter)
# ---------------------------------------------------------------------------


class RegisterBody(BaseModel):
    email: str
    password: str
    first_name: str = Field(alias="firstName", default="")
    last_name: str = Field(alias="lastName", default="")

    model_config = {"populate_by_name": True}


class LoginBody(BaseModel):
    email: str
    password: str


class ForgotPasswordBody(BaseModel):
    email: str


class ResetPasswordBody(BaseModel):
    password: str
    token: str


class ChangePasswordBody(BaseModel):
    current_password: str = Field(alias="currentPassword")
    new_password: str = Field(alias="newPassword")

    model_config = {"populate_by_name": True}


class UpdateProfileBody(BaseModel):
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")

    model_config = {"populate_by_name": True}


class MagicLinkSendBody(BaseModel):
    email: str | None = None
    temp_token: str | None = Field(default=None, alias="tempToken")
    mode: str = "login"

    model_config = {"populate_by_name": True}


class MagicLinkVerifyBody(BaseModel):
    token: str
    mode: str = "login"


class SmsSendBody(BaseModel):
    email: str | None = None
    temp_token: str | None = Field(default=None, alias="tempToken")
    mode: str = "login"

    model_config = {"populate_by_name": True}


class SmsVerifyBody(BaseModel):
    user_id: str | None = Field(default=None, alias="userId")
    temp_token: str | None = Field(default=None, alias="tempToken")
    code: str
    mode: str = "login"

    model_config = {"populate_by_name": True}


class AddPhoneBody(BaseModel):
    phone_number: str = Field(alias="phoneNumber")

    model_config = {"populate_by_name": True}


class Verify2faSetupBody(BaseModel):
    token: str
    secret: str


class Validate2faBody(BaseModel):
    temp_token: str = Field(alias="tempToken")
    totp_code: str = Field(alias="totpCode")

    model_config = {"populate_by_name": True}


class ValidateSmsBody(BaseModel):
    temp_token: str = Field(alias="tempToken")
    code: str

    model_config = {"populate_by_name": True}


class RequestEmailChangeBody(BaseModel):
    new_email: str = Field(alias="newEmail")

    model_config = {"populate_by_name": True}


class ConfirmEmailChangeBody(BaseModel):
    token: str


class LinkRequestBody(BaseModel):
    email: str
    provider: str


class LinkVerifyBody(BaseModel):
    token: str
    provider: str | None = None
    login_after_linking: bool = Field(default=False, alias="loginAfterLinking")

    model_config = {"populate_by_name": True}


class RefreshBody(BaseModel):
    refresh_token: str | None = Field(default=None, alias="refreshToken")

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Abstract store interfaces
# ---------------------------------------------------------------------------


class StoredUser(BaseModel):
    """Data persisted for each registered user.  Extend as needed."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    hashed_password: str | None = None
    first_name: str = ""
    last_name: str = ""
    name: str | None = None
    phone_number: str | None = None
    role: str | None = None
    is_email_verified: bool = False
    is_totp_enabled: bool = False
    totp_secret: str | None = None
    login_provider: str | None = None
    last_login: datetime | None = None
    metadata: dict[str, Any] | None = None
    roles: list[str] | None = None
    permissions: list[str] | None = None
    is_admin: bool | None = None
    tenant_id: str | None = None
    # Email-change request in progress
    pending_email: str | None = None
    pending_email_token: str | None = None
    # Verification token
    verification_token: str | None = None
    # Password-reset token
    reset_password_token: str | None = None

    def to_auth_user(self) -> AuthUser:
        return AuthUser(
            sub=self.id,
            email=self.email,
            is_email_verified=self.is_email_verified,
            id=self.id,
            first_name=self.first_name or None,
            last_name=self.last_name or None,
            name=self.name,
            phone_number=self.phone_number,
            role=self.role,
            login_provider=self.login_provider,
            is_totp_enabled=self.is_totp_enabled,
            has_password=self.hashed_password is not None,
            last_login=self.last_login,
            metadata=self.metadata,
            roles=self.roles,
            permissions=self.permissions,
            is_admin=self.is_admin,
            tenant_id=self.tenant_id,
        )


class StoredSession(BaseModel):
    """Data persisted for an active session (refresh-token entry)."""

    handle: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    refresh_token_hash: str
    user_agent: str | None = None
    ip_address: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_active_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserStore(ABC):
    """Abstract user storage interface.

    Implement this class and pass an instance to :class:`AuthConfigurator`.

    All methods are async so they can be backed by any I/O (database, HTTP, etc.).
    """

    @abstractmethod
    async def get_by_email(self, email: str) -> StoredUser | None: ...

    @abstractmethod
    async def get_by_id(self, user_id: str) -> StoredUser | None: ...

    @abstractmethod
    async def create(self, user: StoredUser) -> StoredUser: ...

    @abstractmethod
    async def update(self, user: StoredUser) -> StoredUser: ...

    @abstractmethod
    async def delete(self, user_id: str) -> None: ...

    # Session management (optional — override for persistent sessions)
    async def create_session(self, session: StoredSession) -> StoredSession:
        return session

    async def get_sessions_for_user(self, user_id: str) -> list[StoredSession]:
        return []

    async def get_session_by_handle(self, handle: str) -> StoredSession | None:
        return None

    async def update_session(self, session: StoredSession) -> None:
        pass

    async def delete_session(self, handle: str) -> None:
        pass

    async def delete_sessions_for_user(self, user_id: str) -> None:
        pass

    async def list_all_users(self, offset: int = 0, limit: int = 50) -> list[StoredUser]:
        """Return a paginated list of all users.  Override for efficient DB queries."""
        return []

    async def count_users(self) -> int:
        """Return the total number of registered users.  Override for efficient DB queries."""
        return 0

    async def list_all_sessions(self, offset: int = 0, limit: int = 50) -> list[StoredSession]:
        """Return a paginated list of all active sessions.  Override for efficient DB queries."""
        return []

    async def count_active_sessions(self) -> int:
        """Return the total number of active sessions.  Override for efficient DB queries."""
        return 0

    # Token-based lookups (optional — override for efficient indexed queries)
    async def find_by_reset_token(self, token_hash: str) -> StoredUser | None:
        return None

    async def find_by_verification_token(self, token_hash: str) -> StoredUser | None:
        return None

    async def find_by_pending_email_token(self, token_hash: str) -> StoredUser | None:
        return None


class SettingsStore(ABC):
    """Abstract settings storage for UI customisation.

    Implement to persist UI settings across restarts.
    """

    @abstractmethod
    async def get(self, key: str) -> Any: ...

    @abstractmethod
    async def set(self, key: str, value: Any) -> None: ...


class InMemoryUserStore(UserStore):
    """Simple in-memory user store — suitable for testing and examples."""

    def __init__(self) -> None:
        self._users: dict[str, StoredUser] = {}
        self._sessions: dict[str, StoredSession] = {}

    async def get_by_email(self, email: str) -> StoredUser | None:
        email_lower = email.lower()
        return next(
            (u for u in self._users.values() if u.email.lower() == email_lower),
            None,
        )

    async def get_by_id(self, user_id: str) -> StoredUser | None:
        return self._users.get(user_id)

    async def create(self, user: StoredUser) -> StoredUser:
        self._users[user.id] = user
        return user

    async def update(self, user: StoredUser) -> StoredUser:
        self._users[user.id] = user
        return user

    async def delete(self, user_id: str) -> None:
        self._users.pop(user_id, None)

    async def create_session(self, session: StoredSession) -> StoredSession:
        self._sessions[session.handle] = session
        return session

    async def get_sessions_for_user(self, user_id: str) -> list[StoredSession]:
        return [s for s in self._sessions.values() if s.user_id == user_id]

    async def get_session_by_handle(self, handle: str) -> StoredSession | None:
        return self._sessions.get(handle)

    async def update_session(self, session: StoredSession) -> None:
        self._sessions[session.handle] = session

    async def delete_session(self, handle: str) -> None:
        self._sessions.pop(handle, None)

    async def delete_sessions_for_user(self, user_id: str) -> None:
        self._sessions = {
            h: s for h, s in self._sessions.items() if s.user_id != user_id
        }

    async def list_all_users(self, offset: int = 0, limit: int = 50) -> list[StoredUser]:
        all_users = list(self._users.values())
        return all_users[offset : offset + limit]

    async def count_users(self) -> int:
        return len(self._users)

    async def list_all_sessions(self, offset: int = 0, limit: int = 50) -> list[StoredSession]:
        all_sessions = list(self._sessions.values())
        return all_sessions[offset : offset + limit]

    async def count_active_sessions(self) -> int:
        return len(self._sessions)

    async def find_by_reset_token(self, token_hash: str) -> StoredUser | None:
        return next(
            (u for u in self._users.values() if u.reset_password_token == token_hash),
            None,
        )

    async def find_by_verification_token(self, token_hash: str) -> StoredUser | None:
        return next(
            (u for u in self._users.values() if u.verification_token == token_hash),
            None,
        )

    async def find_by_pending_email_token(self, token_hash: str) -> StoredUser | None:
        return next(
            (u for u in self._users.values() if u.pending_email_token == token_hash),
            None,
        )


class InMemorySettingsStore(SettingsStore):
    """Simple in-memory settings store — suitable for testing and examples."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    async def get(self, key: str) -> Any:
        return self._data.get(key)

    async def set(self, key: str, value: Any) -> None:
        self._data[key] = value
