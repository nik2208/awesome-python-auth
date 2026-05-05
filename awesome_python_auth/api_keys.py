"""API key management for awesome-python-auth.

Mirrors the ``ApiKeyService`` and ``IApiKeyStore`` from awesome-node-auth.

Raw keys are formatted as ``ak_<48 hex chars>`` (~196 bits of entropy).
Only the bcrypt hash and an 11-char prefix (``ak_`` + 8 hex) are persisted.

Usage::

    from awesome_python_auth.api_keys import ApiKeyService, InMemoryApiKeyStore
    from awesome_python_auth.models import ApiKey

    store = InMemoryApiKeyStore()
    svc = ApiKeyService()

    # Create a key (raw key is shown once)
    result = await svc.create_key(store, name="my-service", scopes=["tools:read"])
    print(result.raw_key)  # ak_...  → store this safely

    # Verify on incoming request
    ok = await svc.authenticate(store, raw_key)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import bcrypt
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class ApiKey(BaseModel):
    """Persisted API key record.  Never stores the raw key — only the bcrypt hash."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    key_hash: str  # bcrypt hash of the raw key
    key_prefix: str  # first 11 chars of the raw key (for lookup)
    service_id: str | None = None
    scopes: list[str] = Field(default_factory=list)
    allowed_ips: list[str] | None = None
    is_active: bool = True
    expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: datetime | None = None

    def to_api_dict(self) -> dict[str, Any]:
        """Return a safe dict (no hash) for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "keyPrefix": self.key_prefix,
            "serviceId": self.service_id,
            "scopes": self.scopes,
            "allowedIps": self.allowed_ips,
            "isActive": self.is_active,
            "expiresAt": self.expires_at.isoformat() if self.expires_at else None,
            "createdAt": self.created_at.isoformat(),
            "lastUsedAt": self.last_used_at.isoformat() if self.last_used_at else None,
        }


# ---------------------------------------------------------------------------
# Store interface + in-memory implementation
# ---------------------------------------------------------------------------


class ApiKeyStore(ABC):
    """Abstract store for API key records.

    Implement this interface to persist keys in any database.
    """

    @abstractmethod
    async def save(self, key: ApiKey) -> ApiKey: ...

    @abstractmethod
    async def find_by_prefix(self, prefix: str) -> list[ApiKey]: ...

    @abstractmethod
    async def find_by_id(self, key_id: str) -> ApiKey | None: ...

    @abstractmethod
    async def list_all(self, service_id: str | None = None) -> list[ApiKey]: ...

    @abstractmethod
    async def update(self, key: ApiKey) -> ApiKey: ...

    @abstractmethod
    async def delete(self, key_id: str) -> None: ...


class InMemoryApiKeyStore(ApiKeyStore):
    """Simple in-memory API key store — for testing and examples."""

    def __init__(self) -> None:
        self._keys: dict[str, ApiKey] = {}

    async def save(self, key: ApiKey) -> ApiKey:
        self._keys[key.id] = key
        return key

    async def find_by_prefix(self, prefix: str) -> list[ApiKey]:
        return [k for k in self._keys.values() if k.key_prefix == prefix]

    async def find_by_id(self, key_id: str) -> ApiKey | None:
        return self._keys.get(key_id)

    async def list_all(self, service_id: str | None = None) -> list[ApiKey]:
        keys = list(self._keys.values())
        if service_id is not None:
            keys = [k for k in keys if k.service_id == service_id]
        return keys

    async def update(self, key: ApiKey) -> ApiKey:
        self._keys[key.id] = key
        return key

    async def delete(self, key_id: str) -> None:
        self._keys.pop(key_id, None)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CreatedApiKey:
    """Result of :meth:`ApiKeyService.create_key` — contains the raw key (show once)."""

    def __init__(self, raw_key: str, record: ApiKey) -> None:
        self.raw_key = raw_key
        self.record = record


class ApiKeyService:
    """Generate, verify, and manage API keys.

    Raw keys are formatted ``ak_<48 hex chars>`` (196 bits of entropy).
    Only the bcrypt hash and a short prefix are persisted.
    """

    def __init__(self, salt_rounds: int = 10) -> None:
        self._salt_rounds = salt_rounds

    def _generate_raw_key(self) -> str:
        return f"ak_{secrets.token_hex(24)}"  # 24 bytes = 48 hex chars

    def extract_prefix(self, raw_key: str) -> str:
        """Return the 11-char prefix used as a lookup index (``ak_`` + 8 chars)."""
        return raw_key[:11]

    async def create_key(
        self,
        store: ApiKeyStore,
        *,
        name: str,
        service_id: str | None = None,
        scopes: list[str] | None = None,
        allowed_ips: list[str] | None = None,
        expires_at: datetime | None = None,
        salt_rounds: int | None = None,
    ) -> CreatedApiKey:
        """Generate a new API key, hash it, persist it, and return the raw key once."""
        raw = self._generate_raw_key()
        prefix = self.extract_prefix(raw)
        rounds = salt_rounds if salt_rounds is not None else self._salt_rounds
        key_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds)).decode()

        record = ApiKey(
            name=name,
            key_hash=key_hash,
            key_prefix=prefix,
            service_id=service_id,
            scopes=scopes or [],
            allowed_ips=allowed_ips,
            expires_at=expires_at,
        )
        await store.save(record)
        return CreatedApiKey(raw_key=raw, record=record)

    async def verify_key(self, raw_key: str, key_hash: str) -> bool:
        """Return ``True`` when *raw_key* matches *key_hash*."""
        try:
            return bcrypt.checkpw(raw_key.encode(), key_hash.encode())
        except Exception:
            return False

    async def authenticate(
        self,
        store: ApiKeyStore,
        raw_key: str,
        *,
        required_scope: str | None = None,
        client_ip: str | None = None,
    ) -> ApiKey | None:
        """Authenticate a raw API key.

        Returns the :class:`ApiKey` record on success, ``None`` on failure.

        :param store: The store to look up key candidates from.
        :param raw_key: The raw ``ak_…`` key string from the request.
        :param required_scope: When set, the key must include this scope.
        :param client_ip: When set, checked against ``allowed_ips``.
        """
        prefix = self.extract_prefix(raw_key)
        candidates = await store.find_by_prefix(prefix)
        now = datetime.now(timezone.utc)
        for key in candidates:
            if not key.is_active:
                continue
            if key.expires_at and key.expires_at < now:
                continue
            if not await self.verify_key(raw_key, key.key_hash):
                continue
            if required_scope and required_scope not in key.scopes:
                continue
            if client_ip and key.allowed_ips and client_ip not in key.allowed_ips:
                continue
            # Update last_used_at (best-effort)
            key.last_used_at = now
            try:
                await store.update(key)
            except Exception:
                pass
            return key
        return None
