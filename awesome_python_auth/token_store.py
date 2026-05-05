"""TokenStore — pluggable one-time token persistence for awesome-python-auth.

Provides:
- :class:`TokenStore` — abstract interface for opaque token storage with TTL.
- :class:`InMemoryTokenStore` — simple in-memory implementation for testing.

The token store is useful when you want to persist magic-link tokens, email
verification tokens, and password-reset tokens in a shared storage (e.g. Redis,
a database) rather than inside the :class:`~awesome_python_auth.models.StoredUser`
record.  This allows tokens to be checked without a full user-object load and
simplifies token revocation.

Usage::

    from awesome_python_auth import TokenStore, InMemoryTokenStore

    store = InMemoryTokenStore()
    await store.save("reset", "hashed-token-abc", user_id="user-1", ttl=3600)
    user_id = await store.get("reset", "hashed-token-abc")  # "user-1"
    await store.delete("reset", "hashed-token-abc")
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any


class TokenStore(ABC):
    """Abstract store for typed, time-limited opaque tokens.

    *purpose* is an application-defined string such as ``"reset"``,
    ``"verify-email"``, or ``"magic-link"``.  This allows a single store
    implementation to hold tokens of different types without key collision.
    """

    @abstractmethod
    async def save(
        self,
        purpose: str,
        token_hash: str,
        user_id: str,
        ttl: int,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Persist *token_hash* for *user_id* under *purpose* with a TTL in seconds.

        *extra* can carry any additional metadata (e.g. new_email for email-change tokens).
        Overwrites any existing record with the same (purpose, token_hash) key.
        """

    @abstractmethod
    async def get(self, purpose: str, token_hash: str) -> str | None:
        """Return the ``user_id`` associated with *token_hash* (for *purpose*).

        Returns ``None`` when the token is unknown or has expired.
        """

    @abstractmethod
    async def get_with_extra(self, purpose: str, token_hash: str) -> dict[str, Any] | None:
        """Return ``{"userId": str, "extra": dict | None}`` or ``None`` when expired/missing."""

    @abstractmethod
    async def delete(self, purpose: str, token_hash: str) -> None:
        """Invalidate *token_hash* for *purpose*.  No-op when the token is not found."""

    @abstractmethod
    async def delete_for_user(self, purpose: str, user_id: str) -> None:
        """Invalidate **all** tokens for *user_id* under *purpose*."""


class InMemoryTokenStore(TokenStore):
    """Simple in-memory token store with TTL support.

    Suitable for testing, examples, and single-process deployments.
    All data is lost on restart — use a database/Redis-backed implementation
    for production.

    Expired tokens are lazily pruned on access.
    """

    def __init__(self) -> None:
        # (purpose, token_hash) -> {"user_id", "expires_at", "extra"}
        self._store: dict[tuple[str, str], dict[str, Any]] = {}

    def _prune(self) -> None:
        """Remove all expired entries."""
        now = time.monotonic()
        expired = [k for k, v in self._store.items() if v["expires_at"] <= now]
        for k in expired:
            del self._store[k]

    async def save(
        self,
        purpose: str,
        token_hash: str,
        user_id: str,
        ttl: int,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self._prune()
        self._store[(purpose, token_hash)] = {
            "user_id": user_id,
            "expires_at": time.monotonic() + ttl,
            "extra": extra,
        }

    async def get(self, purpose: str, token_hash: str) -> str | None:
        result = await self.get_with_extra(purpose, token_hash)
        if result is None:
            return None
        return result["userId"]

    async def get_with_extra(self, purpose: str, token_hash: str) -> dict[str, Any] | None:
        self._prune()
        record = self._store.get((purpose, token_hash))
        if record is None:
            return None
        if record["expires_at"] <= time.monotonic():
            del self._store[(purpose, token_hash)]
            return None
        return {"userId": record["user_id"], "extra": record.get("extra")}

    async def delete(self, purpose: str, token_hash: str) -> None:
        self._store.pop((purpose, token_hash), None)

    async def delete_for_user(self, purpose: str, user_id: str) -> None:
        to_delete = [
            k
            for k, v in self._store.items()
            if k[0] == purpose and v["user_id"] == user_id
        ]
        for k in to_delete:
            del self._store[k]
