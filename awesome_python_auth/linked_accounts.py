"""Linked-accounts and pending-link stores for awesome-python-auth.

These stores support the account-linking flow where a user can connect multiple
OAuth / social-login providers to a single account.

Provides:
- :class:`LinkedAccount` — a record of a linked provider account.
- :class:`LinkedAccountsStore` — abstract interface.
- :class:`InMemoryLinkedAccountsStore` — in-memory implementation.
- :class:`PendingLink` — a pending (unconfirmed) link record.
- :class:`PendingLinkStore` — abstract interface.
- :class:`InMemoryPendingLinkStore` — in-memory implementation with TTL.

Usage::

    from awesome_python_auth import (
        LinkedAccount, LinkedAccountsStore, InMemoryLinkedAccountsStore,
        PendingLink, PendingLinkStore, InMemoryPendingLinkStore,
    )
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class LinkedAccount(BaseModel):
    """A provider account linked to a local user."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    provider: str
    provider_account_id: str
    email: str | None = None
    display_name: str | None = None
    avatar_url: str | None = None
    linked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] | None = None

    def to_api_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "userId": self.user_id,
            "provider": self.provider,
            "providerAccountId": self.provider_account_id,
            "linkedAt": self.linked_at.isoformat(),
        }
        if self.email is not None:
            data["email"] = self.email
        if self.display_name is not None:
            data["displayName"] = self.display_name
        if self.avatar_url is not None:
            data["avatarUrl"] = self.avatar_url
        if self.metadata is not None:
            data["metadata"] = self.metadata
        return data


class PendingLink(BaseModel):
    """A temporary record created when account-linking is initiated."""

    token_hash: str
    user_id: str
    provider: str
    email: str | None = None
    login_after_linking: bool = False
    expires_at: datetime
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# LinkedAccountsStore
# ---------------------------------------------------------------------------


class LinkedAccountsStore(ABC):
    """Abstract store for linked OAuth provider accounts."""

    @abstractmethod
    async def add(self, account: LinkedAccount) -> LinkedAccount:
        """Persist a new linked account.  Returns the saved record."""

    @abstractmethod
    async def get_by_user(self, user_id: str) -> list[LinkedAccount]:
        """Return all accounts linked to *user_id*."""

    @abstractmethod
    async def get_by_provider_account(
        self, provider: str, provider_account_id: str
    ) -> LinkedAccount | None:
        """Find a linked account by provider + provider-specific account ID."""

    @abstractmethod
    async def delete(
        self, provider: str, provider_account_id: str, user_id: str
    ) -> None:
        """Unlink the provider account from the user.  No-op when not found."""

    @abstractmethod
    async def delete_for_user(self, user_id: str) -> None:
        """Unlink **all** provider accounts for *user_id*."""


class InMemoryLinkedAccountsStore(LinkedAccountsStore):
    """Simple in-memory linked-accounts store — suitable for testing."""

    def __init__(self) -> None:
        # id -> LinkedAccount
        self._accounts: dict[str, LinkedAccount] = {}

    async def add(self, account: LinkedAccount) -> LinkedAccount:
        self._accounts[account.id] = account
        return account

    async def get_by_user(self, user_id: str) -> list[LinkedAccount]:
        return [a for a in self._accounts.values() if a.user_id == user_id]

    async def get_by_provider_account(
        self, provider: str, provider_account_id: str
    ) -> LinkedAccount | None:
        return next(
            (
                a
                for a in self._accounts.values()
                if a.provider == provider and a.provider_account_id == provider_account_id
            ),
            None,
        )

    async def delete(
        self, provider: str, provider_account_id: str, user_id: str
    ) -> None:
        to_delete = [
            aid
            for aid, a in self._accounts.items()
            if a.provider == provider
            and a.provider_account_id == provider_account_id
            and a.user_id == user_id
        ]
        for aid in to_delete:
            del self._accounts[aid]

    async def delete_for_user(self, user_id: str) -> None:
        self._accounts = {
            aid: a for aid, a in self._accounts.items() if a.user_id != user_id
        }


# ---------------------------------------------------------------------------
# PendingLinkStore
# ---------------------------------------------------------------------------


class PendingLinkStore(ABC):
    """Abstract store for pending (unconfirmed) account-link requests."""

    @abstractmethod
    async def save(self, pending: PendingLink) -> None:
        """Persist (or overwrite) a pending link record."""

    @abstractmethod
    async def get(self, token_hash: str) -> PendingLink | None:
        """Return the pending link for *token_hash*, or ``None`` when expired/missing."""

    @abstractmethod
    async def delete(self, token_hash: str) -> None:
        """Remove the pending link.  No-op when not found."""

    @abstractmethod
    async def delete_for_user(self, user_id: str) -> None:
        """Remove **all** pending links for *user_id*."""


class InMemoryPendingLinkStore(PendingLinkStore):
    """Simple in-memory pending-link store with TTL support."""

    def __init__(self) -> None:
        # token_hash -> (PendingLink, monotonic_expires)
        self._store: dict[str, tuple[PendingLink, float]] = {}

    def _prune(self) -> None:
        now = time.monotonic()
        # We use actual datetime comparison here
        cutoff = datetime.now(timezone.utc)
        expired = [
            h for h, (p, _) in self._store.items() if p.expires_at <= cutoff
        ]
        for h in expired:
            del self._store[h]

    async def save(self, pending: PendingLink) -> None:
        self._prune()
        self._store[pending.token_hash] = (pending, 0.0)  # expiry encoded in model

    async def get(self, token_hash: str) -> PendingLink | None:
        self._prune()
        record = self._store.get(token_hash)
        if record is None:
            return None
        pending, _ = record
        if pending.expires_at <= datetime.now(timezone.utc):
            del self._store[token_hash]
            return None
        return pending

    async def delete(self, token_hash: str) -> None:
        self._store.pop(token_hash, None)

    async def delete_for_user(self, user_id: str) -> None:
        self._store = {
            h: v for h, v in self._store.items() if v[0].user_id != user_id
        }
