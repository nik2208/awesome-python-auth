"""Tests for LinkedAccountsStore / PendingLinkStore."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from awesome_python_auth.linked_accounts import (
    InMemoryLinkedAccountsStore,
    InMemoryPendingLinkStore,
    LinkedAccount,
    PendingLink,
)


# ---------------------------------------------------------------------------
# LinkedAccountsStore
# ---------------------------------------------------------------------------


@pytest.fixture()
def la_store() -> InMemoryLinkedAccountsStore:
    return InMemoryLinkedAccountsStore()


class TestLinkedAccountsStore:
    @pytest.mark.asyncio
    async def test_add_and_get_by_user(self, la_store):
        acc = LinkedAccount(user_id="u1", provider="google", provider_account_id="g-123")
        saved = await la_store.add(acc)
        results = await la_store.get_by_user("u1")
        assert any(r.id == saved.id for r in results)

    @pytest.mark.asyncio
    async def test_get_by_user_empty(self, la_store):
        assert await la_store.get_by_user("nonexistent") == []

    @pytest.mark.asyncio
    async def test_get_by_provider_account(self, la_store):
        acc = LinkedAccount(user_id="u1", provider="github", provider_account_id="gh-456")
        await la_store.add(acc)
        found = await la_store.get_by_provider_account("github", "gh-456")
        assert found is not None
        assert found.user_id == "u1"

    @pytest.mark.asyncio
    async def test_get_by_provider_account_missing(self, la_store):
        assert await la_store.get_by_provider_account("github", "nonexistent") is None

    @pytest.mark.asyncio
    async def test_delete(self, la_store):
        acc = LinkedAccount(user_id="u1", provider="google", provider_account_id="g-123")
        await la_store.add(acc)
        await la_store.delete("google", "g-123", "u1")
        results = await la_store.get_by_user("u1")
        assert results == []

    @pytest.mark.asyncio
    async def test_delete_noop_when_not_found(self, la_store):
        await la_store.delete("google", "nonexistent", "u1")  # must not raise

    @pytest.mark.asyncio
    async def test_delete_for_user(self, la_store):
        await la_store.add(LinkedAccount(user_id="u1", provider="google", provider_account_id="g-1"))
        await la_store.add(LinkedAccount(user_id="u1", provider="github", provider_account_id="gh-1"))
        await la_store.add(LinkedAccount(user_id="u2", provider="google", provider_account_id="g-2"))
        await la_store.delete_for_user("u1")
        assert await la_store.get_by_user("u1") == []
        assert len(await la_store.get_by_user("u2")) == 1

    def test_to_api_dict(self):
        acc = LinkedAccount(
            id="id-1",
            user_id="u1",
            provider="google",
            provider_account_id="g-1",
            email="user@gmail.com",
        )
        d = acc.to_api_dict()
        assert d["provider"] == "google"
        assert d["email"] == "user@gmail.com"
        assert "linkedAt" in d


# ---------------------------------------------------------------------------
# PendingLinkStore
# ---------------------------------------------------------------------------


@pytest.fixture()
def pl_store() -> InMemoryPendingLinkStore:
    return InMemoryPendingLinkStore()


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=1)


def _past() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=1)


class TestPendingLinkStore:
    @pytest.mark.asyncio
    async def test_save_and_get(self, pl_store):
        pending = PendingLink(
            token_hash="h1",
            user_id="u1",
            provider="google",
            expires_at=_future(),
        )
        await pl_store.save(pending)
        result = await pl_store.get("h1")
        assert result is not None
        assert result.user_id == "u1"

    @pytest.mark.asyncio
    async def test_expired_returns_none(self, pl_store):
        pending = PendingLink(
            token_hash="h-exp",
            user_id="u1",
            provider="google",
            expires_at=_past(),
        )
        await pl_store.save(pending)
        result = await pl_store.get("h-exp")
        assert result is None

    @pytest.mark.asyncio
    async def test_missing_returns_none(self, pl_store):
        assert await pl_store.get("nonexistent") is None

    @pytest.mark.asyncio
    async def test_delete(self, pl_store):
        pending = PendingLink(
            token_hash="h2",
            user_id="u1",
            provider="github",
            expires_at=_future(),
        )
        await pl_store.save(pending)
        await pl_store.delete("h2")
        assert await pl_store.get("h2") is None

    @pytest.mark.asyncio
    async def test_delete_for_user(self, pl_store):
        await pl_store.save(PendingLink(token_hash="h3", user_id="u1", provider="g", expires_at=_future()))
        await pl_store.save(PendingLink(token_hash="h4", user_id="u1", provider="g", expires_at=_future()))
        await pl_store.save(PendingLink(token_hash="h5", user_id="u2", provider="g", expires_at=_future()))
        await pl_store.delete_for_user("u1")
        assert await pl_store.get("h3") is None
        assert await pl_store.get("h4") is None
        assert await pl_store.get("h5") is not None
