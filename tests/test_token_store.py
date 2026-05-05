"""Tests for TokenStore / InMemoryTokenStore."""

from __future__ import annotations

import asyncio

import pytest

from awesome_python_auth.token_store import InMemoryTokenStore


@pytest.fixture()
def store() -> InMemoryTokenStore:
    return InMemoryTokenStore()


class TestSaveAndGet:
    @pytest.mark.asyncio
    async def test_save_and_get(self, store):
        await store.save("reset", "hash-abc", "user-1", ttl=3600)
        result = await store.get("reset", "hash-abc")
        assert result == "user-1"

    @pytest.mark.asyncio
    async def test_different_purposes_dont_collide(self, store):
        await store.save("reset", "hash-1", "user-a", ttl=3600)
        await store.save("verify", "hash-1", "user-b", ttl=3600)
        assert await store.get("reset", "hash-1") == "user-a"
        assert await store.get("verify", "hash-1") == "user-b"

    @pytest.mark.asyncio
    async def test_missing_token_returns_none(self, store):
        assert await store.get("reset", "nonexistent") is None

    @pytest.mark.asyncio
    async def test_expired_token_returns_none(self, store):
        await store.save("reset", "hash-exp", "user-1", ttl=0)
        # Even with ttl=0, it expires immediately on next monotonic check;
        # force expiry by manipulating internal state
        for k in list(store._store.keys()):
            store._store[k]["expires_at"] = 0.0
        result = await store.get("reset", "hash-exp")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_with_extra(self, store):
        await store.save("verify", "h1", "u1", ttl=3600, extra={"newEmail": "a@b.com"})
        result = await store.get_with_extra("verify", "h1")
        assert result is not None
        assert result["userId"] == "u1"
        assert result["extra"]["newEmail"] == "a@b.com"


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete(self, store):
        await store.save("reset", "h1", "u1", ttl=3600)
        await store.delete("reset", "h1")
        assert await store.get("reset", "h1") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_is_noop(self, store):
        await store.delete("reset", "nonexistent")  # must not raise

    @pytest.mark.asyncio
    async def test_delete_for_user(self, store):
        await store.save("reset", "h1", "u1", ttl=3600)
        await store.save("reset", "h2", "u1", ttl=3600)
        await store.save("reset", "h3", "u2", ttl=3600)
        await store.delete_for_user("reset", "u1")
        assert await store.get("reset", "h1") is None
        assert await store.get("reset", "h2") is None
        # u2's token survives
        assert await store.get("reset", "h3") == "u2"
