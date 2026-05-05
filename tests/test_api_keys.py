"""Tests for api_keys module."""
from __future__ import annotations

import pytest

from awesome_python_auth.api_keys import (
    ApiKey,
    ApiKeyService,
    InMemoryApiKeyStore,
)


@pytest.fixture
def store():
    return InMemoryApiKeyStore()


@pytest.fixture
def svc():
    return ApiKeyService(salt_rounds=4)  # fast rounds for tests


class TestApiKeyService:
    async def test_create_key_returns_raw_key(self, store, svc):
        result = await svc.create_key(store, name="test-key")
        assert result.raw_key.startswith("ak_")
        assert len(result.raw_key) == 51  # "ak_" + 48 hex chars

    async def test_create_key_saves_to_store(self, store, svc):
        result = await svc.create_key(store, name="test-key")
        keys = await store.list_all()
        assert len(keys) == 1
        assert keys[0].id == result.record.id

    async def test_authenticate_success(self, store, svc):
        created = await svc.create_key(store, name="svc-key", scopes=["read"])
        key = await svc.authenticate(store, created.raw_key)
        assert key is not None
        assert key.name == "svc-key"

    async def test_authenticate_wrong_key(self, store, svc):
        await svc.create_key(store, name="svc-key")
        key = await svc.authenticate(store, "ak_" + "0" * 48)
        assert key is None

    async def test_authenticate_inactive_key(self, store, svc):
        created = await svc.create_key(store, name="key")
        # Deactivate
        record = created.record
        record.is_active = False
        await store.update(record)
        result = await svc.authenticate(store, created.raw_key)
        assert result is None

    async def test_authenticate_scope_check(self, store, svc):
        created = await svc.create_key(store, name="key", scopes=["tools:read"])
        assert await svc.authenticate(store, created.raw_key, required_scope="tools:read") is not None
        assert await svc.authenticate(store, created.raw_key, required_scope="admin") is None

    async def test_delete_key(self, store, svc):
        created = await svc.create_key(store, name="to-delete")
        await store.delete(created.record.id)
        keys = await store.list_all()
        assert len(keys) == 0

    async def test_extract_prefix(self, svc):
        key = "ak_" + "a" * 48
        prefix = svc.extract_prefix(key)
        assert prefix == "ak_" + "a" * 8
        assert len(prefix) == 11
