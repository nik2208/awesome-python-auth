"""Tests for Tenant / TenantStore / InMemoryTenantStore."""

from __future__ import annotations

import pytest

from awesome_python_auth.tenants import InMemoryTenantStore, Tenant


@pytest.fixture()
def store() -> InMemoryTenantStore:
    return InMemoryTenantStore()


class TestTenantCRUD:
    @pytest.mark.asyncio
    async def test_create_tenant(self, store):
        t = await store.create_tenant({"name": "Acme", "slug": "acme"})
        assert t.name == "Acme"
        assert t.slug == "acme"
        assert t.id

    @pytest.mark.asyncio
    async def test_get_by_id(self, store):
        t = await store.create_tenant({"name": "Acme"})
        found = await store.get_tenant_by_id(t.id)
        assert found is not None
        assert found.id == t.id

    @pytest.mark.asyncio
    async def test_get_by_id_missing(self, store):
        assert await store.get_tenant_by_id("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_all_tenants(self, store):
        await store.create_tenant({"name": "A"})
        await store.create_tenant({"name": "B"})
        tenants = await store.get_all_tenants()
        assert len(tenants) == 2

    @pytest.mark.asyncio
    async def test_update_tenant(self, store):
        t = await store.create_tenant({"name": "Acme"})
        updated = await store.update_tenant(t.id, {"name": "Acme Corp", "slug": "acme-corp"})
        assert updated is not None
        assert updated.name == "Acme Corp"
        assert updated.slug == "acme-corp"
        # Verify it's persisted
        reloaded = await store.get_tenant_by_id(t.id)
        assert reloaded.name == "Acme Corp"

    @pytest.mark.asyncio
    async def test_update_missing_returns_none(self, store):
        result = await store.update_tenant("nonexistent", {"name": "X"})
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_tenant(self, store):
        t = await store.create_tenant({"name": "Delete Me"})
        await store.delete_tenant(t.id)
        assert await store.get_tenant_by_id(t.id) is None

    @pytest.mark.asyncio
    async def test_delete_removes_memberships(self, store):
        t = await store.create_tenant({"name": "T"})
        await store.associate_user_with_tenant("u1", t.id)
        await store.delete_tenant(t.id)
        # After deletion, get_tenants_for_user should not return the deleted tenant
        tenants = await store.get_tenants_for_user("u1")
        assert not any(ten.id == t.id for ten in tenants)


class TestMembership:
    @pytest.mark.asyncio
    async def test_associate_and_get(self, store):
        t = await store.create_tenant({"name": "T"})
        await store.associate_user_with_tenant("u1", t.id)
        tenants = await store.get_tenants_for_user("u1")
        assert any(ten.id == t.id for ten in tenants)

    @pytest.mark.asyncio
    async def test_associate_idempotent(self, store):
        t = await store.create_tenant({"name": "T"})
        await store.associate_user_with_tenant("u1", t.id)
        await store.associate_user_with_tenant("u1", t.id)
        user_ids = await store.get_users_for_tenant(t.id)
        assert user_ids.count("u1") == 1

    @pytest.mark.asyncio
    async def test_disassociate(self, store):
        t = await store.create_tenant({"name": "T"})
        await store.associate_user_with_tenant("u1", t.id)
        await store.disassociate_user_from_tenant("u1", t.id)
        tenants = await store.get_tenants_for_user("u1")
        assert not any(ten.id == t.id for ten in tenants)

    @pytest.mark.asyncio
    async def test_get_users_for_tenant(self, store):
        t = await store.create_tenant({"name": "T"})
        await store.associate_user_with_tenant("u1", t.id)
        await store.associate_user_with_tenant("u2", t.id)
        user_ids = await store.get_users_for_tenant(t.id)
        assert set(user_ids) == {"u1", "u2"}


class TestToApiDict:
    def test_basic(self):
        t = Tenant(id="abc", name="Acme", slug="acme")
        d = t.to_api_dict()
        assert d["id"] == "abc"
        assert d["name"] == "Acme"
        assert d["slug"] == "acme"
        assert "metadata" not in d

    def test_with_metadata(self):
        t = Tenant(id="abc", name="Acme", metadata={"plan": "pro"})
        d = t.to_api_dict()
        assert d["metadata"] == {"plan": "pro"}
