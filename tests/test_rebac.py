"""Tests for RolesPermissionsStore / InMemoryRolesPermissionsStore."""

from __future__ import annotations

import pytest

from awesome_python_auth.rebac import InMemoryRolesPermissionsStore


@pytest.fixture()
def store() -> InMemoryRolesPermissionsStore:
    return InMemoryRolesPermissionsStore()


# ---------------------------------------------------------------------------
# Role management
# ---------------------------------------------------------------------------


class TestCreateRole:
    @pytest.mark.asyncio
    async def test_create_role(self, store):
        await store.create_role("admin")
        roles = await store.get_all_roles()
        assert "admin" in roles

    @pytest.mark.asyncio
    async def test_create_role_with_permissions(self, store):
        await store.create_role("editor", permissions=["posts:read", "posts:write"])
        perms = await store.get_permissions_for_role("editor")
        assert set(perms) == {"posts:read", "posts:write"}

    @pytest.mark.asyncio
    async def test_create_role_idempotent(self, store):
        await store.create_role("admin", permissions=["users:read"])
        await store.create_role("admin", permissions=["users:write"])
        # second call should not wipe, but merge
        perms = await store.get_permissions_for_role("admin")
        assert "users:read" in perms
        assert "users:write" in perms

    @pytest.mark.asyncio
    async def test_delete_role(self, store):
        await store.create_role("temp")
        await store.delete_role("temp")
        roles = await store.get_all_roles()
        assert "temp" not in roles

    @pytest.mark.asyncio
    async def test_delete_role_removes_from_users(self, store):
        await store.create_role("admin")
        await store.add_role_to_user("u1", "admin")
        await store.delete_role("admin")
        roles = await store.get_roles_for_user("u1")
        assert "admin" not in roles


# ---------------------------------------------------------------------------
# Permission management
# ---------------------------------------------------------------------------


class TestPermissions:
    @pytest.mark.asyncio
    async def test_add_permission_to_role(self, store):
        await store.create_role("viewer")
        await store.add_permission_to_role("viewer", "posts:read")
        perms = await store.get_permissions_for_role("viewer")
        assert "posts:read" in perms

    @pytest.mark.asyncio
    async def test_add_permission_idempotent(self, store):
        await store.create_role("viewer")
        await store.add_permission_to_role("viewer", "posts:read")
        await store.add_permission_to_role("viewer", "posts:read")
        perms = await store.get_permissions_for_role("viewer")
        assert perms.count("posts:read") == 1

    @pytest.mark.asyncio
    async def test_remove_permission_from_role(self, store):
        await store.create_role("editor", permissions=["posts:read", "posts:write"])
        await store.remove_permission_from_role("editor", "posts:write")
        perms = await store.get_permissions_for_role("editor")
        assert "posts:write" not in perms
        assert "posts:read" in perms


# ---------------------------------------------------------------------------
# User ↔ Role assignments
# ---------------------------------------------------------------------------


class TestUserRoles:
    @pytest.mark.asyncio
    async def test_add_and_get_roles(self, store):
        await store.create_role("admin")
        await store.create_role("editor")
        await store.add_role_to_user("u1", "admin")
        await store.add_role_to_user("u1", "editor")
        roles = await store.get_roles_for_user("u1")
        assert "admin" in roles
        assert "editor" in roles

    @pytest.mark.asyncio
    async def test_remove_role(self, store):
        await store.create_role("admin")
        await store.add_role_to_user("u1", "admin")
        await store.remove_role_from_user("u1", "admin")
        roles = await store.get_roles_for_user("u1")
        assert "admin" not in roles

    @pytest.mark.asyncio
    async def test_tenant_scoped_roles(self, store):
        await store.create_role("admin")
        await store.add_role_to_user("u1", "admin", tenant_id="t1")
        global_roles = await store.get_roles_for_user("u1")
        tenant_roles = await store.get_roles_for_user("u1", tenant_id="t1")
        assert "admin" not in global_roles
        assert "admin" in tenant_roles

    @pytest.mark.asyncio
    async def test_add_role_idempotent(self, store):
        await store.create_role("admin")
        await store.add_role_to_user("u1", "admin")
        await store.add_role_to_user("u1", "admin")
        roles = await store.get_roles_for_user("u1")
        assert roles.count("admin") == 1


# ---------------------------------------------------------------------------
# Aggregated permissions
# ---------------------------------------------------------------------------


class TestAggregatedPermissions:
    @pytest.mark.asyncio
    async def test_get_permissions_for_user(self, store):
        await store.create_role("admin", permissions=["users:read", "users:write"])
        await store.create_role("editor", permissions=["posts:write"])
        await store.add_role_to_user("u1", "admin")
        await store.add_role_to_user("u1", "editor")
        perms = await store.get_permissions_for_user("u1")
        assert set(perms) >= {"users:read", "users:write", "posts:write"}

    @pytest.mark.asyncio
    async def test_user_has_permission_true(self, store):
        await store.create_role("admin", permissions=["users:delete"])
        await store.add_role_to_user("u1", "admin")
        assert await store.user_has_permission("u1", "users:delete") is True

    @pytest.mark.asyncio
    async def test_user_has_permission_false(self, store):
        assert await store.user_has_permission("u1", "nonexistent:perm") is False
