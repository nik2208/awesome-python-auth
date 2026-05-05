"""Tests for build_admin_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from awesome_python_auth import (
    AuthConfig,
    AuthConfigurator,
    InMemoryRolesPermissionsStore,
    InMemoryTenantStore,
    InMemoryUserStore,
)
from awesome_python_auth.admin_router import build_admin_router
from awesome_python_auth.models import StoredUser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(access_policy="is-admin-flag"):
    user_store = InMemoryUserStore()
    rbac_store = InMemoryRolesPermissionsStore()
    tenant_store = InMemoryTenantStore()

    config = AuthConfig(
        access_token_secret="a-very-long-secret-that-is-at-least-32-chars!",
        roles_permissions_store=rbac_store,
        tenant_store=tenant_store,
    )
    auth = AuthConfigurator(config, user_store)

    app = FastAPI()
    app.include_router(auth.router())
    app.include_router(
        build_admin_router(
            config=config,
            user_store=user_store,
            rbac_store=rbac_store,
            tenant_store=tenant_store,
            access_policy=access_policy,
        ),
        prefix="/admin",
    )
    return app, user_store, rbac_store, tenant_store, config


async def _admin_token(client, user_store, config):
    """Register an admin user and return a Bearer token."""
    admin = StoredUser(
        email="admin@example.com",
        hashed_password=None,
        is_admin=True,
    )
    await user_store.create(admin)
    # Generate token directly
    from awesome_python_auth.jwt_utils import create_access_token
    payload = admin.to_auth_user().to_jwt_payload()
    return create_access_token(payload, config.access_token_secret, 900)


# ---------------------------------------------------------------------------
# Tests — access control
# ---------------------------------------------------------------------------


class TestAdminAccess:
    @pytest.mark.asyncio
    async def test_unauthenticated_returns_401(self):
        app, *_ = _make_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/admin/api/ping")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_non_admin_returns_403(self):
        app, user_store, _, __, config = _make_app()
        normal_user = StoredUser(email="user@example.com")
        await user_store.create(normal_user)
        from awesome_python_auth.jwt_utils import create_access_token
        token = create_access_token(normal_user.to_auth_user().to_jwt_payload(), config.access_token_secret, 900)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get("/admin/api/ping", headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_can_ping(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                "/admin/api/ping",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_open_policy_allows_any_authenticated(self):
        app, user_store, _, __, config = _make_app(access_policy="open")
        normal_user = StoredUser(email="user@example.com")
        await user_store.create(normal_user)
        from awesome_python_auth.jwt_utils import create_access_token
        token = create_access_token(normal_user.to_auth_user().to_jwt_payload(), config.access_token_secret, 900)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                "/admin/api/ping",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Tests — users
# ---------------------------------------------------------------------------


class TestAdminUsers:
    @pytest.mark.asyncio
    async def test_list_users(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                "/admin/api/users",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 200
        data = r.json()
        assert "users" in data
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_get_user(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        admin = await user_store.get_by_email("admin@example.com")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                f"/admin/api/users/{admin.id}",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 200
        assert r.json()["id"] == admin.id

    @pytest.mark.asyncio
    async def test_get_missing_user_returns_404(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                "/admin/api/users/nonexistent",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_user(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        victim = StoredUser(email="victim@example.com")
        await user_store.create(victim)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.delete(
                f"/admin/api/users/{victim.id}",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 204
        assert await user_store.get_by_id(victim.id) is None


# ---------------------------------------------------------------------------
# Tests — roles
# ---------------------------------------------------------------------------


class TestAdminRoles:
    @pytest.mark.asyncio
    async def test_list_roles(self):
        app, user_store, rbac_store, _, config = _make_app()
        await rbac_store.create_role("admin", permissions=["users:read"])
        token = await _admin_token(None, user_store, config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.get(
                "/admin/api/roles",
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 200
        names = [role["name"] for role in r.json()["roles"]]
        assert "admin" in names

    @pytest.mark.asyncio
    async def test_create_role(self):
        app, user_store, _, __, config = _make_app()
        token = await _admin_token(None, user_store, config)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                "/admin/api/roles",
                json={"name": "editor", "permissions": ["posts:write"]},
                headers={"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"},
            )
        assert r.status_code == 201

    @pytest.mark.asyncio
    async def test_add_and_remove_user_role(self):
        app, user_store, rbac_store, _, config = _make_app()
        await rbac_store.create_role("editor")
        token = await _admin_token(None, user_store, config)
        admin = await user_store.get_by_email("admin@example.com")
        headers = {"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                f"/admin/api/users/{admin.id}/roles",
                json={"role": "editor"},
                headers=headers,
            )
            assert r.status_code == 201
            # Verify it appears
            r2 = await client.get(f"/admin/api/users/{admin.id}/roles", headers=headers)
            assert "editor" in r2.json()["roles"]
            # Remove it
            r3 = await client.delete(f"/admin/api/users/{admin.id}/roles/editor", headers=headers)
            assert r3.status_code == 204


# ---------------------------------------------------------------------------
# Tests — tenants
# ---------------------------------------------------------------------------


class TestAdminTenants:
    @pytest.mark.asyncio
    async def test_list_and_create_tenant(self):
        app, user_store, _, tenant_store, config = _make_app()
        token = await _admin_token(None, user_store, config)
        headers = {"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.post(
                "/admin/api/tenants",
                json={"name": "Acme Corp", "slug": "acme"},
                headers=headers,
            )
            assert r.status_code == 201
            tenant_id = r.json()["id"]
            r2 = await client.get("/admin/api/tenants", headers=headers)
            assert any(t["id"] == tenant_id for t in r2.json()["tenants"])

    @pytest.mark.asyncio
    async def test_delete_tenant(self):
        app, user_store, _, tenant_store, config = _make_app()
        token = await _admin_token(None, user_store, config)
        t = await tenant_store.create_tenant({"name": "To Delete"})
        headers = {"Authorization": f"Bearer {token}", "X-Auth-Strategy": "bearer"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r = await client.delete(f"/admin/api/tenants/{t.id}", headers=headers)
        assert r.status_code == 204
