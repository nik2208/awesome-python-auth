"""Integration tests for the auth router using FastAPI TestClient."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from awesome_python_auth.config import AuthConfig, AuthConfigurator
from awesome_python_auth.models import InMemoryUserStore, StoredUser
from awesome_python_auth.password_utils import hash_password

SECRET = "router-test-secret"

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def user_store():
    store = InMemoryUserStore()
    return store


@pytest.fixture()
def app(user_store):
    config = AuthConfig(
        api_prefix="/api/auth",
        access_token_secret=SECRET,
        cookie_secure=False,
        cookie_same_site="lax",
    )
    configurator = AuthConfigurator(config, user_store)
    fastapi_app = FastAPI()
    fastapi_app.include_router(configurator.router())
    return fastapi_app


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def registered_user(user_store):
    """Pre-populate the store with a verified user."""
    stored = StoredUser(
        email="alice@example.com",
        hashed_password=hash_password("password123"),
        first_name="Alice",
        last_name="Smith",
        is_email_verified=True,
    )
    import asyncio
    asyncio.get_event_loop().run_until_complete(user_store.create(stored))
    return stored


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_success(self, client):
        resp = client.post(
            "/api/auth/register",
            json={"email": "bob@example.com", "password": "Pass1234!", "firstName": "Bob", "lastName": "Jones"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["success"] is True
        assert "userId" in data

    def test_duplicate_email(self, client, registered_user):
        resp = client.post(
            "/api/auth/register",
            json={"email": "alice@example.com", "password": "Pass1234!"},
        )
        assert resp.status_code == 409

    def test_email_normalised_to_lowercase(self, client, user_store):
        resp = client.post(
            "/api/auth/register",
            json={"email": "UPPER@EXAMPLE.COM", "password": "Pass1234!"},
        )
        assert resp.status_code == 201
        import asyncio
        user = asyncio.get_event_loop().run_until_complete(
            user_store.get_by_email("upper@example.com")
        )
        assert user is not None


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class TestLogin:
    def test_success_cookie_mode(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["email"] == "alice@example.com"
        assert "access-token" in resp.cookies

    def test_success_bearer_mode(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "accessToken" in data
        assert "refreshToken" in data

    def test_wrong_password(self, client, registered_user):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401

    def test_unknown_email(self, client):
        resp = client.post(
            "/api/auth/login",
            json={"email": "nobody@example.com", "password": "anything"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------


class TestMe:
    def _login_get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_me_with_valid_bearer(self, client, registered_user):
        token = self._login_get_token(client, registered_user)
        resp = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["email"] == "alice@example.com"

    def test_me_unauthenticated(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_with_cookie(self, client, registered_user):
        login_resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        assert "access-token" in login_resp.cookies
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout_clears_cookies(self, client, registered_user):
        client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
        )
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        assert resp.json()["success"] is True


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class TestProfile:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_update_profile(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.patch(
            "/api/auth/profile",
            json={"firstName": "Alicia", "lastName": "Doe"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_update_profile_unauthenticated(self, client):
        resp = client.patch(
            "/api/auth/profile",
            json={"firstName": "X", "lastName": "Y"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------


class TestPasswordManagement:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_forgot_password_always_200(self, client):
        resp = client.post(
            "/api/auth/forgot-password",
            json={"email": "nobody@example.com"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_change_password(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/change-password",
            json={"currentPassword": "password123", "newPassword": "NewPass!456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_change_password_wrong_current(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/change-password",
            json={"currentPassword": "WRONG", "newPassword": "NewPass!456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestSessions:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_get_sessions(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.get(
            "/api/auth/sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "sessions" in resp.json()

    def test_revoke_unknown_session(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.delete(
            "/api/auth/sessions/nonexistent-handle",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 2FA
# ---------------------------------------------------------------------------


class TestTwoFactor:
    def _get_token(self, client, registered_user) -> str:
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        return resp.json()["accessToken"]

    def test_setup_2fa(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/2fa/setup",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert "qrCode" in data

    def test_disable_2fa(self, client, registered_user):
        token = self._get_token(client, registered_user)
        resp = client.post(
            "/api/auth/2fa/disable",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# UI config
# ---------------------------------------------------------------------------


class TestUiConfig:
    def test_returns_empty_dict_by_default(self, client):
        resp = client.get("/api/auth/ui/config")
        assert resp.status_code == 200
        assert resp.json() == {}


# ---------------------------------------------------------------------------
# Delete account
# ---------------------------------------------------------------------------


class TestDeleteAccount:
    def test_delete_account(self, client, registered_user, user_store):
        resp = client.post(
            "/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            headers={"X-Auth-Strategy": "bearer"},
        )
        token = resp.json()["accessToken"]
        del_resp = client.delete(
            "/api/auth/account",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert del_resp.status_code == 200
        import asyncio
        user = asyncio.get_event_loop().run_until_complete(
            user_store.get_by_email("alice@example.com")
        )
        assert user is None
