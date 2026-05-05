"""Tests for CSRF middleware."""

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from awesome_python_auth.middleware import CsrfMiddleware


@pytest.fixture()
def app_with_csrf():
    app = FastAPI()
    app.add_middleware(
        CsrfMiddleware,
        api_prefix="/api/auth",
        cookie_secure=False,
    )

    @app.post("/api/auth/profile")
    async def profile():
        return {"ok": True}

    @app.post("/api/auth/login")
    async def login():
        return {"ok": True}

    @app.get("/api/auth/me")
    async def me():
        return {"ok": True}

    return app


@pytest.fixture()
def client(app_with_csrf):
    return TestClient(app_with_csrf, raise_server_exceptions=False)


class TestCsrfMiddleware:
    def test_csrf_cookie_set_on_first_response(self, client):
        resp = client.get("/api/auth/me")
        assert "csrf-token" in resp.cookies

    def test_get_requests_pass_without_csrf_header(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200

    def test_login_excluded_from_csrf(self, client):
        """Login endpoint is excluded from CSRF validation."""
        resp = client.post("/api/auth/login")
        assert resp.status_code == 200

    def test_non_excluded_post_requires_csrf(self, client):
        """POST to a non-excluded endpoint without CSRF header returns 403."""
        # First get a CSRF cookie
        get_resp = client.get("/api/auth/me")
        csrf_cookie = get_resp.cookies.get("csrf-token")
        # POST without the X-CSRF-Token header
        resp = client.post("/api/auth/profile")
        assert resp.status_code == 403

    def test_non_excluded_post_with_valid_csrf(self, client):
        """POST with matching CSRF header and cookie is allowed."""
        get_resp = client.get("/api/auth/me")
        csrf_token = get_resp.cookies.get("csrf-token")
        resp = client.post(
            "/api/auth/profile",
            headers={"X-CSRF-Token": csrf_token},
            cookies={"csrf-token": csrf_token},
        )
        assert resp.status_code == 200

    def test_bearer_mode_skips_csrf(self, client):
        """Native (Bearer) clients with X-Auth-Strategy header skip CSRF."""
        resp = client.post(
            "/api/auth/profile",
            headers={"X-Auth-Strategy": "bearer"},
        )
        assert resp.status_code == 200

    def test_mismatched_csrf_token_rejected(self, client):
        get_resp = client.get("/api/auth/me")
        csrf_token = get_resp.cookies.get("csrf-token")
        resp = client.post(
            "/api/auth/profile",
            headers={"X-CSRF-Token": "bad-token"},
            cookies={"csrf-token": csrf_token},
        )
        assert resp.status_code == 403
