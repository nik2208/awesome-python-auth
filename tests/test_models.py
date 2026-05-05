"""Tests for AuthUser model serialization."""

from datetime import datetime

import pytest

from awesome_python_auth.models import AuthUser, StoredUser


class TestAuthUser:
    def test_to_jwt_payload_required_fields(self):
        user = AuthUser(sub="abc", email="test@test.com", is_email_verified=True)
        payload = user.to_jwt_payload()
        assert payload["sub"] == "abc"
        assert payload["email"] == "test@test.com"
        assert payload["isEmailVerified"] is True

    def test_to_jwt_payload_optional_fields_omitted(self):
        user = AuthUser(sub="abc", email="test@test.com", is_email_verified=False)
        payload = user.to_jwt_payload()
        assert "firstName" not in payload
        assert "lastName" not in payload

    def test_to_jwt_payload_optional_fields_included(self):
        user = AuthUser(
            sub="abc",
            email="test@test.com",
            is_email_verified=True,
            first_name="John",
            last_name="Doe",
            roles=["admin"],
            is_admin=True,
        )
        payload = user.to_jwt_payload()
        assert payload["firstName"] == "John"
        assert payload["lastName"] == "Doe"
        assert payload["roles"] == ["admin"]
        assert payload["isAdmin"] is True

    def test_from_jwt_payload_roundtrip(self):
        user = AuthUser(
            sub="u1",
            email="a@b.com",
            is_email_verified=True,
            first_name="Alice",
            last_name="Smith",
            roles=["user"],
        )
        payload = user.to_jwt_payload()
        restored = AuthUser.from_jwt_payload(payload)
        assert restored.sub == user.sub
        assert restored.email == user.email
        assert restored.first_name == user.first_name
        assert restored.roles == user.roles

    def test_to_api_dict_camel_case(self):
        user = AuthUser(
            sub="u1",
            email="a@b.com",
            is_email_verified=True,
            first_name="Bob",
            last_name="Builder",
        )
        data = user.to_api_dict()
        assert "isEmailVerified" in data
        assert "firstName" in data
        assert "lastName" in data
        assert "is_email_verified" not in data

    def test_from_jwt_payload_last_login_parsed(self):
        payload = {
            "sub": "u1",
            "email": "a@b.com",
            "isEmailVerified": True,
            "lastLogin": "2024-01-15T10:30:00",
        }
        user = AuthUser.from_jwt_payload(payload)
        assert isinstance(user.last_login, datetime)

    def test_from_jwt_payload_bad_last_login_ignored(self):
        payload = {
            "sub": "u1",
            "email": "a@b.com",
            "isEmailVerified": False,
            "lastLogin": "not-a-date",
        }
        user = AuthUser.from_jwt_payload(payload)
        assert user.last_login is None


class TestStoredUser:
    def test_to_auth_user_basic(self):
        stored = StoredUser(
            email="test@test.com",
            first_name="Test",
            last_name="User",
            hashed_password="hashed",
        )
        auth = stored.to_auth_user()
        assert auth.sub == stored.id
        assert auth.email == stored.email
        assert auth.has_password is True

    def test_to_auth_user_no_password(self):
        stored = StoredUser(email="oauth@test.com")
        auth = stored.to_auth_user()
        assert auth.has_password is False
