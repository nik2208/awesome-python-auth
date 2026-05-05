"""Tests for jwt_utils and password_utils."""

import time

import jwt
import pytest

from awesome_python_auth.jwt_utils import (
    create_access_token,
    create_refresh_token,
    create_temp_token,
    decode_token,
    generate_csrf_token,
    generate_opaque_token,
)
from awesome_python_auth.password_utils import hash_password, verify_password

SECRET = "test-secret-123"


# ---------------------------------------------------------------------------
# JWT utilities
# ---------------------------------------------------------------------------


class TestCreateAccessToken:
    def test_returns_string(self):
        token = create_access_token({"sub": "user1", "email": "a@b.com"}, SECRET)
        assert isinstance(token, str)

    def test_payload_round_trips(self):
        payload = {"sub": "user1", "email": "a@b.com", "isEmailVerified": True}
        token = create_access_token(payload, SECRET)
        decoded = decode_token(token, SECRET)
        assert decoded["sub"] == "user1"
        assert decoded["email"] == "a@b.com"
        assert decoded["isEmailVerified"] is True

    def test_expiry_in_payload(self):
        token = create_access_token({"sub": "u"}, SECRET, expires_in_seconds=60)
        decoded = decode_token(token, SECRET)
        assert decoded["exp"] > decoded["iat"]
        assert decoded["exp"] - decoded["iat"] == 60

    def test_expired_token_raises(self):
        token = create_access_token({"sub": "u"}, SECRET, expires_in_seconds=-1)
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_token(token, SECRET)

    def test_wrong_secret_raises(self):
        token = create_access_token({"sub": "u"}, SECRET)
        with pytest.raises(jwt.PyJWTError):
            decode_token(token, "wrong-secret")


class TestCreateRefreshToken:
    def test_contains_session_handle(self):
        token = create_refresh_token("user1", "handle-abc", SECRET)
        decoded = decode_token(token, SECRET)
        assert decoded["sessionHandle"] == "handle-abc"

    def test_default_expiry(self):
        token = create_refresh_token("u", "h", SECRET)
        decoded = decode_token(token, SECRET)
        delta = decoded["exp"] - decoded["iat"]
        assert delta == 604800  # 7 days


class TestCreateTempToken:
    def test_contains_purpose(self):
        token = create_temp_token("user1", SECRET, purpose="2fa")
        decoded = decode_token(token, SECRET)
        assert decoded["purpose"] == "2fa"
        assert decoded["sub"] == "user1"

    def test_short_lived(self):
        token = create_temp_token("u", SECRET)
        decoded = decode_token(token, SECRET)
        assert (decoded["exp"] - decoded["iat"]) <= 300


class TestGenerateTokens:
    def test_csrf_token_is_string(self):
        t = generate_csrf_token()
        assert isinstance(t, str)
        assert len(t) > 20

    def test_opaque_token_is_string(self):
        t = generate_opaque_token()
        assert isinstance(t, str)
        assert len(t) > 20

    def test_tokens_unique(self):
        assert generate_csrf_token() != generate_csrf_token()
        assert generate_opaque_token() != generate_opaque_token()


# ---------------------------------------------------------------------------
# Password utilities
# ---------------------------------------------------------------------------


class TestPasswordUtils:
    def test_hash_and_verify(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed)

    def test_wrong_password(self):
        hashed = hash_password("correct")
        assert not verify_password("wrong", hashed)

    def test_empty_plain(self):
        hashed = hash_password("something")
        assert not verify_password("", hashed)

    def test_empty_hash(self):
        assert not verify_password("something", "")
