"""Tests for the IDP / JWKS module."""
from __future__ import annotations

import pytest
import jwt as pyjwt

from awesome_python_auth.idp import (
    IdProviderConfig,
    ResourceServerConfig,
    JwksService,
    JwksClient,
    JWK,
    resolve_idp_keypair,
)
from awesome_python_auth.jwt_utils import (
    create_idp_access_token,
    create_idp_refresh_token,
    decode_token_with_jwks,
)


class TestJwksService:
    def test_generate_keypair_returns_pem_strings(self):
        priv, pub = JwksService.generate_keypair()
        assert "BEGIN PRIVATE KEY" in priv
        assert "BEGIN PUBLIC KEY" in pub

    def test_derive_public_key(self):
        priv, pub = JwksService.generate_keypair()
        derived = JwksService.derive_public_key(priv)
        assert "BEGIN PUBLIC KEY" in derived
        # The derived key should match the generated one (same bytes)
        assert derived.strip() == pub.strip()

    def test_public_key_to_jwk(self):
        _, pub = JwksService.generate_keypair()
        jwk = JwksService.public_key_to_jwk(pub, kid="test-key-1")
        assert jwk.kty == "RSA"
        assert jwk.use == "sig"
        assert jwk.alg == "RS256"
        assert jwk.kid == "test-key-1"
        assert jwk.n
        assert jwk.e

    def test_jwk_to_dict(self):
        _, pub = JwksService.generate_keypair()
        jwk = JwksService.public_key_to_jwk(pub)
        d = jwk.to_dict()
        assert set(d.keys()) >= {"kty", "use", "alg", "kid", "n", "e"}

    def test_build_jwks_document(self):
        _, pub = JwksService.generate_keypair()
        doc = JwksService.build_jwks_document(pub, kid="my-key")
        assert "keys" in doc
        assert len(doc["keys"]) == 1
        assert doc["keys"][0]["kid"] == "my-key"

    def test_jwk_to_public_key_pem_roundtrip(self):
        _, pub = JwksService.generate_keypair()
        jwk = JwksService.public_key_to_jwk(pub)
        pem_back = JwksService.jwk_to_public_key_pem(jwk)
        assert "BEGIN PUBLIC KEY" in pem_back

    def test_jwk_dict_roundtrip(self):
        _, pub = JwksService.generate_keypair()
        jwk = JwksService.public_key_to_jwk(pub)
        pem_back = JwksService.jwk_to_public_key_pem(jwk.to_dict())
        assert "BEGIN PUBLIC KEY" in pem_back


class TestIdpJwtCreation:
    def test_create_idp_access_token_rs256(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1", "email": "a@b.com"}, priv)
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert header["kid"] == "provisioner-key-1"

    def test_create_idp_access_token_verifiable(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1", "email": "a@b.com"}, priv)
        payload = pyjwt.decode(token, pub, algorithms=["RS256"])
        assert payload["sub"] == "u1"
        assert payload["email"] == "a@b.com"

    def test_create_idp_access_token_with_issuer(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1"}, priv, issuer="https://auth.example.com")
        payload = pyjwt.decode(token, pub, algorithms=["RS256"])
        assert payload["iss"] == "https://auth.example.com"

    def test_create_idp_refresh_token(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_refresh_token({"sub": "u1"}, priv)
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        payload = pyjwt.decode(token, pub, algorithms=["RS256"])
        assert payload["sub"] == "u1"

    def test_idp_token_not_verifiable_with_hs256_secret(self):
        priv, _ = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1"}, priv)
        with pytest.raises(pyjwt.PyJWTError):
            pyjwt.decode(token, "some-secret", algorithms=["HS256"])


class TestIdProviderConfig:
    def test_defaults(self):
        cfg = IdProviderConfig()
        assert cfg.enabled is False
        assert cfg.private_key is None
        assert cfg.jwks_path == "/.well-known/jwks.json"
        assert cfg.token_expiry == 2592000
        assert cfg.refresh_token_expiry == 7776000

    def test_resolve_idp_keypair_generates_ephemeral(self):
        cfg = IdProviderConfig(enabled=True)
        priv, pub = resolve_idp_keypair(cfg)
        assert priv
        assert pub
        # Second call reuses the same keypair
        priv2, pub2 = resolve_idp_keypair(cfg)
        assert priv == priv2
        assert pub == pub2

    def test_resolve_idp_keypair_with_provided_key(self):
        priv, pub = JwksService.generate_keypair()
        cfg = IdProviderConfig(enabled=True, private_key=priv)
        resolved_priv, resolved_pub = resolve_idp_keypair(cfg)
        assert resolved_priv == priv
        assert resolved_pub == pub

    def test_resolve_idp_keypair_derives_public_from_private(self):
        priv, _ = JwksService.generate_keypair()
        cfg = IdProviderConfig(enabled=True, private_key=priv)
        _, pub = resolve_idp_keypair(cfg)
        assert "BEGIN PUBLIC KEY" in pub


class TestResourceServerConfig:
    def test_defaults(self):
        cfg = ResourceServerConfig()
        assert cfg.enabled is False
        assert cfg.jwks_url == ""
        assert cfg.jwks_cache_ttl == 3600
        assert cfg.jwks_fetch_timeout == 5.0


class TestDecodeTokenWithJwks:
    async def test_decode_valid_token(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1", "email": "a@b.com"}, priv)

        # Build a local JWKS client that returns the key directly
        doc = JwksService.build_jwks_document(pub, kid="provisioner-key-1")

        class _LocalJwksClient:
            async def get_key(self, kid):
                return next((k for k in doc["keys"] if k["kid"] == kid), None)

            def invalidate_cache(self):
                pass

        payload = await decode_token_with_jwks(token, _LocalJwksClient())
        assert payload["sub"] == "u1"

    async def test_decode_verifies_issuer(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1"}, priv, issuer="https://auth.example.com")
        doc = JwksService.build_jwks_document(pub, kid="provisioner-key-1")

        class _LocalJwksClient:
            async def get_key(self, kid):
                return next((k for k in doc["keys"] if k["kid"] == kid), None)

            def invalidate_cache(self):
                pass

        payload = await decode_token_with_jwks(
            token, _LocalJwksClient(), expected_issuer="https://auth.example.com"
        )
        assert payload["sub"] == "u1"

    async def test_decode_rejects_wrong_issuer(self):
        priv, pub = JwksService.generate_keypair()
        token = create_idp_access_token({"sub": "u1"}, priv, issuer="https://other.com")
        doc = JwksService.build_jwks_document(pub, kid="provisioner-key-1")

        class _LocalJwksClient:
            async def get_key(self, kid):
                return next((k for k in doc["keys"] if k["kid"] == kid), None)

            def invalidate_cache(self):
                pass

        with pytest.raises(pyjwt.InvalidTokenError):
            await decode_token_with_jwks(
                token, _LocalJwksClient(), expected_issuer="https://expected.com"
            )

    async def test_decode_raises_on_missing_kid(self):
        priv, _ = JwksService.generate_keypair()
        # Create an HS256 token (no kid header)
        import jwt as pyjwt_inner, time
        token = pyjwt_inner.encode({"sub": "u1", "iat": int(time.time()), "exp": int(time.time()) + 900}, priv[:32], algorithm="HS256")

        class _LocalJwksClient:
            async def get_key(self, kid):
                return None

            def invalidate_cache(self):
                pass

        with pytest.raises((ValueError, pyjwt.PyJWTError)):
            await decode_token_with_jwks(token, _LocalJwksClient())
