"""Tests for the webhooks module."""
from __future__ import annotations

import json
import pytest

from awesome_python_auth.webhooks import (
    InMemoryWebhookStore,
    OutgoingWebhookEvent,
    WebhookConfig,
    WebhookSender,
    _build_signature,
)


class TestInMemoryWebhookStore:
    async def test_add_and_find_by_event(self):
        store = InMemoryWebhookStore()
        cfg = WebhookConfig(url="https://example.com/hook", events=["user.login"])
        await store.add(cfg)
        results = await store.find_by_event("user.login")
        assert len(results) == 1

    async def test_wildcard_event_matches_all(self):
        store = InMemoryWebhookStore()
        cfg = WebhookConfig(url="https://example.com/hook", events=["*"])
        await store.add(cfg)
        assert len(await store.find_by_event("anything")) == 1

    async def test_inactive_config_excluded(self):
        store = InMemoryWebhookStore()
        cfg = WebhookConfig(url="https://example.com/hook", events=["*"], is_active=False)
        await store.add(cfg)
        assert len(await store.find_by_event("anything")) == 0

    async def test_find_by_provider(self):
        store = InMemoryWebhookStore()
        cfg = WebhookConfig(url="", events=[], provider="stripe")
        await store.add(cfg)
        found = await store.find_by_provider("stripe")
        assert found is not None
        assert found.provider == "stripe"
        assert await store.find_by_provider("paypal") is None

    async def test_remove(self):
        store = InMemoryWebhookStore()
        cfg = WebhookConfig(url="https://example.com", events=["*"])
        await store.add(cfg)
        await store.remove(cfg.id)
        assert len(await store.list_all()) == 0

    async def test_tenant_isolation(self):
        store = InMemoryWebhookStore()
        cfg_global = WebhookConfig(url="https://a.com", events=["*"])
        cfg_tenant_a = WebhookConfig(url="https://b.com", events=["*"], tenant_id="a")
        cfg_tenant_b = WebhookConfig(url="https://c.com", events=["*"], tenant_id="b")
        await store.add(cfg_global)
        await store.add(cfg_tenant_a)
        await store.add(cfg_tenant_b)
        results = await store.find_by_event("evt", tenant_id="a")
        urls = {c.url for c in results}
        assert "https://a.com" in urls
        assert "https://b.com" in urls
        assert "https://c.com" not in urls


class TestOutgoingWebhookEvent:
    def test_to_dict(self):
        ev = OutgoingWebhookEvent("user.login", {"id": "1"})
        d = ev.to_dict()
        assert d["event"] == "user.login"
        assert d["data"] == {"id": "1"}
        assert "timestamp" in d
        assert d["version"] == "1"


class TestSignature:
    def test_hmac_sha256(self):
        sig = _build_signature('{"event":"test"}', "secret")
        assert len(sig) == 64  # hex-encoded SHA-256
        assert all(c in "0123456789abcdef" for c in sig)
