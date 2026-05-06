"""Tests for the tools module (AuthTools)."""
from __future__ import annotations

import pytest

from awesome_python_auth.events import AuthEventBus
from awesome_python_auth.sse import SseManager
from awesome_python_auth.tools import AuthTools, InMemoryTelemetryStore
from awesome_python_auth.webhooks import InMemoryWebhookStore, WebhookConfig


class TestAuthTools:
    async def test_track_persists_event(self):
        store = InMemoryTelemetryStore()
        tools = AuthTools(telemetry_store=store)
        await tools.track("user.login", data={"userId": "abc"}, user_id="abc")
        results = await store.query(event="user.login")
        assert len(results) == 1
        assert results[0]["event"] == "user.login"

    async def test_track_broadcasts_sse(self):
        sse = SseManager(heartbeat_interval_ms=0)
        tools = AuthTools(sse=sse)
        conn = sse.connect(["global"])
        await tools.track("test.event", user_id="u1")
        assert not conn._queue.empty()

    async def test_notify_sse(self):
        sse = SseManager(heartbeat_interval_ms=0)
        tools = AuthTools(sse=sse)
        conn = sse.connect(["user:42"], user_id="42")
        await tools.notify("user:42", type="msg", data={"text": "hi"}, user_id="42")
        assert not conn._queue.empty()

    async def test_track_without_stores_no_error(self):
        tools = AuthTools()
        # Should not raise
        await tools.track("some.event")

    async def test_telemetry_query(self):
        store = InMemoryTelemetryStore()
        tools = AuthTools(telemetry_store=store)
        await tools.track("login", user_id="u1")
        await tools.track("logout", user_id="u1")
        await tools.track("login", user_id="u2")
        results = await store.query(event="login")
        assert len(results) == 2
        results_u1 = await store.query(user_id="u1")
        assert len(results_u1) == 2

    async def test_track_publishes_to_event_bus(self):
        bus = AuthEventBus()
        received = []
        bus.on_event("identity.auth.login.success", lambda p: received.append(p))
        tools = AuthTools(event_bus=bus)
        await tools.track("identity.auth.login.success", user_id="u1")
        assert len(received) == 1
        assert received[0]["userId"] == "u1"

    async def test_track_publishes_to_wildcard(self):
        bus = AuthEventBus()
        all_events = []
        bus.on_event("*", lambda p: all_events.append(p["event"]))
        tools = AuthTools(event_bus=bus)
        await tools.track("event.a")
        await tools.track("event.b")
        assert "event.a" in all_events
        assert "event.b" in all_events

    async def test_notify_sse_channel_explicit(self):
        sse = SseManager(heartbeat_interval_ms=0)
        tools = AuthTools(sse=sse)
        conn = sse.connect(["user:7"])
        await tools.notify("user:7", data={"x": 1}, channels=["sse"])
        assert not conn._queue.empty()

    async def test_notify_no_sse_when_channel_not_sse(self):
        sse = SseManager(heartbeat_interval_ms=0)
        tools = AuthTools(sse=sse)
        conn = sse.connect(["user:8"])
        # only sms channel — sse not included
        await tools.notify("user:8", data={"x": 1}, channels=["sms"])
        assert conn._queue.empty()

    async def test_notify_multichannel_no_error_when_missing_config(self):
        """Multi-channel notify should not raise even when transports are missing."""
        tools = AuthTools()
        # Should not raise
        await tools.notify("user:9", data={"x": 1}, channels=["sse", "email", "sms"])

