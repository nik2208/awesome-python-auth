"""Tests for the AuthEventBus and AuthEventNames."""
from __future__ import annotations

import asyncio
import pytest

from awesome_python_auth.events import AuthEventBus, AuthEventNames


class TestAuthEventNames:
    def test_has_login_success(self):
        assert AuthEventNames.AUTH_LOGIN_SUCCESS == "identity.auth.login.success"

    def test_has_user_created(self):
        assert AuthEventNames.USER_CREATED == "identity.user.created"

    def test_has_session_events(self):
        assert AuthEventNames.SESSION_CREATED == "identity.session.created"
        assert AuthEventNames.SESSION_REVOKED == "identity.session.revoked"

    def test_has_role_events(self):
        assert AuthEventNames.ROLE_ASSIGNED == "identity.role.assigned"
        assert AuthEventNames.ROLE_REVOKED == "identity.role.revoked"


class TestAuthEventBus:
    def test_on_event_and_publish(self):
        bus = AuthEventBus()
        received = []
        bus.on_event("test.event", lambda p: received.append(p))
        bus.publish("test.event", {"userId": "u1"})
        assert len(received) == 1
        assert received[0]["event"] == "test.event"
        assert received[0]["userId"] == "u1"
        assert "timestamp" in received[0]

    def test_wildcard_receives_all(self):
        bus = AuthEventBus()
        all_events = []
        bus.on_event("*", lambda p: all_events.append(p["event"]))
        bus.publish("event.a", {})
        bus.publish("event.b", {})
        assert all_events == ["event.a", "event.b"]

    def test_specific_handler_not_called_for_other_events(self):
        bus = AuthEventBus()
        received = []
        bus.on_event("event.a", lambda p: received.append(p))
        bus.publish("event.b", {})
        assert len(received) == 0

    def test_off_event_stops_delivery(self):
        bus = AuthEventBus()
        received = []

        def handler(p):
            received.append(p)

        bus.on_event("my.event", handler)
        bus.publish("my.event", {})
        bus.off_event("my.event", handler)
        bus.publish("my.event", {})
        assert len(received) == 1

    def test_multiple_listeners_same_event(self):
        bus = AuthEventBus()
        a, b = [], []
        bus.on_event("ev", lambda p: a.append(1))
        bus.on_event("ev", lambda p: b.append(1))
        bus.publish("ev", {})
        assert len(a) == 1
        assert len(b) == 1

    def test_handler_exception_does_not_propagate(self):
        bus = AuthEventBus()
        called = []

        def bad(p):
            raise RuntimeError("oops")

        def good(p):
            called.append(1)

        bus.on_event("ev", bad)
        bus.on_event("ev", good)
        bus.publish("ev", {})
        # good handler should still have been called
        assert len(called) == 1

    async def test_async_handler(self):
        bus = AuthEventBus()
        received = []

        async def async_handler(p):
            await asyncio.sleep(0)
            received.append(p["event"])

        bus.on_event("async.ev", async_handler)
        bus.publish("async.ev", {"foo": "bar"})
        # Allow the scheduled task to run
        await asyncio.sleep(0.05)
        assert "async.ev" in received

    def test_timestamp_injected(self):
        bus = AuthEventBus()
        received = []
        bus.on_event("ts.ev", lambda p: received.append(p))
        bus.publish("ts.ev", {})
        assert received[0]["timestamp"]

    def test_existing_timestamp_preserved(self):
        bus = AuthEventBus()
        received = []
        bus.on_event("ts.ev", lambda p: received.append(p))
        bus.publish("ts.ev", {"timestamp": "2024-01-01T00:00:00+00:00"})
        assert received[0]["timestamp"] == "2024-01-01T00:00:00+00:00"

    def test_chaining(self):
        bus = AuthEventBus()
        result = bus.on_event("ev", lambda p: None)
        assert result is bus
        result2 = bus.off_event("ev", lambda p: None)
        assert result2 is bus
