"""Tests for the sse module."""
from __future__ import annotations

import asyncio
import json
import pytest

from awesome_python_auth.sse import SseManager, StreamEvent


class TestSseManager:
    def test_connect_returns_connection(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["global"])
        assert conn.id in mgr._connections
        assert mgr.connection_count == 1

    def test_disconnect_removes_connection(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["global"])
        mgr.disconnect(conn.id)
        assert mgr.connection_count == 0

    def test_broadcast_to_subscribed_topic(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["global"])
        mgr.broadcast("global", type="ping", data={"hello": "world"})
        assert not conn._queue.empty()

    def test_broadcast_to_unsubscribed_topic_ignored(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["global"])
        mgr.broadcast("user:999", type="private", data={})
        assert conn._queue.empty()

    def test_tenant_isolation(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn_a = mgr.connect(["global", "tenant:a"], tenant_id="a")
        conn_b = mgr.connect(["global", "tenant:b"], tenant_id="b")
        # Broadcast for tenant b — conn_a should NOT receive it
        mgr.broadcast("global", type="evt", data={}, tenant_id="b")
        assert conn_a._queue.empty()
        assert not conn_b._queue.empty()

    def test_deduplicate(self):
        mgr = SseManager(heartbeat_interval_ms=0, deduplicate=True)
        conn = mgr.connect(["global"])
        mgr.broadcast("global", type="evt", data={}, event_id="abc")
        mgr.broadcast("global", type="evt", data={}, event_id="abc")
        assert conn._queue.qsize() == 1

    def test_notify_user_helper(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["user:42"], user_id="42")
        mgr.notify_user("42", type="msg", data={"text": "hi"})
        assert not conn._queue.empty()

    def test_close_all(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        mgr.connect(["global"])
        mgr.connect(["global"])
        mgr.close_all()
        assert mgr.connection_count == 0

    async def test_connected_event_emitted(self):
        mgr = SseManager(heartbeat_interval_ms=0)
        conn = mgr.connect(["global"])
        # Pull the first event from the connection
        it = conn.__aiter__()
        raw = await asyncio.wait_for(it.__anext__(), timeout=1.0)
        assert "connected" in raw
