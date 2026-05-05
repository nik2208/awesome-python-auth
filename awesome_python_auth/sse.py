"""Server-Sent Events (SSE) manager for awesome-python-auth.

Mirrors the ``SseManager`` from awesome-node-auth.

The manager tracks open HTTP/async generator connections and broadcasts
:class:`StreamEvent` objects to all subscribers matching a given topic.
Topics follow a hierarchical scheme::

    global
    tenant:{tenantId}
    user:{userId}
    session:{sessionId}

The server controls which topics a connection may subscribe to — clients
cannot self-declare channels.

Usage (FastAPI)::

    from awesome_python_auth.sse import SseManager
    from fastapi.responses import StreamingResponse

    sse = SseManager()

    @app.get("/stream")
    async def stream(user = Depends(require_auth)):
        topics = ["global", f"user:{user.sub}"]
        return StreamingResponse(
            sse.connect(topics),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Elsewhere — broadcast an event
    sse.broadcast("global", {"type": "ping", "data": {}})
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class StreamEvent:
    """A single real-time SSE event delivered to subscribers."""

    def __init__(
        self,
        *,
        type: str,
        data: Any,
        id: str | None = None,
        timestamp: str | None = None,
        topic: str = "global",
        user_id: str | None = None,
        tenant_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.id = id or str(uuid.uuid4())
        self.type = type
        self.data = data
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.topic = topic
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.metadata = metadata

    def to_sse_bytes(self) -> str:
        payload = {
            "id": self.id,
            "type": self.type,
            "timestamp": self.timestamp,
            "topic": self.topic,
            "data": self.data,
        }
        if self.user_id:
            payload["userId"] = self.user_id
        if self.tenant_id:
            payload["tenantId"] = self.tenant_id
        if self.metadata:
            payload["metadata"] = self.metadata
        return f"id: {self.id}\nevent: {self.type}\ndata: {json.dumps(payload)}\n\n"


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------


class _SseConnection:
    def __init__(
        self,
        topics: list[str],
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
        heartbeat_interval: float = 30.0,
    ) -> None:
        self.id = str(uuid.uuid4())
        self.topics: set[str] = set(topics)
        self.user_id = user_id
        self.tenant_id = tenant_id
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._heartbeat_interval = heartbeat_interval
        self._last_event_id: str | None = None

    def enqueue(self, raw: str, event_id: str) -> None:
        # Deduplicate by event ID
        if event_id == self._last_event_id:
            return
        self._last_event_id = event_id
        try:
            self._queue.put_nowait(raw)
        except asyncio.QueueFull:
            pass

    def close(self) -> None:
        try:
            self._queue.put_nowait(None)  # sentinel
        except asyncio.QueueFull:
            pass

    async def __aiter__(self) -> AsyncGenerator[str, None]:
        """Yield SSE-formatted strings, including periodic heartbeats."""
        # Send initial connected event
        connected = StreamEvent(
            type="connected",
            data={"connectionId": self.id, "topics": list(self.topics)},
            topic="meta",
        )
        yield connected.to_sse_bytes()

        while True:
            try:
                raw = await asyncio.wait_for(
                    self._queue.get(), timeout=self._heartbeat_interval
                )
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
                continue
            if raw is None:  # sentinel → close
                return
            yield raw


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SseManager:
    """Manages SSE connections and broadcasts events to topic subscribers.

    This is a single-process implementation.  For multi-instance deployments,
    run a shared message broker (Redis pub/sub, etc.) and forward messages to
    :meth:`broadcast_local`.
    """

    def __init__(
        self,
        *,
        heartbeat_interval_ms: int = 30_000,
        deduplicate: bool = True,
    ) -> None:
        self._connections: dict[str, _SseConnection] = {}
        self._heartbeat_interval = heartbeat_interval_ms / 1000.0
        self._deduplicate = deduplicate

    # ---- Connection management -----------------------------------------------

    def connect(
        self,
        topics: list[str],
        *,
        user_id: str | None = None,
        tenant_id: str | None = None,
    ) -> _SseConnection:
        """Create and register a new SSE connection.

        Returns a :class:`_SseConnection` that is async-iterable and yields
        SSE-formatted strings.  Pass it directly to
        :class:`fastapi.responses.StreamingResponse`.
        """
        conn = _SseConnection(
            topics,
            user_id=user_id,
            tenant_id=tenant_id,
            heartbeat_interval=self._heartbeat_interval,
        )
        self._connections[conn.id] = conn
        return conn

    def disconnect(self, connection_id: str) -> None:
        """Close and remove a connection by its ID."""
        conn = self._connections.pop(connection_id, None)
        if conn:
            conn.close()

    @property
    def connection_count(self) -> int:
        """Number of currently open connections."""
        return len(self._connections)

    # ---- Broadcasting --------------------------------------------------------

    def broadcast(
        self,
        topic: str,
        *,
        type: str,
        data: Any,
        user_id: str | None = None,
        tenant_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        event_id: str | None = None,
    ) -> None:
        """Broadcast an event to all connections subscribed to *topic*.

        Tenant isolation is enforced: if the event carries a *tenant_id* and a
        connection belongs to a different tenant, it will not receive the event.
        """
        event = StreamEvent(
            type=type,
            data=data,
            id=event_id,
            topic=topic,
            user_id=user_id,
            tenant_id=tenant_id,
            metadata=metadata,
        )
        raw = event.to_sse_bytes()
        dead: list[str] = []
        for conn in list(self._connections.values()):
            if topic not in conn.topics:
                continue
            if tenant_id and conn.tenant_id and conn.tenant_id != tenant_id:
                continue
            try:
                conn.enqueue(raw, event.id)
            except Exception:
                dead.append(conn.id)
        for cid in dead:
            self._connections.pop(cid, None)

    def broadcast_local(self, topic: str, event: StreamEvent) -> None:
        """Broadcast a pre-built :class:`StreamEvent` to local connections."""
        raw = event.to_sse_bytes()
        for conn in list(self._connections.values()):
            if topic not in conn.topics:
                continue
            if event.tenant_id and conn.tenant_id and conn.tenant_id != event.tenant_id:
                continue
            conn.enqueue(raw, event.id)

    def notify_user(self, user_id: str, type: str, data: Any) -> None:
        """Convenience helper — broadcast to the ``user:{user_id}`` topic."""
        self.broadcast(f"user:{user_id}", type=type, data=data, user_id=user_id)

    def close_all(self) -> None:
        """Close all open connections (e.g. on server shutdown)."""
        for conn in list(self._connections.values()):
            conn.close()
        self._connections.clear()
