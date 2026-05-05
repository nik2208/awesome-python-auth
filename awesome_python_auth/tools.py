"""AuthTools — telemetry, SSE notifications, and outgoing webhooks.

Mirrors the ``AuthTools`` class from awesome-node-auth.

All capabilities are optional and have zero overhead when disabled.

Usage::

    from awesome_python_auth.tools import AuthTools, TelemetryStore
    from awesome_python_auth.sse import SseManager
    from awesome_python_auth.webhooks import InMemoryWebhookStore

    sse = SseManager()
    webhook_store = InMemoryWebhookStore()
    tools = AuthTools(sse=sse, webhook_store=webhook_store)

    # Track an event
    await tools.track("identity.auth.login.success", data={"userId": "123"}, user_id="123")

    # Notify a topic over SSE
    await tools.notify("user:123", type="welcome", data={"message": "Hello!"})
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from .sse import SseManager
from .webhooks import OutgoingWebhookEvent, WebhookSender, WebhookStore


# ---------------------------------------------------------------------------
# Telemetry store
# ---------------------------------------------------------------------------


class TelemetryEvent:
    """A persisted telemetry / audit event."""

    def __init__(
        self,
        event: str,
        *,
        id: str | None = None,
        timestamp: str | None = None,
        data: Any = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        session_id: str | None = None,
        correlation_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.id = id or str(uuid.uuid4())
        self.event = event
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.data = data
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.correlation_id = correlation_id
        self.ip = ip
        self.user_agent = user_agent

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event": self.event,
            "timestamp": self.timestamp,
            "data": self.data,
            "userId": self.user_id,
            "tenantId": self.tenant_id,
            "sessionId": self.session_id,
            "correlationId": self.correlation_id,
            "ip": self.ip,
            "userAgent": self.user_agent,
        }


class TelemetryStore(ABC):
    """Abstract telemetry store.

    Implement to persist audit / telemetry events in any database.
    """

    @abstractmethod
    async def save(self, event: TelemetryEvent) -> None: ...

    async def query(
        self,
        *,
        event: str | None = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        """Optional query endpoint.  Implement for ``GET /tools/telemetry``."""
        return []


class InMemoryTelemetryStore(TelemetryStore):
    """Simple in-memory telemetry store — for testing and examples."""

    def __init__(self) -> None:
        self._events: list[TelemetryEvent] = []

    async def save(self, event: TelemetryEvent) -> None:
        self._events.append(event)

    async def query(
        self,
        *,
        event: str | None = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[dict[str, Any]]:
        results = self._events
        if event:
            results = [e for e in results if e.event == event]
        if user_id:
            results = [e for e in results if e.user_id == user_id]
        if tenant_id:
            results = [e for e in results if e.tenant_id == tenant_id]
        if from_dt:
            results = [e for e in results if e.timestamp >= from_dt.isoformat()]
        if to_dt:
            results = [e for e in results if e.timestamp <= to_dt.isoformat()]
        start = offset or 0
        end = start + limit if limit else None
        return [e.to_dict() for e in results[start:end]]


# ---------------------------------------------------------------------------
# AuthTools
# ---------------------------------------------------------------------------


class AuthTools:
    """Unified API for telemetry, SSE notifications, and outgoing webhooks.

    All arguments are optional.  Capabilities that are not configured have
    zero overhead.

    Parameters
    ----------
    sse:
        A :class:`~awesome_python_auth.sse.SseManager` instance.  When
        provided, ``track()`` broadcasts events to SSE subscribers.
    webhook_store:
        When provided, ``track()`` fires matching outgoing webhooks.
    telemetry_store:
        When provided, ``track()`` persists events.
    webhook_version:
        Version string attached to all outgoing webhook payloads.
    """

    def __init__(
        self,
        *,
        sse: SseManager | None = None,
        webhook_store: WebhookStore | None = None,
        telemetry_store: TelemetryStore | None = None,
        webhook_version: str = "1",
    ) -> None:
        self.sse = sse
        self._webhook_store = webhook_store
        self._telemetry_store = telemetry_store
        self._webhook_version = webhook_version
        self._webhook_sender = WebhookSender()

    # ---- Public API ---------------------------------------------------------

    async def track(
        self,
        event_name: str,
        *,
        data: Any = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        session_id: str | None = None,
        correlation_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Track an event: persist it, broadcast via SSE, and fire webhooks.

        All steps are best-effort — a failure in one does not abort others.
        """
        ev = TelemetryEvent(
            event_name,
            data=data,
            user_id=user_id,
            tenant_id=tenant_id,
            session_id=session_id,
            correlation_id=correlation_id,
            ip=ip,
            user_agent=user_agent,
        )

        # 1. Persist
        if self._telemetry_store:
            try:
                await self._telemetry_store.save(ev)
            except Exception:
                pass

        # 2. SSE broadcast
        if self.sse:
            topics = self._resolve_topics(user_id, tenant_id, session_id)
            for topic in topics:
                try:
                    self.sse.broadcast(
                        topic,
                        type=event_name,
                        data=ev.to_dict(),
                        user_id=user_id,
                        tenant_id=tenant_id,
                        event_id=ev.id,
                    )
                except Exception:
                    pass

        # 3. Outgoing webhooks
        if self._webhook_store:
            try:
                configs = await self._webhook_store.find_by_event(
                    event_name, tenant_id
                )
            except Exception:
                configs = []
            webhook_event = OutgoingWebhookEvent(
                event_name,
                data,
                version=self._webhook_version,
                metadata={
                    "userId": user_id,
                    "tenantId": tenant_id,
                    "sessionId": session_id,
                    "correlationId": correlation_id,
                },
            )
            for cfg in configs:
                import asyncio
                asyncio.create_task(
                    self._fire_webhook_best_effort(cfg, webhook_event)
                )

    async def notify(
        self,
        target: str,
        *,
        type: str = "notification",
        data: Any = None,
        user_id: str | None = None,
        tenant_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Send a notification to a single SSE topic.

        :param target: Target SSE topic (e.g. ``"user:123"``, ``"global"``).
        """
        if self.sse:
            self.sse.broadcast(
                target,
                type=type,
                data=data,
                user_id=user_id,
                tenant_id=tenant_id,
                metadata=metadata,
            )

    # ---- Helpers ------------------------------------------------------------

    def _resolve_topics(
        self,
        user_id: str | None,
        tenant_id: str | None,
        session_id: str | None,
    ) -> list[str]:
        topics: list[str] = ["global"]
        if tenant_id:
            topics.append(f"tenant:{tenant_id}")
        if user_id:
            topics.append(f"user:{user_id}")
        if session_id:
            topics.append(f"session:{session_id}")
        return topics

    async def _fire_webhook_best_effort(
        self,
        config: Any,
        event: OutgoingWebhookEvent,
    ) -> None:
        try:
            await self._webhook_sender.send(config, event)
        except Exception:
            pass
