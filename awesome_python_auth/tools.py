"""AuthTools — telemetry, SSE notifications, outgoing webhooks, and event bus.

Mirrors the ``AuthTools`` class from awesome-node-auth (>= 1.8.0).

All capabilities are optional and have zero overhead when disabled.

Usage::

    from awesome_python_auth.tools import AuthTools, TelemetryStore
    from awesome_python_auth.sse import SseManager
    from awesome_python_auth.webhooks import InMemoryWebhookStore
    from awesome_python_auth.events import AuthEventBus
    from awesome_python_auth.mailer import MailerConfig
    from awesome_python_auth.notification import SmsConfig

    bus = AuthEventBus()
    sse = SseManager()
    webhook_store = InMemoryWebhookStore()
    tools = AuthTools(
        event_bus=bus,
        sse=sse,
        webhook_store=webhook_store,
        email_config=MailerConfig(endpoint="...", api_key="...", from_address="..."),
        sms_config=SmsConfig(endpoint="...", api_key="...", username="...", password="..."),
    )

    # Track an event
    await tools.track("identity.auth.login.success", data={"userId": "123"}, user_id="123")

    # Notify a topic over SSE
    await tools.notify("user:123", type="welcome", data={"message": "Hello!"})

    # Notify via multiple channels
    await tools.notify(
        "user:123",
        type="alert",
        data={"message": "Subscription expiring"},
        user_id="123",
        channels=["sse", "email"],
        email_subject="Action required",
    )
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from .sse import SseManager
from .webhooks import OutgoingWebhookEvent, WebhookSender, WebhookStore

if TYPE_CHECKING:
    from .events import AuthEventBus
    from .mailer import MailerConfig
    from .notification import SmsConfig, NotificationService
    from .models import UserStore


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
    """Unified API for telemetry, SSE notifications, outgoing webhooks, and event bus.

    All arguments are optional.  Capabilities that are not configured have
    zero overhead.

    Parameters
    ----------
    sse:
        A :class:`~awesome_python_auth.sse.SseManager` instance.  When
        provided, ``track()`` broadcasts events to SSE subscribers and
        ``notify()`` with ``channels=['sse']`` (default) works.
    webhook_store:
        When provided, ``track()`` fires matching outgoing webhooks.
    telemetry_store:
        When provided, ``track()`` persists events.
    event_bus:
        A :class:`~awesome_python_auth.events.AuthEventBus` instance.
        When provided, ``track()`` publishes every event on the bus so
        external handlers (analytics, audit logging, etc.) can react without
        coupling to the auth flow.
    user_store:
        Required when ``notify()`` is called with ``'email'`` or ``'sms'``
        channels so the service can look up the user's contact details.
    email_config:
        :class:`~awesome_python_auth.mailer.MailerConfig` enabling the
        ``'email'`` channel in ``notify()``.
    sms_config:
        :class:`~awesome_python_auth.notification.SmsConfig` enabling the
        ``'sms'`` channel in ``notify()``.
    webhook_version:
        Version string attached to all outgoing webhook payloads.
    """

    def __init__(
        self,
        *,
        sse: SseManager | None = None,
        webhook_store: WebhookStore | None = None,
        telemetry_store: TelemetryStore | None = None,
        event_bus: "AuthEventBus | None" = None,
        user_store: "UserStore | None" = None,
        email_config: "MailerConfig | None" = None,
        sms_config: "SmsConfig | None" = None,
        webhook_version: str = "1",
    ) -> None:
        self.sse = sse
        self._webhook_store = webhook_store
        self._telemetry_store = telemetry_store
        self._webhook_version = webhook_version
        self._webhook_sender = WebhookSender()
        self.event_bus = event_bus
        self._user_store = user_store
        self._notification_service: NotificationService | None = None
        if email_config is not None or sms_config is not None:
            from .notification import NotificationService
            self._notification_service = NotificationService(
                email=email_config,
                sms=sms_config,
            )

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
        """Track an event: persist it, emit on the event bus, broadcast via SSE, and fire webhooks.

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

        # 2. Emit on the event bus
        if self.event_bus is not None:
            try:
                self.event_bus.publish(
                    event_name,
                    {
                        "data": data,
                        "userId": user_id,
                        "tenantId": tenant_id,
                        "sessionId": session_id,
                        "correlationId": correlation_id,
                        "ip": ip,
                        "userAgent": user_agent,
                        "timestamp": ev.timestamp,
                    },
                )
            except Exception:
                pass

        # 3. SSE broadcast
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

        # 4. Outgoing webhooks
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
        channels: list[str] | None = None,
        email_subject: str | None = None,
        sms_message: str | None = None,
    ) -> None:
        """Send a notification to one or more delivery channels.

        By default (or when *channels* is ``['sse']``) the behaviour is
        identical to the original synchronous SSE broadcast.  Pass additional
        channels to also deliver the notification via email and/or SMS.

        Parameters
        ----------
        target:
            Target SSE topic (e.g. ``'user:123'``, ``'global'``).
        type:
            Event type label.  Default: ``'notification'``.
        data:
            Payload to deliver.
        user_id:
            User ID for scoping.  Required when using ``'email'`` or ``'sms'``
            channels so the service can look up the user's contact details.
        tenant_id:
            Tenant ID for multi-tenant isolation.
        metadata:
            Arbitrary metadata dict attached to the SSE event.
        channels:
            Delivery channels.  Defaults to ``['sse']``.

            - ``'sse'``   — broadcast to SSE subscribers on the *target* topic.
            - ``'email'`` — send an email to the user identified by *user_id*
                           (requires ``user_store`` and ``email_config``).
            - ``'sms'``   — send an SMS to the user identified by *user_id*
                           (requires ``user_store`` and ``sms_config``).

            When multiple channels are listed all are attempted; a failure in
            one does **not** abort the others.
        email_subject:
            Email subject override.  Used when ``'email'`` is in *channels*.
            Defaults to the stringified *type* or ``'Notification'``.
        sms_message:
            SMS body override.  Used when ``'sms'`` is in *channels*.
            Defaults to ``str(data)``.
        """
        effective_channels: list[str] = channels if channels is not None else ["sse"]

        # ── 1. SSE ────────────────────────────────────────────────────────────
        if "sse" in effective_channels and self.sse:
            self.sse.broadcast(
                target,
                type=type,
                data=data,
                user_id=user_id,
                tenant_id=tenant_id,
                metadata=metadata,
            )

        # ── 2. Email / SMS ────────────────────────────────────────────────────
        needs_contact = "email" in effective_channels or "sms" in effective_channels
        if needs_contact and user_id and self._user_store and self._notification_service:
            user = None
            try:
                user = await self._user_store.get_by_id(user_id)
            except Exception:
                pass

            if user is not None:
                # ── 2a. Email ────────────────────────────────────────────────
                if (
                    "email" in effective_channels
                    and self._notification_service.has_email
                    and getattr(user, "email", None)
                ):
                    from .notification import SendEmailOptions
                    subject = email_subject or (str(type) if type != "notification" else "Notification")
                    body = str(data) if not isinstance(data, str) else data
                    try:
                        await self._notification_service.send_email(
                            SendEmailOptions(
                                to=user.email,
                                subject=subject,
                                html=f"<p>{body}</p>",
                                text=body,
                            )
                        )
                    except Exception:
                        pass

                # ── 2b. SMS ───────────────────────────────────────────────────
                if (
                    "sms" in effective_channels
                    and self._notification_service.has_sms
                    and getattr(user, "phone_number", None)
                ):
                    from .notification import SendSmsOptions
                    message = sms_message or (
                        data if isinstance(data, str) else str(data)
                    )
                    try:
                        await self._notification_service.send_sms(
                            SendSmsOptions(to=user.phone_number, message=message)
                        )
                    except Exception:
                        pass

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
