"""Outgoing webhook sender and store interface for awesome-python-auth.

Mirrors the ``IWebhookStore``, ``OutgoingWebhookEvent``, and
``WebhookSender`` from awesome-node-auth.

Outgoing webhooks are fired when events are tracked via :class:`AuthTools`.
Inbound webhooks (``POST /tools/webhook/:provider``) are handled in the
tools router.

Usage::

    from awesome_python_auth.webhooks import (
        WebhookConfig, WebhookStore, InMemoryWebhookStore, WebhookSender,
    )
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class WebhookConfig:
    """Configuration for a single outgoing or inbound webhook."""

    def __init__(
        self,
        *,
        id: str | None = None,
        url: str = "",
        events: list[str] | None = None,
        secret: str | None = None,
        is_active: bool = True,
        tenant_id: str | None = None,
        max_retries: int = 3,
        retry_delay_ms: int = 1000,
        provider: str | None = None,
        allowed_actions: list[str] | None = None,
        js_script: str | None = None,
    ) -> None:
        self.id: str = id or str(uuid.uuid4())
        self.url = url
        self.events: list[str] = events or []
        self.secret = secret
        self.is_active = is_active
        self.tenant_id = tenant_id
        self.max_retries = max_retries
        self.retry_delay_ms = retry_delay_ms
        self.provider = provider
        self.allowed_actions: list[str] = allowed_actions or []
        self.js_script = js_script

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "events": self.events,
            "isActive": self.is_active,
            "tenantId": self.tenant_id,
            "maxRetries": self.max_retries,
            "retryDelayMs": self.retry_delay_ms,
            "provider": self.provider,
            "allowedActions": self.allowed_actions,
        }


class OutgoingWebhookEvent:
    """Payload POSTed to a webhook endpoint."""

    def __init__(
        self,
        event: str,
        data: Any,
        *,
        version: str = "1",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.event = event
        self.version = version
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.data = data
        self.metadata = metadata or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "version": self.version,
            "timestamp": self.timestamp,
            "data": self.data,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Store interface + in-memory implementation
# ---------------------------------------------------------------------------


class WebhookStore(ABC):
    """Abstract store for webhook configurations."""

    @abstractmethod
    async def find_by_event(
        self, event: str, tenant_id: str | None = None
    ) -> list[WebhookConfig]:
        """Return active configs that match *event* (and optionally *tenant_id*)."""
        ...

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[WebhookConfig]:
        return []

    async def add(self, config: WebhookConfig) -> WebhookConfig:
        raise NotImplementedError

    async def remove(self, webhook_id: str) -> None:
        raise NotImplementedError

    async def update(
        self, webhook_id: str, changes: dict[str, Any]
    ) -> None:
        raise NotImplementedError

    async def find_by_provider(
        self, provider: str
    ) -> WebhookConfig | None:
        return None


class InMemoryWebhookStore(WebhookStore):
    """Simple in-memory webhook store — for testing and examples."""

    def __init__(self) -> None:
        self._configs: dict[str, WebhookConfig] = {}

    async def find_by_event(
        self, event: str, tenant_id: str | None = None
    ) -> list[WebhookConfig]:
        result = []
        for cfg in self._configs.values():
            if not cfg.is_active:
                continue
            if tenant_id and cfg.tenant_id and cfg.tenant_id != tenant_id:
                continue
            if "*" in cfg.events or event in cfg.events:
                result.append(cfg)
        return result

    async def list_all(
        self, limit: int = 100, offset: int = 0
    ) -> list[WebhookConfig]:
        items = list(self._configs.values())
        return items[offset : offset + limit]

    async def add(self, config: WebhookConfig) -> WebhookConfig:
        self._configs[config.id] = config
        return config

    async def remove(self, webhook_id: str) -> None:
        self._configs.pop(webhook_id, None)

    async def update(self, webhook_id: str, changes: dict[str, Any]) -> None:
        cfg = self._configs.get(webhook_id)
        if not cfg:
            return
        for key, value in changes.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)

    async def find_by_provider(self, provider: str) -> WebhookConfig | None:
        return next(
            (c for c in self._configs.values() if c.provider == provider),
            None,
        )


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------


def _build_signature(body: str, secret: str) -> str:
    """Compute HMAC-SHA256 signature for webhook request signing."""
    return hmac.new(
        secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()


class WebhookSender:
    """Sends outgoing webhook events with retry + optional HMAC signing."""

    async def send(
        self,
        config: WebhookConfig,
        event: OutgoingWebhookEvent,
    ) -> None:
        """Fire *event* to *config.url* with exponential back-off retries."""
        payload_dict = event.to_dict()
        body_str = json.dumps(payload_dict)
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if config.secret:
            sig = _build_signature(body_str, config.secret)
            headers["X-Webhook-Signature"] = f"sha256={sig}"

        delay = config.retry_delay_ms / 1000.0
        last_exc: Exception | None = None
        async with httpx.AsyncClient() as client:
            for attempt in range(max(1, config.max_retries)):
                if attempt > 0:
                    import asyncio
                    await asyncio.sleep(delay)
                    delay *= 2
                try:
                    resp = await client.post(
                        config.url,
                        content=body_str,
                        headers=headers,
                        timeout=10.0,
                    )
                    if resp.is_success:
                        return
                    last_exc = RuntimeError(
                        f"Webhook delivery failed: HTTP {resp.status_code}"
                    )
                except Exception as exc:
                    last_exc = exc
        # Best-effort — don't raise after all retries are exhausted
        if last_exc:
            import logging
            logging.getLogger(__name__).warning(
                "Webhook to %s failed after %d attempts: %s",
                config.url,
                config.max_retries,
                last_exc,
            )
