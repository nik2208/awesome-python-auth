"""FastAPI tools router for awesome-python-auth.

Mirrors the ``createToolsRouter`` from awesome-node-auth.

Provides endpoints:
  POST   /tools/track/:event_name    — emit a telemetry event
  POST   /tools/notify/:target       — send an SSE notification
  GET    /tools/stream               — SSE event stream
  POST   /tools/webhook/:provider    — inbound webhook endpoint
  GET    /tools/telemetry            — query persisted events (optional)

Mount under any prefix::

    from awesome_python_auth.tools_router import build_tools_router

    tools = AuthTools(sse=SseManager(), ...)
    app.include_router(build_tools_router(tools), prefix="/api/tools")
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .tools import AuthTools, TelemetryStore
from .webhooks import WebhookStore


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_tools_router(
    tools: AuthTools,
    *,
    enable_telemetry: bool = True,
    enable_notify: bool = True,
    enable_stream: bool = True,
    enable_webhook: bool = True,
    telemetry_store: TelemetryStore | None = None,
    webhook_store: WebhookStore | None = None,
    on_webhook: (
        Callable[[str, Any, Request], Awaitable[dict[str, Any] | None]] | None
    ) = None,
    auth_dependency: Any = None,
    prefix: str = "",
) -> APIRouter:
    """Build and return a FastAPI ``APIRouter`` for the tools endpoints.

    Parameters
    ----------
    tools:
        An :class:`~awesome_python_auth.tools.AuthTools` instance.
    enable_telemetry:
        Enable ``POST /track/:event_name`` and ``GET /telemetry``.
    enable_notify:
        Enable ``POST /notify/:target``.
    enable_stream:
        Enable ``GET /stream`` (SSE).
    enable_webhook:
        Enable ``POST /webhook/:provider`` (inbound webhooks).
    telemetry_store:
        When provided together with ``enable_telemetry``, the
        ``GET /telemetry`` query endpoint is exposed.
    webhook_store:
        Used to look up inbound webhook configs (``jsScript``,
        ``allowedActions``).
    on_webhook:
        Async callback for inbound webhook processing.  Receives
        ``(provider, body, request)`` and should return
        ``{"event": str, "data": ..., "userId": ..., "tenantId": ...}`` or
        ``None`` to silently accept without forwarding.
    auth_dependency:
        Optional FastAPI dependency applied to write endpoints.
    prefix:
        URL prefix for all routes (without trailing slash).
    """

    router = APIRouter(prefix=prefix)
    protect = [Depends(auth_dependency)] if auth_dependency else []

    # ── POST /track/:event_name ───────────────────────────────────────────────
    if enable_telemetry:

        @router.post("/track/{event_name}", dependencies=protect)
        async def track_event(event_name: str, request: Request) -> dict:
            body: dict = await request.json() if await _has_body(request) else {}
            data = body.get("data")
            user_id = body.get("userId")
            tenant_id = body.get("tenantId")
            session_id = body.get("sessionId")
            correlation_id = body.get("correlationId")
            ip = (
                request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                or request.client.host
                if request.client
                else None
            )
            user_agent = request.headers.get("user-agent")
            await tools.track(
                event_name,
                data=data,
                user_id=user_id,
                tenant_id=tenant_id,
                session_id=session_id,
                correlation_id=correlation_id,
                ip=ip,
                user_agent=user_agent,
            )
            return {"ok": True}

    # ── POST /notify/:target ─────────────────────────────────────────────────
    if enable_notify:

        @router.post("/notify/{target}", dependencies=protect)
        async def notify(target: str, request: Request) -> dict:
            body: dict = await request.json() if await _has_body(request) else {}
            await tools.notify(
                target,
                type=body.get("type", "notification"),
                data=body.get("data"),
                user_id=body.get("userId"),
                tenant_id=body.get("tenantId"),
                metadata=body.get("metadata"),
            )
            return {"ok": True}

    # ── GET /stream ───────────────────────────────────────────────────────────
    if enable_stream:

        @router.get("/stream")
        async def stream(
            request: Request,
            topics: str | None = Query(None, description="Comma-separated topics"),
        ) -> StreamingResponse:
            if not tools.sse:
                raise HTTPException(status_code=503, detail="SSE not enabled")

            # Resolve authorised topics from request context
            user_id: str | None = None
            tenant_id: str | None = None
            # Pull user from request.state if set by auth middleware
            user = getattr(request.state, "user", None)
            if user:
                user_id = getattr(user, "sub", None) or getattr(user, "id", None)
                tenant_id = getattr(user, "tenant_id", None)

            authorised = ["global"]
            if tenant_id:
                authorised.append(f"tenant:{tenant_id}")
            if user_id:
                authorised.append(f"user:{user_id}")

            requested = (
                [t.strip() for t in topics.split(",") if t.strip()]
                if topics
                else []
            )
            final_topics = (
                [t for t in requested if t in authorised]
                if requested
                else authorised
            )

            conn = tools.sse.connect(
                final_topics, user_id=user_id, tenant_id=tenant_id
            )

            async def _disconnect_on_close() -> None:
                """Close the SSE connection when the client disconnects."""
                try:
                    await request.is_disconnected()
                except Exception:
                    pass
                finally:
                    tools.sse.disconnect(conn.id)

            import asyncio

            asyncio.create_task(_disconnect_on_close())

            return StreamingResponse(
                conn.__aiter__(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )

    # ── GET /telemetry ────────────────────────────────────────────────────────
    if enable_telemetry and telemetry_store is not None:

        @router.get("/telemetry", dependencies=protect)
        async def query_telemetry(
            event: str | None = None,
            user_id: str | None = Query(None, alias="userId"),
            tenant_id: str | None = Query(None, alias="tenantId"),
            from_date: str | None = Query(None, alias="from"),
            to_date: str | None = Query(None, alias="to"),
            limit: int = 50,
            offset: int = 0,
        ) -> dict:
            from datetime import datetime

            from_dt = datetime.fromisoformat(from_date) if from_date else None
            to_dt = datetime.fromisoformat(to_date) if to_date else None
            data = await telemetry_store.query(
                event=event,
                user_id=user_id,
                tenant_id=tenant_id,
                from_dt=from_dt,
                to_dt=to_dt,
                limit=limit,
                offset=offset,
            )
            return {"data": data}

    # ── POST /webhook/:provider ───────────────────────────────────────────────
    if enable_webhook and (on_webhook is not None or webhook_store is not None):

        @router.post("/webhook/{provider}")
        async def inbound_webhook(provider: str, request: Request) -> dict:
            body: Any = None
            try:
                body = await request.json()
            except Exception:
                body = {}

            result: dict[str, Any] | None = None

            # Dynamic script execution when webhook_store provides a jsScript
            if webhook_store is not None:
                try:
                    cfg = await webhook_store.find_by_provider(provider)
                except Exception:
                    cfg = None
                if cfg and cfg.js_script:
                    result = _run_script_sandbox(cfg, body)

            # Fallback to on_webhook callback
            if result is None and on_webhook is not None:
                try:
                    result = await on_webhook(provider, body, request)
                except Exception:
                    raise HTTPException(
                        status_code=400, detail="Webhook processing failed"
                    )

            if result and result.get("event"):
                await tools.track(
                    result["event"],
                    data=result.get("data"),
                    user_id=result.get("userId") or result.get("user_id"),
                    tenant_id=result.get("tenantId") or result.get("tenant_id"),
                )
            return {"ok": True}

    return router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _has_body(request: Request) -> bool:
    content_length = request.headers.get("content-length", "0")
    return int(content_length) > 0


def _run_script_sandbox(cfg: Any, body: Any) -> dict[str, Any] | None:
    """Execute a simple inbound webhook script in a restricted namespace.

    The script has access to ``body`` (the request payload) and must assign
    ``result`` to instruct the router what event to emit.

    .. warning::
        Python's built-in ``exec`` is used here, **not** a true sandbox.
        Only run scripts from trusted, admin-controlled sources.
        Do not expose this to untrusted user input.
    """
    namespace: dict[str, Any] = {"body": body, "result": None}
    try:
        exec(cfg.js_script, {"__builtins__": {}}, namespace)  # noqa: S102
    except Exception:
        return None
    result = namespace.get("result")
    if isinstance(result, dict) and isinstance(result.get("event"), str):
        return result
    return None
