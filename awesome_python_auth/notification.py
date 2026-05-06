"""Notification service for awesome-python-auth.

Mirrors the ``NotificationService``, ``SmsService``, and related types from
awesome-node-auth (>= 1.8.0).

Provides a thin, transport-agnostic wrapper around the built-in
:class:`~awesome_python_auth.mailer.MailerService` and :class:`SmsService`
so that business-level notifications (e.g. "your subscription will expire in
3 days") can be sent over the same transports already configured for auth
flows — without coupling ``AuthTools`` to the full ``AuthConfig``.

Usage::

    from awesome_python_auth.notification import (
        NotificationService,
        SmsConfig,
        SendEmailOptions,
        SendSmsOptions,
    )
    from awesome_python_auth.mailer import MailerConfig

    service = NotificationService(
        email=MailerConfig(
            endpoint="https://mailer.example.com/send",
            api_key="key",
            from_address="no-reply@example.com",
        ),
        sms=SmsConfig(
            endpoint="https://sms.example.com/send",
            api_key="sms-key",
            username="user",
            password="pass",
        ),
    )

    await service.send_email(SendEmailOptions(
        to="alice@example.com",
        subject="Hello",
        html="<p>Hi Alice!</p>",
    ))

    await service.send_sms(SendSmsOptions(
        to="+15551234567",
        message="Your OTP is 123456",
    ))
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from .mailer import MailerConfig, MailerService


# ---------------------------------------------------------------------------
# SMS config & service
# ---------------------------------------------------------------------------


@dataclass
class SmsConfig:
    """Configuration for the SMS transport.

    Uses the same shape as ``AuthConfig.sms`` (in awesome-node-auth).

    The SMS service performs a ``GET`` to *endpoint* with query parameters:
    ``username``, ``password``, ``phone``, and ``message``.  The ``X-API-Key``
    header is added when *api_key* is set.
    """

    endpoint: str = ""
    api_key: str = ""
    username: str = ""
    password: str = ""
    code_expires_in_minutes: int = 5


class SmsService:
    """Sends SMS messages via an HTTP GET gateway.

    Mirrors ``SmsService`` from awesome-node-auth.
    """

    def __init__(self, config: SmsConfig) -> None:
        self._cfg = config

    async def send_sms(self, phone: str, message: str) -> None:
        """Send *message* to *phone*.  Raises :class:`httpx.HTTPError` on failure."""
        if not self._cfg.endpoint:
            return  # no transport configured — silently skip

        params: dict[str, str] = {
            "username": self._cfg.username,
            "password": self._cfg.password,
            "phone": phone,
            "message": message,
        }
        headers: dict[str, str] = {}
        if self._cfg.api_key:
            headers["X-API-Key"] = self._cfg.api_key

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._cfg.endpoint,
                params=params,
                headers=headers,
                timeout=10.0,
            )
            resp.raise_for_status()

    @staticmethod
    def generate_code(digits: int = 6) -> str:
        """Generate a random numeric OTP code."""
        lo = 10 ** (digits - 1)
        hi = (10 ** digits) - 1
        return str(random.randint(lo, hi))


# ---------------------------------------------------------------------------
# Notification options
# ---------------------------------------------------------------------------


@dataclass
class SendEmailOptions:
    """Options for :meth:`NotificationService.send_email`."""

    to: str
    """Recipient email address."""

    subject: str
    """Email subject line."""

    html: str
    """HTML body."""

    text: str | None = None
    """Plain-text fallback body. Defaults to *html* when omitted."""


@dataclass
class SendSmsOptions:
    """Options for :meth:`NotificationService.send_sms`."""

    to: str
    """Recipient phone number (E.164 format recommended)."""

    message: str
    """SMS message body."""


# ---------------------------------------------------------------------------
# NotificationService
# ---------------------------------------------------------------------------


class NotificationService:
    """Thin facade that exposes email and SMS sending without the full config.

    Intended for use with :meth:`~awesome_python_auth.tools.AuthTools.notify`
    when ``'email'`` or ``'sms'`` channels are requested.

    Parameters
    ----------
    email:
        A :class:`~awesome_python_auth.mailer.MailerConfig` instance.
        When provided, :meth:`send_email` becomes available.
    sms:
        A :class:`SmsConfig` instance.
        When provided, :meth:`send_sms` becomes available.
    """

    def __init__(
        self,
        *,
        email: "MailerConfig | None" = None,
        sms: SmsConfig | None = None,
    ) -> None:
        self._mailer: MailerService | None = None
        self._sms: SmsService | None = None

        if email is not None:
            from .mailer import MailerService
            self._mailer = MailerService(email)

        if sms is not None:
            self._sms = SmsService(sms)

    # ---- Public API ----------------------------------------------------------

    async def send_email(self, opts: SendEmailOptions) -> None:
        """Send a custom email notification.

        :raises RuntimeError: when no email transport is configured.
        """
        if self._mailer is None:
            raise RuntimeError(
                "[NotificationService] No email transport configured.  "
                "Pass an email MailerConfig to the constructor."
            )
        text = opts.text or opts.html
        await self._mailer.send_custom(opts.to, opts.subject, opts.html, text)

    async def send_sms(self, opts: SendSmsOptions) -> None:
        """Send a custom SMS notification.

        :raises RuntimeError: when no SMS transport is configured.
        """
        if self._sms is None:
            raise RuntimeError(
                "[NotificationService] No SMS transport configured.  "
                "Pass a SmsConfig to the constructor."
            )
        await self._sms.send_sms(opts.to, opts.message)

    # ---- Capabilities --------------------------------------------------------

    @property
    def has_email(self) -> bool:
        """``True`` when an email transport is configured."""
        return self._mailer is not None

    @property
    def has_sms(self) -> bool:
        """``True`` when an SMS transport is configured."""
        return self._sms is not None
