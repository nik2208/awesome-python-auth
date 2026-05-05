"""Tests for the built-in mailer templates."""
from __future__ import annotations

import pytest

from awesome_python_auth.mailer import MailerConfig, MailerService


class FakeTemplateStore:
    """Simulates a database template store for testing."""

    def __init__(self, tpl: dict | None = None):
        self._tpl = tpl

    async def get_mail_template(self, template_id: str) -> dict | None:
        return self._tpl


@pytest.fixture
def svc() -> MailerService:
    """MailerService with no endpoint (sends are skipped)."""
    return MailerService(MailerConfig())


class TestBuiltinTemplates:
    async def test_password_reset_en(self, svc):
        # No real send — just ensure render produces a valid dict
        # Patch _send to capture
        calls = []

        async def _fake_send(to, *, subject, html, text):
            calls.append({"to": to, "subject": subject, "html": html, "text": text})

        svc._send = _fake_send
        await svc.send_password_reset("user@example.com", "tok", "https://example.com/reset")
        assert len(calls) == 1
        assert "reset" in calls[0]["subject"].lower()
        assert "https://example.com/reset" in calls[0]["html"]

    async def test_password_reset_it(self, svc):
        calls = []

        async def _fake_send(to, *, subject, html, text):
            calls.append({"subject": subject})

        svc._send = _fake_send
        await svc.send_password_reset(
            "u@e.com", "tok", "https://example.com/reset", lang="it"
        )
        assert "password" in calls[0]["subject"].lower()

    async def test_magic_link_en(self, svc):
        calls = []
        svc._send = lambda *a, **kw: calls.append(kw) or _noop()

        async def _fake(to, *, subject, html, text):
            calls.append({"subject": subject, "html": html})

        svc._send = _fake
        await svc.send_magic_link("u@e.com", "tok", "https://example.com/ml")
        assert "magic" in calls[0]["subject"].lower() or "sign" in calls[0]["subject"].lower()

    async def test_verify_email_en(self, svc):
        calls = []

        async def _fake(to, *, subject, html, text):
            calls.append({"subject": subject, "html": html})

        svc._send = _fake
        await svc.send_verification_email("u@e.com", "tok", "https://example.com/verify")
        assert "verif" in calls[0]["subject"].lower()
        assert "https://example.com/verify" in calls[0]["html"]

    async def test_custom_template_store_override(self):
        tpl = {
            "baseHtml": "<p>Hello {{USER_NAME}}, {{T.body}}</p>",
            "baseText": "Hello {{USER_NAME}}, {{T.body}}",
            "translations": {
                "en": {"subject": "Custom Subject", "body": "Click the link: {{link}}"},
            },
        }
        store = FakeTemplateStore(tpl)
        cfg = MailerConfig()
        svc = MailerService(cfg, template_store=store)

        calls = []

        async def _fake(to, *, subject, html, text):
            calls.append({"subject": subject, "html": html})

        svc._send = _fake
        await svc.send_password_reset("u@e.com", "tok", "https://example.com/reset")
        assert calls[0]["subject"] == "Custom Subject"
        # Interpolation of {{link}} and {{T.body}} should occur in html
        assert "Click the link" in calls[0]["html"]

    async def test_send_custom(self, svc):
        calls = []

        async def _fake(to, *, subject, html, text):
            calls.append({"to": to, "subject": subject})

        svc._send = _fake
        await svc.send_custom("u@e.com", "Hello!", "<p>Hello</p>")
        assert calls[0]["subject"] == "Hello!"
        assert calls[0]["to"] == "u@e.com"


async def _noop(*args, **kwargs):
    pass
