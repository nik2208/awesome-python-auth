"""Tests for the NotificationService and SmsService."""
from __future__ import annotations

import pytest

from awesome_python_auth.notification import (
    NotificationService,
    SmsConfig,
    SmsService,
    SendEmailOptions,
    SendSmsOptions,
)


class TestSmsService:
    def test_generate_code_default_digits(self):
        svc = SmsService(SmsConfig())
        code = svc.generate_code()
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_code_custom_digits(self):
        svc = SmsService(SmsConfig())
        code = svc.generate_code(digits=4)
        assert len(code) == 4
        assert code.isdigit()


class TestNotificationServiceHasCapabilities:
    def test_no_transports(self):
        ns = NotificationService()
        assert not ns.has_email
        assert not ns.has_sms

    def test_has_email_when_configured(self):
        from awesome_python_auth.mailer import MailerConfig
        ns = NotificationService(email=MailerConfig(endpoint="", api_key="", from_address="no-reply@example.com"))
        assert ns.has_email
        assert not ns.has_sms

    def test_has_sms_when_configured(self):
        ns = NotificationService(sms=SmsConfig(endpoint="http://sms.example.com", api_key="k", username="u", password="p"))
        assert not ns.has_email
        assert ns.has_sms

    def test_both_configured(self):
        from awesome_python_auth.mailer import MailerConfig
        ns = NotificationService(
            email=MailerConfig(endpoint="", api_key="", from_address="no-reply@example.com"),
            sms=SmsConfig(endpoint="http://sms.example.com", api_key="k", username="u", password="p"),
        )
        assert ns.has_email
        assert ns.has_sms


class TestNotificationServiceErrors:
    async def test_send_email_raises_without_transport(self):
        ns = NotificationService()
        with pytest.raises(RuntimeError, match="No email transport"):
            await ns.send_email(SendEmailOptions(to="a@b.com", subject="Hi", html="<p>Hi</p>"))

    async def test_send_sms_raises_without_transport(self):
        ns = NotificationService()
        with pytest.raises(RuntimeError, match="No SMS transport"):
            await ns.send_sms(SendSmsOptions(to="+1234567890", message="Hello"))


class TestSendOptions:
    def test_send_email_options_defaults(self):
        opts = SendEmailOptions(to="a@b.com", subject="Sub", html="<p>Hi</p>")
        assert opts.text is None
        assert opts.to == "a@b.com"

    def test_send_sms_options(self):
        opts = SendSmsOptions(to="+1", message="hello")
        assert opts.to == "+1"
        assert opts.message == "hello"
