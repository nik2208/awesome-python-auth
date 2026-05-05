"""Built-in email templates and HTTP mailer transport for awesome-python-auth.

Mirrors the MailerService in awesome-node-auth.  Templates are available in
English (default) and Italian.  A custom ``TemplateStore`` can override any
template at runtime.

Usage::

    from awesome_python_auth.mailer import MailerService, MailerConfig

    mailer = MailerService(MailerConfig(
        endpoint="https://mail.example.com/send",
        api_key="secret",
        from_address="no-reply@example.com",
    ))
    await mailer.send_password_reset("user@example.com", token, link)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class MailerConfig:
    """Configuration for the built-in HTTP mailer transport.

    ``endpoint`` must accept ``POST`` requests with a JSON body::

        {
          "to": "user@example.com",
          "from": "no-reply@example.com",
          "fromName": "My App",
          "subject": "Reset your password",
          "html": "<p>Click …</p>",
          "text": "Click …",
          "provider": "optional-provider-hint"
        }
    """

    endpoint: str = ""
    api_key: str = ""
    from_address: str = "no-reply@example.com"
    from_name: str | None = None
    provider: str | None = None
    default_lang: str = "en"


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------

_SUPPORTED_LANGS = {"en", "it"}


def _lang(lang: str | None, default: str) -> str:
    if lang and lang in _SUPPORTED_LANGS:
        return lang
    return default if default in _SUPPORTED_LANGS else "en"


def _password_reset(link: str, lang: str) -> dict[str, str]:
    if lang == "it":
        return {
            "subject": "Reimposta la tua password",
            "html": (
                f"<p>Hai richiesto di reimpostare la tua password.</p>"
                f"<p>Clicca sul link seguente per procedere (valido 1 ora):</p>"
                f'<p><a href="{link}">{link}</a></p>'
                f"<p>Se non hai richiesto questo, ignora questa email.</p>"
            ),
            "text": (
                f"Hai richiesto di reimpostare la tua password.\n\n"
                f"Clicca sul link seguente (valido 1 ora):\n{link}\n\n"
                f"Se non hai richiesto questo, ignora questa email."
            ),
        }
    return {
        "subject": "Reset your password",
        "html": (
            f"<p>You requested a password reset.</p>"
            f"<p>Click the link below to proceed (valid for 1 hour):</p>"
            f'<p><a href="{link}">{link}</a></p>'
            f"<p>If you did not request this, please ignore this email.</p>"
        ),
        "text": (
            f"You requested a password reset.\n\n"
            f"Click the link below (valid for 1 hour):\n{link}\n\n"
            f"If you did not request this, please ignore this email."
        ),
    }


def _magic_link(link: str, lang: str) -> dict[str, str]:
    if lang == "it":
        return {
            "subject": "Il tuo link di accesso",
            "html": (
                f"<p>Hai richiesto un link di accesso.</p>"
                f"<p>Clicca sul link seguente per accedere (valido 15 minuti):</p>"
                f'<p><a href="{link}">{link}</a></p>'
                f"<p>Se non hai richiesto questo, ignora questa email.</p>"
            ),
            "text": (
                f"Hai richiesto un link di accesso.\n\n"
                f"Clicca sul link seguente (valido 15 minuti):\n{link}\n\n"
                f"Se non hai richiesto questo, ignora questa email."
            ),
        }
    return {
        "subject": "Your magic sign-in link",
        "html": (
            f"<p>You requested a sign-in link.</p>"
            f"<p>Click the link below to sign in (valid for 15 minutes):</p>"
            f'<p><a href="{link}">{link}</a></p>'
            f"<p>If you did not request this, please ignore this email.</p>"
        ),
        "text": (
            f"You requested a sign-in link.\n\nClick the link below (valid for 15 minutes):\n{link}\n\n"
            f"If you did not request this, please ignore this email."
        ),
    }


def _verify_email(link: str, lang: str) -> dict[str, str]:
    if lang == "it":
        return {
            "subject": "Verifica il tuo indirizzo email",
            "html": (
                f"<p>Grazie per esserti registrato.</p>"
                f"<p>Clicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):</p>"
                f'<p><a href="{link}">{link}</a></p>'
                f"<p>Se non hai creato un account, ignora questa email.</p>"
            ),
            "text": (
                f"Grazie per esserti registrato.\n\n"
                f"Clicca sul link seguente per verificare il tuo indirizzo email (valido 24 ore):\n{link}\n\n"
                f"Se non hai creato un account, ignora questa email."
            ),
        }
    return {
        "subject": "Verify your email address",
        "html": (
            f"<p>Thank you for signing up.</p>"
            f"<p>Click the link below to verify your email address (valid for 24 hours):</p>"
            f'<p><a href="{link}">{link}</a></p>'
            f"<p>If you did not create an account, please ignore this email.</p>"
        ),
        "text": (
            f"Thank you for signing up.\n\n"
            f"Click the link below to verify your email address (valid for 24 hours):\n{link}\n\n"
            f"If you did not create an account, please ignore this email."
        ),
    }


def _email_changed(new_email: str, lang: str) -> dict[str, str]:
    if lang == "it":
        return {
            "subject": "Il tuo indirizzo email è stato aggiornato",
            "html": (
                f"<p>Questo è un avviso che il tuo indirizzo email è stato aggiornato a "
                f"<strong>{new_email}</strong>.</p>"
                f"<p>Se non hai richiesto questa modifica, contatta immediatamente il supporto.</p>"
            ),
            "text": (
                f"Il tuo indirizzo email è stato aggiornato a {new_email}.\n\n"
                f"Se non hai richiesto questa modifica, contatta immediatamente il supporto."
            ),
        }
    return {
        "subject": "Your email address has been updated",
        "html": (
            f"<p>This is a notice that your email address has been updated to "
            f"<strong>{new_email}</strong>.</p>"
            f"<p>If you did not request this change, please contact support immediately.</p>"
        ),
        "text": (
            f"Your email address has been updated to {new_email}.\n\n"
            f"If you did not request this change, please contact support immediately."
        ),
    }


def _welcome(data: dict[str, Any], lang: str) -> dict[str, str]:
    login_url = data.get("loginUrl", "")
    temp_password = data.get("tempPassword")
    if lang == "it":
        pw_html = f"<p>Password temporanea: <strong>{temp_password}</strong></p>" if temp_password else ""
        pw_text = f"Password temporanea: {temp_password}\n" if temp_password else ""
        return {
            "subject": "Benvenuto! Il tuo account è stato creato",
            "html": (
                f"<p>Il tuo account è stato creato con successo.</p>"
                f"{pw_html}"
                f'<p>Accedi qui: <a href="{login_url}">{login_url}</a></p>'
            ),
            "text": f"Il tuo account è stato creato con successo.\n{pw_text}Accedi qui: {login_url}",
        }
    pw_html = f"<p>Temporary password: <strong>{temp_password}</strong></p>" if temp_password else ""
    pw_text = f"Temporary password: {temp_password}\n" if temp_password else ""
    return {
        "subject": "Welcome! Your account has been created",
        "html": (
            f"<p>Your account has been created successfully.</p>"
            f"{pw_html}"
            f'<p>Sign in here: <a href="{login_url}">{login_url}</a></p>'
        ),
        "text": f"Your account has been created successfully.\n{pw_text}Sign in here: {login_url}",
    }


def _invitation(data: dict[str, Any], lang: str) -> dict[str, str]:
    link = data.get("link", "")
    if lang == "it":
        return {
            "subject": "Invito ad unirsi",
            "html": f"<p>Sei stato invitato.</p><p><a href=\"{link}\">{link}</a></p>",
            "text": f"Sei stato invitato.\n\n{link}",
        }
    return {
        "subject": "Invitation to join",
        "html": f"<p>You have been invited.</p><p><a href=\"{link}\">{link}</a></p>",
        "text": f"You have been invited.\n\n{link}",
    }


# ---------------------------------------------------------------------------
# Template store protocol
# ---------------------------------------------------------------------------


class TemplateStore:
    """Optional override for email templates.

    Implement ``get_mail_template`` to return custom templates from a database
    or CMS.  The ``MailerService`` falls back to built-in templates when a
    lookup returns ``None``.
    """

    async def get_mail_template(self, template_id: str) -> dict[str, Any] | None:
        """Return a template dict or ``None`` to use the built-in fallback.

        The returned dict should have the shape::

            {
                "baseHtml": "<p>Hello {{NAME}}, {{T.body}}</p>",
                "baseText": "Hello {{NAME}}, {{T.body}}",
                "translations": {
                    "en": {"subject": "Hello", "body": "Click …"},
                    "it": {"subject": "Ciao",  "body": "Clicca …"},
                }
            }
        """
        return None


# ---------------------------------------------------------------------------
# MailerService
# ---------------------------------------------------------------------------


class MailerService:
    """Sends transactional emails via a configurable HTTP endpoint.

    Compatible with the awesome-node-auth ``MailerService`` transport contract.
    """

    def __init__(
        self,
        config: MailerConfig,
        template_store: TemplateStore | None = None,
    ) -> None:
        self._cfg = config
        self._tpl_store = template_store

    # ---- Template rendering -------------------------------------------------

    async def _render(
        self,
        template_id: str,
        lang: str | None,
        data: dict[str, Any],
        fallback: Callable[[str], dict[str, str]],
    ) -> dict[str, str]:
        resolved_lang = _lang(lang, self._cfg.default_lang)
        if self._tpl_store:
            tpl = await self._tpl_store.get_mail_template(template_id)
            if tpl and tpl.get("baseHtml") and tpl.get("baseText"):
                translations: dict[str, str] = (
                    tpl.get("translations", {}).get(resolved_lang)
                    or tpl.get("translations", {}).get("en")
                    or {}
                )

                def _interpolate(s: str) -> str:
                    import re

                    def _replace(m: re.Match) -> str:
                        key = m.group(1)
                        if key.startswith("T."):
                            return translations.get(key[2:], f"[{key[2:]}]")
                        return str(data.get(key, f"[{key}]"))

                    return re.sub(r"\{\{([^}]+)\}\}", _replace, s)

                subject = translations.get("subject") or fallback(resolved_lang)["subject"]
                return {
                    "subject": _interpolate(subject),
                    "html": _interpolate(tpl["baseHtml"]),
                    "text": _interpolate(tpl["baseText"]),
                }
        return fallback(resolved_lang)

    # ---- Public send helpers ------------------------------------------------

    async def send_password_reset(
        self, to: str, token: str, link: str, lang: str | None = None
    ) -> None:
        tpl = await self._render(
            "password-reset", lang, {"link": link, "token": token},
            lambda l: _password_reset(link, l),
        )
        await self._send(to, **tpl)

    async def send_magic_link(
        self, to: str, token: str, link: str, lang: str | None = None
    ) -> None:
        tpl = await self._render(
            "magic-link", lang, {"link": link, "token": token},
            lambda l: _magic_link(link, l),
        )
        await self._send(to, **tpl)

    async def send_verification_email(
        self, to: str, token: str, link: str, lang: str | None = None
    ) -> None:
        tpl = await self._render(
            "verify-email", lang, {"link": link, "token": token},
            lambda l: _verify_email(link, l),
        )
        await self._send(to, **tpl)

    async def send_email_changed(
        self, to: str, new_email: str, lang: str | None = None
    ) -> None:
        tpl = await self._render(
            "email-changed", lang, {"newEmail": new_email},
            lambda l: _email_changed(new_email, l),
        )
        await self._send(to, **tpl)

    async def send_welcome(
        self, to: str, data: dict[str, Any], lang: str | None = None
    ) -> None:
        tpl = await self._render(
            "welcome", lang, data,
            lambda l: _welcome(data, l),
        )
        await self._send(to, **tpl)

    async def send_invitation(
        self, to: str, link: str, data: dict[str, Any], lang: str | None = None
    ) -> None:
        merged = {**data, "link": link}
        tpl = await self._render(
            "invitation", lang, merged,
            lambda l: _invitation(merged, l),
        )
        await self._send(to, **tpl)

    async def send_custom(
        self, to: str, subject: str, html: str, text: str | None = None
    ) -> None:
        """Send an arbitrary transactional email."""
        await self._send(to, subject=subject, html=html, text=text or html)

    # ---- Transport ----------------------------------------------------------

    async def _send(
        self, to: str, *, subject: str, html: str, text: str
    ) -> None:
        if not self._cfg.endpoint:
            return  # no transport configured — silently skip
        payload: dict[str, Any] = {
            "to": to,
            "from": self._cfg.from_address,
            "subject": subject,
            "html": html,
            "text": text,
        }
        if self._cfg.from_name:
            payload["fromName"] = self._cfg.from_name
        if self._cfg.provider:
            payload["provider"] = self._cfg.provider

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._cfg.endpoint,
                json=payload,
                headers={"X-API-Key": self._cfg.api_key, "Content-Type": "application/json"},
                timeout=10.0,
            )
            resp.raise_for_status()
