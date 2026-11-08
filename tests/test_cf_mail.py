from __future__ import annotations

import base64
import json
import time
from email.message import EmailMessage

from cf_mail import CfMailClient, CfMailbox, mailbox_mail_url, normalize_cf_base
from email_service import EmailService


def test_normalize_cf_base_and_mail_url():
    assert normalize_cf_base("mail.example.com/") == "https://mail.example.com"
    assert normalize_cf_base("https://mail.example.com/api") == "https://mail.example.com"
    assert (
        mailbox_mail_url("https://mail.example.com")
        == "https://mail.example.com/api/mails?limit=20&offset=0"
    )


def test_allocate_returns_unique_mailbox(monkeypatch):
    client = CfMailClient("https://mail.example.com")
    calls = []

    def fake_create_address(self, *, name="", domain="", password=""):
        calls.append((name, domain, password))
        return CfMailbox(
            email=f"{name or 'random'}@example.com",
            jwt="test-jwt",
            api_base=self.base,
            api_url=mailbox_mail_url(self.base),
            address_id=42,
        )

    monkeypatch.setattr(CfMailClient, "create_address", fake_create_address)
    mailbox = client.allocate(
        requested_name="Alice Smith",
        domain="example.com",
        existing_emails={"alicesmith@example.com"},
    )
    assert mailbox.email != "alicesmith@example.com"
    assert mailbox.jwt == "test-jwt"
    assert len(calls) == 2


def test_dynamic_email_service_extracts_link_from_raw_mime(monkeypatch):
    message = EmailMessage()
    message["To"] = "dynamic@example.com"
    message["Subject"] = "Verify your Z.ai account"
    message.set_content(
        "Open https://chat.z.ai/auth/verify_email?token=verify-dynamic-123 to continue"
    )
    raw = message.as_string()

    class Response:
        status_code = 200
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"id": "mail-1", "raw": raw}]}

    monkeypatch.setattr("email_service.requests.get", lambda *args, **kwargs: Response())
    monkeypatch.setattr("email_service.time.sleep", lambda _seconds: None)
    service = EmailService(
        provider="cf_dynamic",
        api_url=mailbox_mail_url("https://mail.example.com"),
        api_token="jwt",
    )
    link = service.find_verification_link(
        "dynamic@example.com",
        since_timestamp=time.time(),
        timeout=1,
    )
    assert link == "https://chat.z.ai/auth/verify_email?token=verify-dynamic-123"
