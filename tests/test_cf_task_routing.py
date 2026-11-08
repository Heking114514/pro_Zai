from __future__ import annotations

import app
from email_service import EmailService


def test_task_scoped_cf_jwt_wins_over_static_pool(monkeypatch):
    monkeypatch.setattr(
        app,
        "load_config",
        lambda: {
            "mail_provider": "cf_dynamic",
            "mail_api_pool": "shared@example.com----fake-static-mail-token",
            "mail_api_url": "https://mail.example.com/api/mails?limit=20&offset=0",
            "cf_mail_base": "https://mail.example.com",
            "imap_host": "",
            "imap_port": 993,
            "imap_ssl": True,
            "imap_user": "",
            "imap_pass": "",
            "imap_folder": "INBOX",
        },
    )
    monkeypatch.setattr(
        app,
        "tasks",
        [
            {
                "id": "task-cf",
                "email": "dynamic@example.com",
                "mail_jwt": "dynamic-jwt",
                "mail_api_url": "https://mail.example.com/api/mails?limit=20&offset=0",
            }
        ],
    )
    service = app.get_email_service("dynamic@example.com")
    assert isinstance(service, EmailService)
    assert service.provider == "cf_dynamic"
    assert service.api_token == "dynamic-jwt"


def test_static_pool_still_works_when_task_has_no_jwt(monkeypatch):
    monkeypatch.setattr(
        app,
        "load_config",
        lambda: {
            "mail_provider": "api",
            "mail_api_pool": "shared@example.com----fake-static-mail-token",
            "mail_api_url": "https://mail.example.com/api/mails?limit=20&offset=0",
            "cf_mail_base": "https://mail.example.com",
            "imap_host": "",
            "imap_port": 993,
            "imap_ssl": True,
            "imap_user": "",
            "imap_pass": "",
            "imap_folder": "INBOX",
        },
    )
    monkeypatch.setattr(
        app,
        "tasks",
        [{"id": "task-static", "email": "shared@example.com"}],
    )
    service = app.get_email_service("shared@example.com")
    assert service.api_token == "fake-static-mail-token"
