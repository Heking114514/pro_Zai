from __future__ import annotations

import asyncio

import protocol_registration
from protocol_client import ProtocolFallback
from protocol_registration import ProtocolRegistrationWorker


class FakeCaptchaWindow:
    async def solve(self, task, profile, proxy, *, on_status):
        return protocol_registration.CaptchaSolution(
            captcha_verify_param="",
            provider="test",
            signup_response={"status": 200, "completed": True, "body": {}},
        )


def _worker(monkeypatch):
    worker = ProtocolRegistrationWorker(
        {
            "proxy_enabled": True,
            "protocol_proxy_retry_attempts": 2,
            "protocol_timeout_sec": 5,
            "protocol_check_exists_before_signup": False,
            "auto_verify_email": False,
        },
        None,
    )
    worker.captcha_window = FakeCaptchaWindow()
    proxies = iter(
        [
            {"raw": "proxy-a", "display": "HTTP://proxy-a", "requests_proxy": "http://a"},
            {"raw": "proxy-b", "display": "HTTP://proxy-b", "requests_proxy": "http://b"},
        ]
    )
    monkeypatch.setattr(worker, "_proxy", lambda: next(proxies, None))
    return worker


def test_proxy_timeout_retries_and_succeeds(monkeypatch):
    worker = _worker(monkeypatch)
    attempts = {"count": 0}

    class FakeClient:
        def __init__(self, profile, *, proxy, timeout):
            self.proxy = proxy
            self.state = type(
                "State",
                (),
                {"guest_jwt": "guest", "web_jwt": "web"},
            )()

        def bootstrap(self):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise ProtocolFallback(
                    "HTTP transport failed: curl: (28) Operation timed out",
                    code="transport_error",
                )
            return {"email": "guest@example.com"}

        def state_snapshot(self):
            return {"guest_jwt": self.state.guest_jwt}

        def cookie_snapshot(self):
            return {}

        def import_browser_captcha_session(self, solution):
            return None

        def finish_signup(self, **kwargs):
            return {"success": True}

        def oauth_exchange(self, *, timeout_sec):
            return type(
                "OAuth",
                (),
                {
                    "cli_jwt": "cli",
                    "access_token": "business",
                    "sub": "subject",
                    "device_mid": "device",
                    "web_jwt": "web",
                },
            )()

    async def no_wait(_):
        return None

    async def no_mail(*args, **kwargs):
        return "https://chat.z.ai/auth/verify_email?token=verify-test"

    async def no_import(*args, **kwargs):
        return None

    monkeypatch.setattr(protocol_registration, "ZaiProtocolClient", FakeClient)
    monkeypatch.setattr(protocol_registration.asyncio, "sleep", no_wait)
    monkeypatch.setattr(worker, "_find_verification", no_mail)
    monkeypatch.setattr(worker, "_import_to_zcode2api", no_import)

    task = {
        "id": "task-proxy-retry",
        "email": "user@example.com",
        "name": "User",
        "password": "password",
    }
    result = asyncio.run(worker.execute_task(task))
    assert attempts["count"] == 2
    assert result["status"] == "SUCCESS"
    assert result["cli_jwt"] == "cli"
