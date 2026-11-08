"""Small password gate for a remotely exposed single-operator WebUI."""

from __future__ import annotations

import hashlib
import hmac
import html
import os
import time
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response


COOKIE_NAME = "pro_zai_session"
PUBLIC_PATHS = {
    "/login",
    "/api/login",
    "/api/health",
    "/favicon.ico",
}
PUBLIC_PREFIXES = ("/static/",)


def _password() -> str:
    return os.environ.get("PRO_ZAI_PASSWORD", "")


def _secret() -> bytes:
    configured = os.environ.get("PRO_ZAI_SESSION_SECRET", "")
    if configured:
        return configured.encode("utf-8")
    # Stable within a container lifetime, intentionally not written to disk.
    return hashlib.sha256(("pro-zai:" + _password()).encode("utf-8")).digest()


def _signature(timestamp: str) -> str:
    return hmac.new(
        _secret(),
        f"pro-zai-session:{timestamp}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_session_value() -> str:
    timestamp = str(int(time.time()))
    return f"{timestamp}.{_signature(timestamp)}"


def verify_session_value(value: str, max_age_sec: int = 7 * 24 * 3600) -> bool:
    try:
        timestamp, signature = value.split(".", 1)
        issued = int(timestamp)
    except (AttributeError, ValueError):
        return False
    if abs(time.time() - issued) > max_age_sec:
        return False
    return hmac.compare_digest(signature, _signature(timestamp))


def is_authenticated(request: Request) -> bool:
    if not _password():
        return True
    return verify_session_value(request.cookies.get(COOKIE_NAME, ""))


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def login_page(error: str = "") -> HTMLResponse:
    error_html = (
        f'<p style="color:#b91c1c;margin:0 0 14px">{html.escape(error)}</p>'
        if error
        else ""
    )
    page = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pro-zai 登录</title>
<style>
body{{margin:0;background:#f1f5f9;font-family:system-ui,sans-serif;color:#0f172a}}
main{{max-width:380px;margin:14vh auto;background:white;border:1px solid #e2e8f0;
border-radius:12px;padding:28px;box-shadow:0 18px 50px #0f172a14}}
h1{{font-size:20px;margin:0 0 8px}}p{{font-size:13px;color:#64748b}}
input{{box-sizing:border-box;width:100%;padding:11px;border:1px solid #cbd5e1;
border-radius:8px;margin:12px 0}}button{{width:100%;padding:11px;border:0;
border-radius:8px;background:#4f46e5;color:white;font-weight:600;cursor:pointer}}
</style></head><body><main><h1>pro-zai</h1>
<p>输入部署时设置的访问密码。</p>{error_html}
<form method="post" action="/api/login">
<input name="password" type="password" autocomplete="current-password"
placeholder="访问密码" autofocus required>
<button type="submit">进入控制台</button></form></main></body></html>"""
    return HTMLResponse(page, status_code=401 if error else 200)


def login_redirect(request: Request) -> Response:
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(f"/login?next={quote(target, safe='/')}", status_code=303)
