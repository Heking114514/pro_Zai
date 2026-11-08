"""HTTP-only Z.ai registration and ZCode OAuth client."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qs, urljoin, urlsplit

from captcha_solver import CaptchaSolution, validate_captcha_param
from protocol_fingerprint import BrowserFingerprint, generate_profile_image
from traffic_log import capture as capture_traffic


CHAT_ORIGIN = "https://chat.z.ai"
ZCODE_ORIGIN = "https://zcode.z.ai"
AUTH_PAGE = f"{CHAT_ORIGIN}/auth"
SIGNUP_URL = f"{CHAT_ORIGIN}/api/v1/auths/signup"
FORGOT_PASSWORD_URL = f"{CHAT_ORIGIN}/api/v1/auths/forgot-password"
VERIFY_EMAIL_URL = f"{CHAT_ORIGIN}/api/v1/auths/verify_email"
FINISH_SIGNUP_URL = f"{CHAT_ORIGIN}/api/v1/auths/finish_signup"
CLI_INIT_URL = f"{ZCODE_ORIGIN}/api/v1/oauth/cli/init"
CLI_POLL_URL = f"{ZCODE_ORIGIN}/api/v1/oauth/cli/poll"


class ProtocolError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "protocol_error",
        status: Optional[int] = None,
        response_body: Any = None,
        fallback_safe: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.response_body = response_body
        self.fallback_safe = fallback_safe


class ProtocolFallback(ProtocolError):
    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs["fallback_safe"] = True
        super().__init__(message, **kwargs)


@dataclass
class HttpResult:
    status: int
    url: str
    headers: Dict[str, str]
    text: str
    json_data: Any = None


@dataclass
class OAuthResult:
    cli_jwt: str
    access_token: str
    sub: str
    device_mid: str
    redirect_url: str = ""
    web_jwt: str = ""


@dataclass
class ProtocolState:
    guest_jwt: str = ""
    web_jwt: str = ""
    email: str = ""
    verify_url: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)


def _response_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _jwt_payload(token: str) -> Dict[str, Any]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        value = json.loads(base64.urlsafe_b64decode(part.encode("ascii")).decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (IndexError, ValueError, UnicodeDecodeError):
        return {}


def extract_verify_token(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if re.fullmatch(r"verify-[A-Za-z0-9._~-]+", raw):
        return raw
    try:
        token = parse_qs(urlsplit(raw).query).get("token", [""])[0]
    except ValueError:
        return ""
    return token.strip()


def _error_message(payload: Any, fallback: str) -> str:
    if isinstance(payload, Mapping):
        for key in ("detail", "message", "error", "msg"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    if isinstance(payload, str) and payload.strip():
        return payload.strip()[:300]
    return fallback


class ZaiProtocolClient:
    """A stateful HTTP client for one registration attempt.

    The caller must keep one instance from guest bootstrap through finish_signup
    so the guest token, anti-bot cookie, and one-time email token stay bound to
    the same session.
    """

    def __init__(
        self,
        fingerprint: BrowserFingerprint,
        *,
        proxy: str = "",
        timeout: int = 30,
        session: Any = None,
    ) -> None:
        fingerprint.validate()
        self.fingerprint = fingerprint
        self.device_id = fingerprint.device_id
        self.proxy = (proxy or "").strip()
        self.timeout = max(5, int(timeout))
        self.state = ProtocolState()
        self._session = session or self._new_session()

    def _new_session(self) -> Any:
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:
            raise ProtocolFallback(
                "curl_cffi is not installed; protocol mode is unavailable",
                code="missing_curl_cffi",
            ) from exc
        return curl_requests.Session(impersonate=self.fingerprint.impersonate)

    def _proxies(self) -> Optional[Dict[str, str]]:
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}

    def _api_headers(
        self,
        *,
        include_device_id: bool = True,
        **kwargs: Any,
    ) -> Dict[str, str]:
        headers = self.fingerprint.api_headers(**kwargs)
        if include_device_id:
            headers["x-device-id"] = self.device_id
        return headers

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        form: Optional[Mapping[str, Any]] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
    ) -> HttpResult:
        kwargs: Dict[str, Any] = {
            "headers": dict(headers or {}),
            "timeout": max(1, int(timeout or self.timeout)),
            "allow_redirects": allow_redirects,
        }
        if params:
            kwargs["params"] = dict(params)
        if json_body is not None:
            kwargs["json"] = json_body
        if form is not None:
            kwargs["data"] = dict(form)
        proxies = self._proxies()
        if proxies:
            kwargs["proxies"] = proxies
        started = time.monotonic()
        try:
            response = self._session.request(method, url, **kwargs)
        except Exception as exc:
            try:
                capture_traffic(
                    source="protocol",
                    phase="transport_error",
                    method=method,
                    url=url,
                    request_headers=headers,
                    request_body=json_body if json_body is not None else form,
                    error=str(exc),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception:
                pass
            raise ProtocolFallback(
                f"HTTP transport failed: {exc}",
                code="transport_error",
            ) from exc

        status = int(getattr(response, "status_code", 0) or 0)
        text = getattr(response, "text", "") or ""
        response_headers = {
            str(key).lower(): str(value)
            for key, value in dict(getattr(response, "headers", {}) or {}).items()
        }
        try:
            capture_traffic(
                source="protocol",
                phase="http",
                method=method,
                url=str(getattr(response, "url", url) or url),
                request_headers=headers,
                request_body=json_body if json_body is not None else form,
                status=status,
                response_headers=response_headers,
                response_body=text,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception:
            # Capture is diagnostic only; never abort a registration because
            # a response shape or a log sink could not be serialized.
            pass
        return HttpResult(
            status=status,
            url=str(getattr(response, "url", url) or url),
            headers=response_headers,
            text=text,
            json_data=_response_json(text),
        )

    def _raise_for_status(
        self,
        result: HttpResult,
        *,
        action: str,
        safe_to_fallback: bool = False,
    ) -> None:
        if 200 <= result.status < 300:
            return
        if result.status == 429:
            raise ProtocolError(
                f"{action} was rate limited (HTTP 429)",
                code="rate_limited",
                status=result.status,
                response_body=result.json_data or result.text,
                fallback_safe=safe_to_fallback,
            )
        if result.status in (401, 403, 405):
            if safe_to_fallback:
                raise ProtocolFallback(
                    f"{action} was blocked (HTTP {result.status})",
                    code="waf_or_session_rejected",
                    status=result.status,
                    response_body=result.json_data or result.text,
                )
            raise ProtocolError(
                f"{action} was blocked (HTTP {result.status})",
                code="session_rejected",
                status=result.status,
                response_body=result.json_data or result.text,
            )
        raise ProtocolError(
            f"{action} failed: {_error_message(result.json_data, f'HTTP {result.status}')}",
            code="unexpected_status",
            status=result.status,
            response_body=result.json_data or result.text,
            fallback_safe=safe_to_fallback,
        )

    def _cookie_value(self, name: str) -> str:
        try:
            cookie = self._session.cookies.get(name, domain="chat.z.ai")
        except TypeError:
            cookie = self._session.cookies.get(name)
        except Exception:
            return ""
        if isinstance(cookie, str):
            return cookie
        return str(getattr(cookie, "value", "") or "")

    def set_cookies(self, cookies: Mapping[str, str]) -> None:
        """Merge solver-provided chat.z.ai cookies into this HTTP session."""

        for name, value in cookies.items():
            if not name or value is None:
                continue
            try:
                self._session.cookies.set(str(name), str(value), domain="chat.z.ai", path="/")
            except Exception as exc:
                raise ProtocolError(
                    f"Unable to import CAPTCHA solver cookie {name}",
                    code="cookie_import_failed",
                ) from exc

    def cookie_snapshot(self) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        try:
            values = self._session.cookies.jar
        except Exception:
            values = []
        try:
            for cookie in values:
                name = str(getattr(cookie, "name", "") or "")
                domain = str(getattr(cookie, "domain", "") or "")
                if name and (not domain or "z.ai" in domain):
                    cookies[name] = str(getattr(cookie, "value", "") or "")
        except TypeError:
            pass
        return cookies

    def bootstrap(self) -> Dict[str, Any]:
        """Establish the anonymous Z.ai session and guest JWT."""

        page = self._request(
            "GET",
            AUTH_PAGE,
            headers=self.fingerprint.navigation_headers(),
        )
        self._raise_for_status(page, action="Opening the Z.ai auth page", safe_to_fallback=True)

        # The SPA calls this endpoint to obtain the guest identity. Calling it
        # directly reproduces the observed protocol without executing JS.
        guest = self._request(
            "GET",
            f"{CHAT_ORIGIN}/api/v1/auths/",
            headers=self._api_headers(referer=AUTH_PAGE),
        )
        self._raise_for_status(guest, action="Creating the guest session", safe_to_fallback=True)
        if not isinstance(guest.json_data, Mapping):
            raise ProtocolFallback(
                "Guest session response is not JSON",
                code="guest_session_invalid",
                status=guest.status,
            )
        token = str(guest.json_data.get("token") or self._cookie_value("token") or "")
        if not token:
            raise ProtocolFallback(
                "Guest session did not return a token",
                code="guest_session_missing_token",
                status=guest.status,
            )
        self.state.guest_jwt = token
        self.state.email = str(guest.json_data.get("email") or "")
        return dict(guest.json_data)

    def account_exists(self, email: str) -> bool:
        """Check whether an email is registered without creating an account.

        Z.ai's password-reset request is a non-mutating account oracle:
        registered addresses return ``{"success": true}`` while unknown
        addresses return ``{"success": false, "message": "该邮箱未注册"}``.
        The check does not sign in and does not submit the signup form.
        """

        # The preflight must fail fast. curl_cffi can otherwise sit behind a
        # dead proxy node for the full task timeout before the browser bridge
        # is even launched, which looks like a UI hang.
        check_timeout = min(8, max(4, int(self.timeout)))
        result = self._request(
            "POST",
            FORGOT_PASSWORD_URL,
            headers=self._api_headers(
                referer=AUTH_PAGE,
                content_type="application/json",
            ),
            json_body={"email": email},
            timeout=check_timeout,
        )
        if result.status != 200 or not isinstance(result.json_data, Mapping):
            self._raise_for_status(
                result,
                action="Checking whether the account exists",
                safe_to_fallback=True,
            )
            raise ProtocolError(
                "Account-existence check returned an invalid response",
                code="account_check_invalid",
                status=result.status,
                response_body=result.json_data or result.text,
            )
        if result.json_data.get("success") is True:
            return True
        message = str(result.json_data.get("message") or "").lower()
        if any(
            marker in message
            for marker in ("未注册", "not registered", "does not exist", "not found")
        ):
            return False
        raise ProtocolError(
            f"Account-existence check was inconclusive: {message or 'unknown response'}",
            code="account_check_inconclusive",
            status=result.status,
            response_body=result.json_data,
        )

    def apply_captcha_solution(self, solution: CaptchaSolution) -> None:
        """Bind solver cookies and device identity to this HTTP session."""

        if solution.captcha_verify_param:
            validate_captcha_param(solution.captcha_verify_param)
        if solution.cookies:
            self.set_cookies(solution.cookies)
        if solution.device_id:
            # A solver can keep its own device id; all subsequent headers use it.
            self.device_id = solution.device_id

    def _apply_captcha_solution(self, solution: CaptchaSolution) -> None:
        self.apply_captcha_solution(solution)

    def import_browser_captcha_session(self, solution: CaptchaSolution) -> None:
        """Import a completed browser session into this protocol client.

        The CAPTCHA browser starts from the same fingerprint profile and sends
        its own signup. Cookies from that browser remain necessary for email
        verification and OAuth, while the browser itself can now be closed.
        """

        if not solution.signup_response.get("completed"):
            raise ProtocolError(
                "The CAPTCHA browser did not complete signup",
                code="browser_signup_incomplete",
            )
        # Keep the protocol guest JWT and only merge browser cookies that carry
        # state. The browser's token cookie is a different guest identity and
        # overwrites the session created before signup.
        self.device_id = solution.device_id or self.device_id
        browser_cookies = {
            str(name): str(value)
            for name, value in (solution.cookies or {}).items()
            if name and value is not None and str(name) != "token"
        }
        if browser_cookies:
            self.set_cookies(browser_cookies)

    def submit_signup(
        self,
        *,
        name: str,
        email: str,
        password: str,
        captcha: CaptchaSolution,
    ) -> Dict[str, Any]:
        if not captcha.captcha_verify_param:
            raise ProtocolError(
                "A CAPTCHA token is required for protocol signup",
                code="captcha_token_required",
            )
        if not self.state.guest_jwt:
            raise ProtocolError(
                "Guest session must be initialized before signup",
                code="guest_session_required",
            )
        self._apply_captcha_solution(captcha)
        payload = {
            "name": name,
            "email": email,
            "password": password,
            "profile_image_url": generate_profile_image(
                f"{self.fingerprint.seed}:{email}:avatar"
            ),
            "sso_redirect": None,
            "captcha_verify_param": captcha.captcha_verify_param,
        }
        result = self._request(
            "POST",
            SIGNUP_URL,
            headers=self._api_headers(
                referer=AUTH_PAGE,
                content_type="application/json",
            ),
            json_body=payload,
        )
        self._raise_for_status(result, action="Submitting registration", safe_to_fallback=True)
        if not isinstance(result.json_data, Mapping) or result.json_data.get("success") is not True:
            message = _error_message(result.json_data, "Registration was not confirmed")
            lowered = message.lower()
            code = (
                "captcha_rejected"
                if "captcha" in lowered or "verification" in lowered
                else "signup_rejected"
            )
            raise ProtocolError(
                message,
                code=code,
                status=result.status,
                response_body=result.json_data or result.text,
                fallback_safe=code == "captcha_rejected",
            )
        self.state.email = email
        return dict(result.json_data)

    def open_verification(self, verify_url_or_token: str) -> str:
        token = extract_verify_token(verify_url_or_token)
        if not token:
            raise ProtocolError(
                "Verification URL or token is invalid",
                code="invalid_verify_token",
            )
        verify_url = (
            verify_url_or_token.strip()
            if "://" in verify_url_or_token
            else f"{CHAT_ORIGIN}/auth/verify_email?token={token}"
        )
        # The SPA itself loads this URL before its verify_email POST. Reproduce
        # that navigation in the same HTTP session; the response is HTML.
        result = self._request(
            "GET",
            verify_url,
            headers=self.fingerprint.navigation_headers(),
        )
        if result.status in (401, 403, 404, 410):
            raise ProtocolError(
                f"Verification link was rejected (HTTP {result.status})",
                code="verify_link_rejected",
                status=result.status,
                response_body=result.json_data or result.text,
            )
        if result.status >= 500:
            raise ProtocolError(
                f"Verification page failed (HTTP {result.status})",
                code="verify_page_failed",
                status=result.status,
            )
        self.state.verify_url = verify_url
        return token

    def finish_signup(
        self,
        *,
        verify_url_or_token: str,
        name: str,
        email: str,
        password: str,
    ) -> Dict[str, Any]:
        if self._has_account_web_jwt(email):
            # Browser signup already authenticated this session. Calling the
            # verify page with that token can be rejected as an invalid state.
            return {"success": True, "already_verified": True}
        token = self.open_verification(verify_url_or_token)
        verify = self._request(
            "POST",
            VERIFY_EMAIL_URL,
            headers=self._api_headers(
                include_device_id=False,
                referer=f"{CHAT_ORIGIN}/auth/verify_email?token={token}",
                content_type="application/json",
            ),
            json_body={
                "username": name,
                "email": email,
                "token": token,
            },
        )
        self._raise_for_status(verify, action="Verifying the email token")
        if (
            not isinstance(verify.json_data, Mapping)
            or verify.json_data.get("success") is not True
        ):
            raise ProtocolError(
                _error_message(
                    verify.json_data,
                    "The email verification token was not confirmed",
                ),
                code="verify_email_rejected",
                status=verify.status,
                response_body=verify.json_data or verify.text,
            )
        payload = {
            "username": name,
            "email": email,
            "token": token,
            "password": password,
            "profile_image_url": generate_profile_image(
                f"{self.fingerprint.seed}:{email}:avatar"
            ),
            "sso_redirect": None,
        }
        result = self._request(
            "POST",
            FINISH_SIGNUP_URL,
            headers=self._api_headers(
                referer=f"{CHAT_ORIGIN}/auth/verify_email?token={token}",
                content_type="application/json",
            ),
            json_body=payload,
        )
        self._raise_for_status(result, action="Completing email verification")
        if not isinstance(result.json_data, Mapping) or result.json_data.get("success") is not True:
            raise ProtocolError(
                _error_message(result.json_data, "Account activation was not confirmed"),
                code="finish_signup_rejected",
                status=result.status,
                response_body=result.json_data or result.text,
            )
        user = result.json_data.get("user")
        web_jwt = str(user.get("token") or "") if isinstance(user, Mapping) else ""
        if not web_jwt:
            raise ProtocolError(
                "finish_signup succeeded but did not return a web JWT",
                code="missing_web_jwt",
                status=result.status,
            )
        payload_claims = _jwt_payload(web_jwt)
        jwt_email = str(payload_claims.get("email") or "").lower()
        if jwt_email and jwt_email != email.lower():
            raise ProtocolError(
                "Returned JWT belongs to a different email address",
                code="jwt_email_mismatch",
                status=result.status,
            )
        self.state.web_jwt = web_jwt
        try:
            self._session.cookies.set("token", web_jwt, domain="chat.z.ai", path="/")
        except Exception:
            pass
        return dict(result.json_data)

    def _has_account_web_jwt(self, email: str) -> bool:
        token = str(self.state.web_jwt or "")
        if not token:
            return False
        claims = _jwt_payload(token)
        claim_email = str(claims.get("email") or "").lower()
        if not claim_email or claim_email.startswith("guest-"):
            return False
        return claim_email == email.lower()

    def account(self) -> Dict[str, Any]:
        token = self.state.web_jwt or self.state.guest_jwt
        result = self._request(
            "GET",
            f"{CHAT_ORIGIN}/api/v1/auths/",
            headers=self._api_headers(
                referer=f"{CHAT_ORIGIN}/",
                authorization=token or None,
            ),
        )
        self._raise_for_status(result, action="Reading the current account")
        return dict(result.json_data) if isinstance(result.json_data, Mapping) else {}

    def oauth_exchange(self, *, timeout_sec: int = 30) -> OAuthResult:
        claims = _jwt_payload(self.state.web_jwt)
        claim_email = str(claims.get("email") or "").lower()
        if not claim_email or claim_email.startswith("guest-"):
            raise ProtocolError(
                "A non-guest account web JWT is required for OAuth",
                code="account_web_jwt_required",
                response_body={"email": claim_email},
            )
        poll_token = secrets.token_hex(32)
        init = self._request(
            "POST",
            CLI_INIT_URL,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {poll_token}",
                "User-Agent": self.fingerprint.user_agent,
            },
            json_body={"provider": "zai"},
        )
        self._raise_for_status(init, action="Initializing ZCode CLI OAuth")
        if not isinstance(init.json_data, Mapping) or init.json_data.get("code") != 0:
            raise ProtocolError(
                _error_message(init.json_data, "ZCode CLI init failed"),
                code="oauth_init_failed",
                status=init.status,
                response_body=init.json_data or init.text,
            )
        data = init.json_data.get("data") or {}
        flow_id = str(data.get("flow_id") or "")
        authorize_url = str(data.get("authorize_url") or "")
        if not flow_id or not authorize_url:
            raise ProtocolError(
                "ZCode CLI init response is missing flow_id or authorize_url",
                code="oauth_init_incomplete",
            )

        authorize_url = urljoin(CHAT_ORIGIN, authorize_url)
        page = self._request(
            "GET",
            authorize_url,
            headers=self.fingerprint.navigation_headers(),
        )
        if page.status >= 400:
            raise ProtocolError(
                f"Opening the OAuth consent page failed (HTTP {page.status})",
                code="oauth_page_failed",
                status=page.status,
            )

        parsed = urlsplit(authorize_url)
        query = parse_qs(parsed.query)
        client_id = str((query.get("client_id") or [""])[0])
        redirect_uri = str((query.get("redirect_uri") or [""])[0])
        state = str((query.get("state") or [""])[0])
        response_type = str((query.get("response_type") or ["code"])[0])
        if not client_id or not redirect_uri:
            raise ProtocolError(
                "OAuth authorize URL is missing client_id or redirect_uri",
                code="oauth_authorize_url_invalid",
            )

        info = self._request(
            "GET",
            f"{CHAT_ORIGIN}/api/oauth/authorize/info",
            headers=self._api_headers(
                referer=authorize_url,
                authorization=self.state.web_jwt,
            ),
            params={"client_id": client_id, "redirect_uri": redirect_uri},
        )
        self._raise_for_status(info, action="Reading OAuth authorization details")

        approval = self._request(
            "POST",
            f"{CHAT_ORIGIN}/api/oauth/authorize",
            headers=self._api_headers(
                referer=authorize_url,
                authorization=self.state.web_jwt,
                content_type="application/x-www-form-urlencoded",
            ),
            form={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "response_type": response_type,
                "action": "approve",
            },
        )
        self._raise_for_status(approval, action="Approving the ZCode OAuth request")
        redirect_url = ""
        if isinstance(approval.json_data, Mapping):
            redirect_url = str(approval.json_data.get("redirect_url") or "")
        if not redirect_url:
            raise ProtocolError(
                "OAuth approval response did not return redirect_url",
                code="oauth_redirect_missing",
                response_body=approval.json_data or approval.text,
            )
        callback = self._request(
            "GET",
            redirect_url,
            headers=self.fingerprint.navigation_headers(),
        )
        if callback.status >= 400:
            raise ProtocolError(
                f"ZCode OAuth callback failed (HTTP {callback.status})",
                code="oauth_callback_failed",
                status=callback.status,
            )

        deadline = time.time() + max(5, int(timeout_sec))
        while time.time() < deadline:
            poll = self._request(
                "GET",
                f"{CLI_POLL_URL}/{flow_id}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {poll_token}",
                    "User-Agent": self.fingerprint.user_agent,
                },
            )
            self._raise_for_status(poll, action="Polling the ZCode CLI token")
            payload = poll.json_data if isinstance(poll.json_data, Mapping) else {}
            values = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
            if values.get("status") == "ready" and values.get("token"):
                cli_jwt = str(values["token"])
                claims = _jwt_payload(cli_jwt)
                sub = str(claims.get("sub") or claims.get("user_id") or claims.get("id") or "")
                device_mid = _device_mid(sub or cli_jwt)
                zai = values.get("zai") if isinstance(values.get("zai"), Mapping) else {}
                return OAuthResult(
                    cli_jwt=cli_jwt,
                    access_token=str(zai.get("access_token") or ""),
                    sub=sub,
                    device_mid=device_mid,
                    redirect_url=redirect_url,
                    web_jwt=self.state.web_jwt,
                )
            time.sleep(1.5)
        raise ProtocolError(
            "Timed out waiting for the ZCode CLI token",
            code="oauth_timeout",
        )

    def state_snapshot(self) -> Dict[str, Any]:
        return {
            "guest_jwt": self.state.guest_jwt,
            "web_jwt": self.state.web_jwt,
            "email": self.state.email,
            "verify_url": self.state.verify_url,
            "cookies": self.cookie_snapshot(),
            "fingerprint": {**self.fingerprint.public_dict(), "device_id": self.device_id},
        }


def _device_mid(value: str) -> str:
    """Keep parity with the existing ZCode2Api device MID derivation."""

    import uuid

    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"zcode-gw.{value}"))
