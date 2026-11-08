"""Visible browser window used only for the human CAPTCHA step."""

from __future__ import annotations

import asyncio
import logging
import re
import time
import traceback
from typing import Any, Awaitable, Callable, Dict, Optional

from playwright.async_api import async_playwright

from captcha_solver import CaptchaSolution, validate_captcha_param
from debug_log import event as debug_event, fingerprint
from browser_routes import install_analytics_route
from protocol_fingerprint import BrowserFingerprint
from traffic_log import capture as capture_traffic


class CaptchaWindowError(RuntimeError):
    def __init__(self, message: str, code: str = "captcha_window_error") -> None:
        super().__init__(message)
        self.code = code


class LocalCaptchaWindow:
    """Open a visible browser, wait for a human slider, and return its token."""

    def __init__(
        self,
        config: Dict[str, Any],
        *,
        log_callback: Optional[Callable[[str, str, str], None]] = None,
        captcha_lock: Optional[asyncio.Lock] = None,
    ) -> None:
        self.config = config
        self.log_callback = log_callback
        self.captcha_lock = captcha_lock or asyncio.Lock()
        self.protocol_state: Dict[str, Any] = {}

    def log(self, task_id: str, message: str, level: str = "info") -> None:
        if not self.log_callback:
            return
        try:
            self.log_callback(task_id, message, level)
        except Exception:
            debug_event(
                "captcha.window.log_callback_failed",
                level=logging.ERROR,
                task_id=task_id,
                exc_info=True,
            )

    async def solve(
        self,
        task: Dict[str, Any],
        fingerprint_profile: BrowserFingerprint,
        proxy: Dict[str, Any],
        *,
        on_status: Callable[[str, str], Awaitable[None]],
    ) -> CaptchaSolution:
        task_id = str(task.get("id") or "")
        email = str(task.get("email") or "")
        name = str(task.get("name") or email.split("@")[0])
        password = str(task.get("password") or "")
        timeout = max(60, int(self.config.get("captcha_timeout_sec", 600)))
        self.protocol_state = dict(task.get("protocol_state") or {})

        async with self.captcha_lock:
            await on_status("WAITING_CAPTCHA", "正在打开本机验证码浏览器")
            debug_event(
                "captcha.window.start",
                task_id=task_id,
                email=email,
                timeout_sec=timeout,
                proxy=(proxy or {}).get("display", ""),
            )

            async with async_playwright() as playwright:
                launch_options: Dict[str, Any] = {
                    "headless": False,
                    "args": [
                        "--disable-blink-features=AutomationControlled",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ],
                    "ignore_default_args": ["--enable-automation"],
                }
                if proxy and proxy.get("playwright_cfg"):
                    launch_options["proxy"] = proxy["playwright_cfg"]

                browser = await playwright.chromium.launch(**launch_options)
                context = await browser.new_context(
                    viewport={
                        "width": fingerprint_profile.viewport_width,
                        "height": fingerprint_profile.viewport_height,
                    },
                    screen={
                        "width": fingerprint_profile.screen_width,
                        "height": fingerprint_profile.screen_height,
                    },
                    locale=fingerprint_profile.locale,
                    timezone_id=fingerprint_profile.timezone,
                    color_scheme="light",
                    device_scale_factor=fingerprint_profile.pixel_ratio,
                    user_agent=fingerprint_profile.user_agent,
                )
                page = await context.new_page()
                await install_analytics_route(
                    page,
                    task_id=task_id,
                    on_fulfilled=lambda url: debug_event(
                        "captcha.analytics_fulfilled",
                        task_id=task_id,
                        url=url[:1000],
                    ),
                )
                await page.bring_to_front()

                token_box: Dict[str, str] = {}
                signup_response: Dict[str, Any] = {
                    "status": None,
                    "body": None,
                    "completed": False,
                }
                page_errors: list[str] = []
                failed_requests: list[Dict[str, str]] = []
                request_started: Dict[str, float] = {}

                def should_capture(url: str) -> bool:
                    if url.startswith("https://chat.z.ai/api/"):
                        return True
                    if url.startswith("https://zcode.z.ai/api/"):
                        return True
                    host = url.split("/", 3)[2].lower() if "://" in url else ""
                    return "captcha" in host and "aliyuncs.com" in host

                async def on_request(request: Any) -> None:
                    if should_capture(request.url):
                        request_started[request.url] = time.monotonic()
                        try:
                            post_body = request.post_data or ""
                        except Exception:
                            post_body = ""
                        try:
                            request_headers = await request.all_headers()
                        except Exception as exc:
                            request_headers = {}
                            debug_event(
                                "captcha.traffic_headers_unavailable",
                                level=logging.WARNING,
                                task_id=task_id,
                                error=str(exc),
                                url=request.url[:1200],
                            )
                        capture_traffic(
                            source="captcha_browser",
                            phase="request",
                            method=request.method,
                            url=request.url,
                            request_headers=request_headers,
                            request_body=post_body,
                            task_id=task_id,
                        )
                    if "/api/v1/auths/signup" not in request.url:
                        return
                    try:
                        payload = request.post_data_json or {}
                    except Exception:
                        payload = {}
                    token = str(payload.get("captcha_verify_param") or "")
                    if token:
                        token_box["token"] = token
                    debug_event(
                        "captcha.signup_request",
                        task_id=task_id,
                        url=request.url,
                        has_captcha=bool(token),
                        captcha_fingerprint=fingerprint(token),
                        fields=sorted(payload) if isinstance(payload, dict) else [],
                    )

                async def on_response(response: Any) -> None:
                    if should_capture(response.url):
                        try:
                            response_text = await response.text()
                        except Exception:
                            response_text = ""
                        try:
                            response_headers = await response.all_headers()
                        except Exception as exc:
                            response_headers = {}
                            debug_event(
                                "captcha.traffic_headers_unavailable",
                                level=logging.WARNING,
                                task_id=task_id,
                                error=str(exc),
                                url=response.url[:1200],
                            )
                        started = request_started.pop(response.url, time.monotonic())
                        capture_traffic(
                            source="captcha_browser",
                            phase="response",
                            method=response.request.method,
                            url=response.url,
                            status=response.status,
                            response_headers=response_headers,
                            response_body=response_text,
                            duration_ms=int(
                                (time.monotonic() - started) * 1000
                            ),
                            task_id=task_id,
                        )
                    if "/api/v1/auths/signup" not in response.url:
                        return
                    try:
                        body = await response.json()
                    except Exception:
                        try:
                            body = (await response.text())[:2000]
                        except Exception:
                            body = None
                    signup_response.update(
                        {
                            "status": response.status,
                            "body": body,
                            "completed": response.status in {200, 201}
                            and (
                                not isinstance(body, dict)
                                or body.get("success") is True
                            ),
                        }
                    )
                    debug_event(
                        "captcha.signup_response",
                        level=(
                            logging.INFO
                            if signup_response["completed"]
                            else logging.WARNING
                        ),
                        task_id=task_id,
                        status=response.status,
                        completed=signup_response["completed"],
                        body=body,
                    )

                def on_page_error(error: Any) -> None:
                    text = str(error)[:2000]
                    page_errors.append(text)
                    debug_event(
                        "captcha.page_error",
                        level=logging.ERROR,
                        task_id=task_id,
                        error=text,
                    )

                def on_request_failed(request: Any) -> None:
                    item = {
                        "url": request.url[:1200],
                        "failure": str(request.failure or "")[:1000],
                    }
                    failed_requests.append(item)
                    debug_event(
                        "captcha.request_failed",
                        level=logging.WARNING,
                        task_id=task_id,
                        **item,
                    )

                def on_console(message: Any) -> None:
                    if message.type in {"error", "warning"}:
                        debug_event(
                            "captcha.console",
                            task_id=task_id,
                            console_type=message.type,
                            text=message.text[:2000],
                        )

                page.on("request", on_request)
                page.on("response", on_response)
                page.on("pageerror", on_page_error)
                page.on("requestfailed", on_request_failed)
                page.on("console", on_console)

                try:
                    response = await page.goto(
                        "https://chat.z.ai/auth",
                        wait_until="domcontentloaded",
                        timeout=45000,
                    )
                    debug_event(
                        "captcha.auth_loaded",
                        task_id=task_id,
                        status=response.status if response else 0,
                        url=page.url,
                    )
                    await page.wait_for_timeout(800)
                    await self._restore_protocol_session(page, task_id)
                    await self._open_signup(
                        page,
                        task_id,
                        name,
                        email,
                        password,
                    )

                    captcha_body = page.locator(
                        "#aliyunCaptcha-captcha-body"
                    ).first
                    create_button = page.locator("button:visible").filter(
                        has_text=re.compile(
                            r"^\s*(Create Account|创建账号|Sign up|注册)\s*$",
                            re.I,
                        )
                    ).last
                    await self._trigger_captcha(
                        page,
                        task_id,
                        create_button,
                        captcha_body,
                    )

                    await page.bring_to_front()
                    await on_status(
                        "WAITING_CAPTCHA",
                        "请在本机 Chromium 窗口完成滑块验证",
                    )
                    self.log(
                        task_id,
                        "验证码浏览器已打开，请手动拖动滑块",
                        "warning",
                    )

                    deadline = time.monotonic() + timeout
                    last_failure_log = 0.0
                    while time.monotonic() < deadline:
                        if page.is_closed():
                            raise CaptchaWindowError(
                                "验证码窗口已关闭",
                                "captcha_window_closed",
                            )
                        if signup_response["completed"]:
                            break
                        if signup_response["status"] is not None:
                            break

                        state = await page.evaluate(
                            """() => {
                                const visible = e => !!e &&
                                    e.getClientRects().length > 0 &&
                                    getComputedStyle(e).visibility !== 'hidden';
                                const text = [
                                    document.querySelector('#aliyunCaptcha-captcha-text')?.innerText,
                                    document.querySelector('#aliyunCaptcha-captcha-text-box')?.innerText,
                                    document.querySelector('#aliyunCaptcha-sliding-text')?.innerText,
                                ].filter(Boolean).join(' ');
                                return {
                                    success: /滑动成功|验证通过|Slide completed|Verification passed/i
                                        .test(text),
                                    failed: /验证失败|滑动失败|Verification failed/i
                                        .test(text),
                                    captchaVisible: visible(
                                        document.querySelector('#aliyunCaptcha-captcha-body')
                                    ),
                                    sliderVisible: visible(
                                        document.querySelector('#aliyunCaptcha-window-float, #aliyunCaptcha-sliding-body')
                                    ),
                                };
                            }"""
                        )
                        if state.get("success"):
                            # Wait for the page's signup response before closing
                            # the browser. Closing on request start can consume
                            # the one-time CAPTCHA without committing signup.
                            response_deadline = time.monotonic() + 20
                            while (
                                time.monotonic() < response_deadline
                                and signup_response["status"] is None
                            ):
                                await asyncio.sleep(0.25)
                            break
                        if (
                            state.get("failed")
                            and time.monotonic() - last_failure_log >= 2
                        ):
                            last_failure_log = time.monotonic()
                            self.log(
                                task_id,
                                "滑块未通过，请重新拖动",
                                "warning",
                            )
                        await asyncio.sleep(0.5)
                    else:
                        raise CaptchaWindowError(
                            f"等待人工滑块超过 {timeout} 秒",
                            "captcha_timeout",
                        )

                    token = str(token_box.get("token") or "")
                    if token:
                        validate_captcha_param(token)
                    elif not signup_response["completed"]:
                        raise CaptchaWindowError(
                            "滑块已完成，但没有捕获 captcha_verify_param",
                            "captcha_token_missing",
                        )
                    else:
                        # The page completed signup itself, but the browser's
                        # auth cookie is still required by the protocol client.
                        token = ""

                    cookies: Dict[str, str] = {}
                    for cookie in await context.cookies():
                        domain = str(cookie.get("domain") or "")
                        cookie_name = str(cookie.get("name") or "")
                        if cookie_name and (not domain or "z.ai" in domain):
                            cookies[cookie_name] = str(cookie.get("value") or "")

                    result = CaptchaSolution(
                        captcha_verify_param=token,
                        provider="local_browser",
                        cookies=cookies,
                        device_id=fingerprint_profile.device_id,
                        signup_response={
                            "status": int(signup_response["status"] or 0),
                            "body": signup_response["body"],
                            "completed": bool(signup_response["completed"]),
                        },
                    )
                    debug_event(
                        "captcha.window.completed",
                        task_id=task_id,
                        captcha_fingerprint=fingerprint(token),
                        cookie_names=sorted(cookies),
                        browser_signup=bool(signup_response["completed"]),
                        browser_signup_status=signup_response["status"],
                        page_errors=len(page_errors),
                        failed_requests=len(failed_requests),
                    )
                    return result
                except Exception as exc:
                    debug_event(
                        "captcha.window.failed",
                        level=logging.ERROR,
                        task_id=task_id,
                        error=str(exc),
                        traceback=traceback.format_exc()[-12000:],
                        page_errors=page_errors[-10:],
                        failed_requests=failed_requests[-10:],
                    )
                    raise
                finally:
                    try:
                        await browser.close()
                    except Exception:
                        debug_event(
                            "captcha.window.close_failed",
                            level=logging.WARNING,
                            task_id=task_id,
                            exc_info=True,
                        )

    async def _restore_protocol_session(self, page: Any, task_id: str) -> None:
        """Load the protocol guest identity into the CAPTCHA browser.

        The browser must use the same guest token as the protocol client;
        otherwise the CAPTCHA result and signup are bound to two sessions.
        """

        state = self.protocol_state or {}
        token = str(state.get("guest_jwt") or "")
        cookies = state.get("cookies")
        if isinstance(cookies, dict) and cookies:
            await page.context.add_cookies(
                [
                    {
                        "name": str(name),
                        "value": str(value),
                        "domain": ".z.ai",
                        "path": "/",
                    }
                    for name, value in cookies.items()
                    if name and value
                ]
            )
        if token:
            await page.context.add_cookies(
                [
                    {
                        "name": "token",
                        "value": token,
                        "domain": ".z.ai",
                        "path": "/",
                    }
                ]
            )
            await page.add_init_script(
                f"localStorage.setItem('token', {token!r});"
            )
        debug_event(
            "captcha.protocol_session_imported",
            task_id=task_id,
            has_guest_jwt=bool(token),
            cookie_names=sorted(cookies) if isinstance(cookies, dict) else [],
        )

    async def _trigger_captcha(
        self,
        page: Any,
        task_id: str,
        create_button: Any,
        captcha_body: Any,
    ) -> None:
        """Wait for the signup form, then trigger CAPTCHA exactly once."""

        deadline = time.monotonic() + 25
        clicked = False
        while time.monotonic() < deadline:
            if await captcha_body.count() and await captcha_body.is_visible():
                debug_event(
                    "captcha.trigger_ready",
                    task_id=task_id,
                    trigger="create_button" if clicked else "already_visible",
                )
                return
            if (
                not clicked
                and await create_button.count()
                and await create_button.is_visible()
            ):
                try:
                    await create_button.click(timeout=8000)
                    clicked = True
                    self.log(
                        task_id,
                        "已自动点击创建账号，正在等待验证码组件",
                        "info",
                    )
                except Exception as exc:
                    debug_event(
                        "captcha.trigger_click_failed",
                        level=logging.WARNING,
                        task_id=task_id,
                        error=str(exc),
                    )
            await asyncio.sleep(0.5)

        raise CaptchaWindowError(
            "注册表单已填写，但验证码组件没有出现",
            "captcha_not_triggered",
        )

    async def _open_signup(
        self,
        page: Any,
        task_id: str,
        name: str,
        email: str,
        password: str,
    ) -> None:
        """Open the registration tab and fill all three fields."""

        email_input = page.locator("input[type='email']:visible").first
        signup_tab = page.locator("button:visible,a:visible").filter(
            has_text=re.compile(r"^\s*(注册|Sign up)\s*$", re.I)
        ).first

        for _ in range(40):
            if await signup_tab.count() and await signup_tab.is_visible():
                break
            email_choice = page.locator("button:visible,a:visible").filter(
                has_text=re.compile(
                    r"Continue\s+with\s+Email|Email|邮箱",
                    re.I,
                )
            ).first
            if await email_choice.count() and await email_choice.is_visible():
                try:
                    await email_choice.click(timeout=2000)
                except Exception:
                    pass
            await page.wait_for_timeout(500)

        if not await signup_tab.count():
            raise CaptchaWindowError(
                "认证页没有找到注册入口",
                "signup_tab_missing",
            )
        await signup_tab.click(timeout=8000)
        await page.wait_for_timeout(800)

        name_input = page.locator("input[type='text']:visible").first
        password_input = page.locator("input[type='password']:visible").first
        await name_input.wait_for(state="visible", timeout=20000)
        await name_input.fill(name or email.split("@")[0])
        await email_input.fill(email)
        await password_input.fill(password)
        debug_event(
            "captcha.signup_form_ready",
            task_id=task_id,
            email_field=await email_input.input_value(),
            name_field=await name_input.input_value(),
        )
