import asyncio
import logging
import re
import sys
import time
import traceback
from typing import Dict, Any, Callable, Optional
from playwright.async_api import async_playwright, Page, BrowserContext, Browser
from debug_log import LOG_FILE as DEBUG_LOG_FILE, event as debug_event, fingerprint
from proxy_manager import (
    get_next_task_proxy,
    report_proxy_failure,
    report_proxy_success,
    is_proxy_error,
    get_proxy_list
)

class RegisterWorker:
    def __init__(
        self,
        config: Dict[str, Any],
        email_service: Any,
        log_callback: Optional[Callable[[str, str], None]] = None,
        captcha_lock: Optional[asyncio.Lock] = None,
        **_ignored_legacy: Any,
    ):
        self.config = config
        self.email_service = email_service
        self.log_callback = log_callback
        self.captcha_lock = captcha_lock or asyncio.Lock()
        self._is_paused = False
        self._current_page: Optional[Page] = None
        self._current_browser: Optional[Browser] = None

    def log(self, task_id: str, message: str, level: str = "info"):
        line = f"[{level.upper()}][{task_id}] {message}"
        try:
            print(line)
        except UnicodeEncodeError:
            encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            safe_line = line.encode(encoding, errors="replace").decode(encoding, errors="replace")
            print(safe_line)
        level_no = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "success": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }.get(level, logging.INFO)
        debug_event(
            "browser.log",
            level=level_no,
            task_id=task_id,
            message=message,
            debug_log=str(DEBUG_LOG_FILE),
        )
        if self.log_callback:
            try:
                self.log_callback(task_id, message, level)
            except Exception:
                debug_event(
                    "browser.log_callback_failed",
                    level=logging.ERROR,
                    task_id=task_id,
                    exc_info=True,
                )

    async def _setup_page_routes(self, page: Page, task_id: str = ""):
        """Silence analytics with successful empty responses.

        Aborting these requests makes the page's global error handlers report
        failed fetches to RUM, which is a conspicuous automation signal.
        """

        from browser_routes import install_analytics_route

        def on_fulfilled(url: str) -> None:
            debug_event(
                "browser.request.analytics_fulfilled",
                task_id=task_id,
                url=url[:1000],
            )

        await install_analytics_route(
            page,
            task_id=task_id,
            on_fulfilled=on_fulfilled,
        )

    async def _click_visible_text(self, page: Page, pattern: str, timeout: int = 20000):
        locator = page.locator("button:visible, a:visible").filter(
            has_text=re.compile(pattern, re.I)
        ).first
        await locator.wait_for(state="visible", timeout=timeout)
        await locator.click()
        return locator

    async def _wait_for_auth_ready(self, page: Page, timeout: int = 30000):
        await page.wait_for_function(
            """() => {
                const visible = e => {
                    const s = getComputedStyle(e);
                    const r = e.getBoundingClientRect();
                    return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
                };
                if ([...document.querySelectorAll('input[type=email]')].some(visible)) return true;
                return [...document.querySelectorAll('button, a')].some(e =>
                    visible(e) && /continue\\s+with\\s+email|email|邮箱/i.test(e.innerText || '')
                );
            }""",
            timeout=timeout,
        )

    async def _prepare_email_signup(self, page: Page, task_id: str):
        """Handle both the provider chooser and the direct Chinese auth form."""
        await self._wait_for_auth_ready(page)
        name_input = page.locator("input[type='text']:visible").first
        email_input = page.locator("input[type='email']:visible").first
        pwd_input = page.locator("input[type='password']:visible").first

        if await email_input.count() == 0:
            self.log(task_id, "检测到登录方式选择页，点击 Email 登录...")
            await self._click_visible_text(
                page,
                r"Continue\s+with\s+Email|Email|邮箱",
                timeout=30000,
            )
            await page.wait_for_timeout(1000)

        if await name_input.count() == 0:
            self.log(task_id, "检测到登录表单，切换到注册模式...")
            await self._click_visible_text(
                page,
                r"^\s*(注册|Sign up)\s*$",
                timeout=15000,
            )
            await page.wait_for_timeout(1000)

        await name_input.wait_for(state="visible", timeout=15000)
        await email_input.wait_for(state="visible", timeout=10000)
        await pwd_input.wait_for(state="visible", timeout=10000)

        create_acc_btn = page.locator("button:visible").filter(
            has_text=re.compile(r"Create Account|创建账号|Sign up|注册", re.I)
        ).first
        await create_acc_btn.wait_for(state="visible", timeout=10000)
        return name_input, email_input, pwd_input, create_acc_btn

    async def _prepare_email_login(self, page: Page, task_id: str):
        """Handle both provider-chooser and direct email/password login pages."""
        await self._wait_for_auth_ready(page)
        email_input = page.locator("input[type='email']:visible").first
        if await email_input.count() == 0:
            self.log(task_id, "检测到登录方式选择页，点击 Email 登录...")
            await self._click_visible_text(
                page,
                r"Continue\s+with\s+Email|Email|邮箱",
                timeout=30000,
            )
            await page.wait_for_timeout(1000)
        await email_input.wait_for(state="visible", timeout=15000)
        pwd_input = page.locator("input[type='password']:visible").first
        await pwd_input.wait_for(state="visible", timeout=10000)
        return email_input, pwd_input

    async def _complete_verification_form(self, page: Page, password: str) -> bool:
        """Complete the post-email password form across old and new layouts."""
        pwd_inputs = page.locator("input[type='password']:visible")
        count = await pwd_inputs.count()
        if count and password:
            for index in range(count):
                await pwd_inputs.nth(index).fill(password)
            await page.wait_for_timeout(400)

        complete_btn = page.locator("button:visible").filter(
            has_text=re.compile(r"Complete Registration|完成注册|创建账号|完成|确认", re.I)
        ).first
        if await complete_btn.count() and await complete_btn.is_visible():
            await complete_btn.click()
            await page.wait_for_timeout(2500)
            return True
        return count > 0

    async def execute_task(self, task: Dict[str, Any], on_status_change: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """
        Executes registration for a single account with automatic proxy failover retry.
        """
        from proxy_manager import get_proxy_list
        all_proxies = get_proxy_list(self.config) if self.config.get("proxy_enabled", False) else []
        max_attempts = max(1, min(len(all_proxies), 8)) if all_proxies else 1

        for attempt in range(max_attempts):
            res = await self._run_register_attempt(task, attempt, max_attempts, on_status_change)
            if res.get("_proxy_retry"):
                continue
            return res
        return task

    async def _run_register_attempt(self, task: Dict[str, Any], attempt: int, max_attempts: int, on_status_change: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        task_id = task["id"]
        email = task["email"]
        name = task.get("name") or email.split("@")[0]
        password = task["password"]

        def update_status(status: str, msg: str = "", extra: Dict[str, Any] = None):
            task["status"] = status
            task["message"] = msg
            if extra:
                task.update(extra)
            if on_status_change:
                on_status_change(task)

        email_provider = str(
            getattr(self.email_service, "provider", "imap") or "imap"
        ).lower()
        email_token = str(getattr(self.email_service, "api_token", "") or "")
        if email_provider in {"api", "cf_dynamic"} and not email_token:
            update_status(
                "FAILED",
                f"找不到 {email} 对应的邮箱 JWT，请检查 CF 邮箱或 API 邮箱池",
            )
            debug_event(
                "task.rejected",
                level=logging.ERROR,
                task_id=task_id,
                email=email,
                reason="mail_token_missing",
                mail_provider=email_provider,
            )
            return task

        update_status("RUNNING", "正在启动浏览器环境...")
        self.log(task_id, f"开始处理注册任务: {email}")

        # This mode deliberately runs a visible browser. The operator must be
        # able to drag the Aliyun slider directly in the Chromium window.
        headless = False
        captcha_timeout = max(60, int(self.config.get("captcha_timeout_sec", 600)))
        email_timeout = int(self.config.get("email_poll_timeout_sec", 90))
        debug_event(
            "task.start",
            task_id=task_id,
            email=email,
            name=name,
            headless=headless,
            captcha_timeout_sec=captcha_timeout,
            email_timeout_sec=email_timeout,
            debug_log=str(DEBUG_LOG_FILE),
        )

        proxy_info = None
        browser = None
        async with async_playwright() as p:
            try:
                launch_options = {
                    "headless": headless,
                    "args": [
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-infobars",
                        "--disable-webrtc",
                        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
                    ],
                    "ignore_default_args": ["--enable-automation"]
                }
                proxy_info = None
                from proxy_manager import get_next_task_proxy
                proxy_info = get_next_task_proxy(self.config)
                if proxy_info:
                    launch_options["proxy"] = proxy_info["playwright_cfg"]
                    self.log(task_id, f"🌐 已成功为浏览器挂载公司代理出口 [{proxy_info['scheme']}]: {proxy_info['display']}", "info")
                elif self.config.get("proxy_enabled", False):
                    raise Exception("代理池已启用，但没有 Playwright 可用节点；已阻止直连以保护本机 IP")
                else:
                    self.log(task_id, "⚠️ 警告：当前未启用代理，所有网络流量将直接暴露本机真实网络！", "warning")

                browser = await p.chromium.launch(**launch_options)
                self._current_browser = browser
                debug_event(
                    "browser.started",
                    task_id=task_id,
                    headless=headless,
                    proxy=(proxy_info or {}).get("display", ""),
                )

                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    screen={"width": 1280, "height": 800},
                    locale=str(self.config.get("protocol_locale") or "zh-CN"),
                    timezone_id=str(
                        self.config.get("protocol_timezone") or "Asia/Shanghai"
                    ),
                    color_scheme="light",
                    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                )
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    window.chrome = { runtime: {}, loadTimes: () => {}, csi: () => {}, app: {} };
                """)
                page = await context.new_page()
                self._current_page = page
                await self._setup_page_routes(page, task_id)

                captcha_solved = asyncio.Event()
                captcha_fail_count = [0]
                captcha_cdn_error = [False]
                browser_closed = [False]
                signup_request = {
                    "seen": False,
                    "captured_at": 0.0,
                    "token": "",
                    "post_keys": [],
                }
                signup_response = {
                    "status": None,
                    "data": None,
                    "error": None,
                    "completed": False,
                }

                page.on("close", lambda: browser_closed.__setitem__(0, True))

                def maybe_submit_after_captcha() -> None:
                    if signup_request["seen"] or not captcha_solved.is_set():
                        return

                    async def submit_once() -> None:
                        try:
                            if await create_acc_btn.is_visible():
                                await create_acc_btn.click(timeout=3000)
                                debug_event(
                                    "captcha.submit_after_success",
                                    task_id=task_id,
                                )
                        except Exception as exc:
                            debug_event(
                                "captcha.submit_after_success_failed",
                                level=logging.WARNING,
                                task_id=task_id,
                                error=str(exc),
                            )

                    asyncio.create_task(submit_once())

                def on_console_msg(msg):
                    text = msg.text
                    lowered = text.lower()
                    debug_event(
                        "browser.console",
                        task_id=task_id,
                        console_type=getattr(msg, "type", ""),
                        text=text[:2000],
                    )
                    if any(
                        marker in lowered
                        for marker in (
                            "init_fail",
                            "error: timeout",
                            "error: network error",
                            "captcha sdk error",
                        )
                    ):
                        self.log(task_id, f"阿里云验证码初始化异常: {text}", "warning")
                        captcha_cdn_error[0] = True
                    elif any(
                        marker in text
                        for marker in (
                            "验证码滑动成功",
                            "滑动成功",
                            "验证通过",
                            "Slide completed",
                            "Verification passed",
                        )
                    ):
                        if not captcha_cdn_error[0]:
                            self.log(task_id, "浏览器报告滑块验证成功", "success")
                            captcha_solved.set()
                            maybe_submit_after_captcha()
                    elif any(
                        marker in text
                        for marker in (
                            "验证码验证失败",
                            "滑动失败",
                            "Verification failed",
                        )
                    ):
                        captcha_fail_count[0] += 1
                        debug_event(
                            "captcha.failed_attempt",
                            level=logging.WARNING,
                            task_id=task_id,
                            attempt=captcha_fail_count[0],
                            text=text[:1000],
                        )
                        self.log(
                            task_id,
                            f"第 {captcha_fail_count[0]} 次滑块未通过，请重新拖动",
                            "warning",
                        )

                page.on("console", on_console_msg)

                def on_page_error(error):
                    debug_event(
                        "browser.page_error",
                        level=logging.ERROR,
                        task_id=task_id,
                        error=str(error)[:2000],
                    )

                def on_request_failed(request):
                    debug_event(
                        "browser.request_failed",
                        level=logging.WARNING,
                        task_id=task_id,
                        url=request.url[:1200],
                        failure=str(request.failure or "")[:1000],
                    )

                page.on("pageerror", on_page_error)
                page.on("requestfailed", on_request_failed)

                async def on_request(request):
                    if "/api/v1/auths/signup" not in request.url:
                        return
                    import json

                    try:
                        payload = request.post_data_json or {}
                    except Exception:
                        try:
                            payload = json.loads(request.post_data or "{}")
                        except Exception:
                            payload = {}
                    token = str(payload.get("captcha_verify_param") or "")
                    signup_request.update(
                        {
                            "seen": True,
                            "captured_at": time.time(),
                            "token": token,
                            "post_keys": sorted(payload) if isinstance(payload, dict) else [],
                        }
                    )
                    debug_event(
                        "signup.request",
                        task_id=task_id,
                        url=request.url,
                        has_captcha=bool(token),
                        captcha_fingerprint=fingerprint(token),
                        post_keys=signup_request["post_keys"],
                    )
                    if token:
                        self.log(
                            task_id,
                            f"已捕获 captcha_verify_param ({fingerprint(token)})",
                            "success",
                        )

                async def on_response(resp):
                    if "/api/v1/auths/signup" not in resp.url:
                        return
                    import json

                    body_text = ""
                    body = None
                    try:
                        body_text = await resp.text()
                        try:
                            body = json.loads(body_text)
                        except Exception:
                            body = body_text[:2000]
                    except Exception as exc:
                        debug_event(
                            "signup.response.read_failed",
                            level=logging.ERROR,
                            task_id=task_id,
                            error=str(exc),
                        )
                    signup_response["status"] = resp.status
                    signup_response["data"] = body
                    if isinstance(body, dict):
                        signup_response["error"] = str(
                            body.get("detail")
                            or body.get("message")
                            or body.get("error")
                            or ""
                        )
                    signup_response["completed"] = (
                        resp.status in {200, 201}
                        and (
                            not isinstance(body, dict)
                            or body.get("success") is True
                        )
                    )
                    debug_event(
                        "signup.response",
                        level=(
                            logging.INFO
                            if signup_response["completed"]
                            else logging.WARNING
                        ),
                        task_id=task_id,
                        status=resp.status,
                        completed=signup_response["completed"],
                        error=signup_response["error"],
                        body=body,
                    )
                    self.log(
                        task_id,
                        f"注册接口响应 HTTP {resp.status}"
                        + (
                            "，注册成功"
                            if signup_response["completed"]
                            else f"，错误: {signup_response['error'] or body}"
                        ),
                        "success" if signup_response["completed"] else "warning",
                    )

                page.on("request", on_request)
                page.on("response", on_response)

                # 1. 打开注册认证页
                self.log(task_id, "正在打开 https://chat.z.ai/auth ...")
                update_status("RUNNING", "正在打开网页...")
                debug_event("auth.navigate", task_id=task_id, url="https://chat.z.ai/auth")
                auth_response = await page.goto(
                    "https://chat.z.ai/auth",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                debug_event(
                    "auth.loaded",
                    task_id=task_id,
                    url=page.url,
                    status=auth_response.status if auth_response else 0,
                )
                await page.bring_to_front()
                if proxy_info:
                    report_proxy_success(proxy_info["raw"])
                await page.wait_for_timeout(1000)

                # 2. 兼容英文登录方式选择页、中文直登页和已进入注册页的情况
                self.log(task_id, "正在准备 Email 注册表单...")
                name_input, email_input, pwd_input, create_acc_btn = await self._prepare_email_signup(page, task_id)

                # 3. 填写表单信息
                self.log(task_id, f"填写账号信息: 姓名={name}, 邮箱={email}")
                update_status("RUNNING", "正在填写注册信息...")

                await name_input.fill(name)
                await page.wait_for_timeout(300)
                await email_input.fill(email)
                await page.wait_for_timeout(300)
                await pwd_input.fill(password)
                await page.wait_for_timeout(800)

                # 4. 点击创建账号，触发人机验证滑块加载。
                # The click may be intercepted by a short-lived loading state.
                # Do not treat that as a fatal error: the visible browser is
                # already available and the operator can retry the control.
                self.log(task_id, "点击创建账号按钮激活人机验证模块...")
                await create_acc_btn.wait_for(state="visible", timeout=8000)
                try:
                    await create_acc_btn.click(timeout=5000)
                except Exception as exc:
                    debug_event(
                        "captcha.trigger_click_failed",
                        level=logging.WARNING,
                        task_id=task_id,
                        error=str(exc),
                    )
                    self.log(
                        task_id,
                        "创建账号按钮首次点击未完成，请在本机浏览器中手动点击",
                        "warning",
                    )
                await page.wait_for_timeout(1000)

                # 6. 等待人机验证滑块按钮加载 ("Click to start verification" / #aliyunCaptcha-captcha-body)
                self.log(task_id, "等待人机滑块按钮渲染 (通常需 5~15 秒网络建连)...")
                captcha_body = page.locator("#aliyunCaptcha-captcha-body").first
                has_captcha = False
                for wait_i in range(30):
                    if await captcha_body.is_visible():
                        has_captcha = True
                        break
                    # 若在第 10 秒仍未渲染，再辅助补点一次 Create Account
                    if wait_i == 10:
                        try:
                            if await create_acc_btn.is_visible():
                                await create_acc_btn.click()
                        except Exception:
                            pass
                    await asyncio.sleep(1)

                if not has_captcha:
                    await page.bring_to_front()
                    update_status(
                        "WAITING_CAPTCHA",
                        "请在本机浏览器中点击创建账号并完成滑块",
                    )
                    self.log(
                        task_id,
                        "未自动检测到验证码入口，请在本机 Chromium 中手动点击创建账号",
                        "warning",
                    )
                    debug_event(
                        "captcha.entry_not_detected",
                        level=logging.WARNING,
                        task_id=task_id,
                        page_url=page.url,
                        proxy=(proxy_info or {}).get("display", ""),
                    )
                    entry_deadline = time.monotonic() + 60
                    while time.monotonic() < entry_deadline:
                        if await captcha_body.is_visible():
                            has_captcha = True
                            break
                        if signup_request["seen"]:
                            break
                        if page.is_closed():
                            raise RuntimeError("验证窗口已关闭")
                        await asyncio.sleep(0.5)
                    if not has_captcha and not signup_request["seen"]:
                        raise TimeoutError(
                            "60 秒内未检测到验证码入口或注册请求"
                        )

                # 7. 直接在本机可见的 Chromium 中完成人工滑块。
                self.log(task_id, "正在排队进入人工滑块窗口...", "info")
                update_status("QUEUED_CAPTCHA", "等待进入人工滑块窗口...")

                async with self.captcha_lock:
                    if captcha_cdn_error[0]:
                        raise Exception(
                            "阿里云验证码 SDK 初始化失败，请检查代理和网络"
                        )

                    await page.bring_to_front()
                    if has_captcha:
                        try:
                            await captcha_body.click(timeout=5000)
                        except Exception:
                            try:
                                await page.locator(
                                    "#aliyunCaptcha-captcha-body"
                                ).click(force=True, timeout=5000)
                            except Exception:
                                self.log(
                                    task_id,
                                    "验证码入口未能自动点击，请在浏览器中手动点击",
                                    "warning",
                                )

                    if has_captcha:
                        try:
                            slider_modal = page.locator(
                                "#aliyunCaptcha-window-float, "
                                "#aliyunCaptcha-sliding-body, .puzzle"
                            ).first
                            await slider_modal.wait_for(
                                state="visible",
                                timeout=15000,
                            )
                        except Exception:
                            self.log(
                                task_id,
                                "未检测到滑块浮层，请检查浏览器页面",
                                "warning",
                            )

                    update_status(
                        "WAITING_CAPTCHA",
                        "请直接在已弹出的本机 Chromium 窗口中拖动滑块",
                    )
                    self.log(
                        task_id,
                        "请在已置顶的 Chromium 窗口中手动完成滑块；程序不会自动拖动",
                        "warning",
                    )
                    debug_event(
                        "captcha.waiting_for_human",
                        task_id=task_id,
                        timeout_sec=captcha_timeout,
                        browser_url=page.url,
                    )

                    start_wait = time.monotonic()
                    last_state_log = 0.0
                    while True:
                        if browser_closed[0] or page.is_closed():
                            raise RuntimeError("验证窗口已关闭，当前任务停止")
                        if captcha_cdn_error[0]:
                            raise RuntimeError(
                                "阿里云验证码 SDK 网络错误，当前任务停止"
                            )
                        if signup_response["completed"]:
                            captcha_solved.set()
                            break
                        if signup_response["status"] is not None:
                            break

                        elapsed = time.monotonic() - start_wait
                        if elapsed > captcha_timeout:
                            raise TimeoutError(
                                f"等待人工滑块超过 {captcha_timeout} 秒"
                            )

                        page_state = await page.evaluate(
                            """() => {
                                const visible = e => !!e &&
                                    e.getClientRects().length > 0 &&
                                    getComputedStyle(e).visibility !== 'hidden';
                                const text = [
                                    document.querySelector('#aliyunCaptcha-captcha-text')?.innerText,
                                    document.querySelector('#aliyunCaptcha-captcha-text-box')?.innerText,
                                    document.querySelector('#aliyunCaptcha-sliding-text')?.innerText,
                                ].filter(Boolean).join(' ');
                                const successNode = document.querySelector(
                                    '.aliyunCaptcha-btn-success,'
                                    + '[class*="captcha-btn-success"],'
                                    + '[class*="success-icon"]'
                                );
                                return {
                                    text: text.slice(0, 500),
                                    success: visible(successNode) ||
                                        /滑动成功|验证通过|Slide completed|Verification passed/i.test(text),
                                    failed: /验证失败|滑动失败|Verification failed/i.test(text),
                                    captchaVisible: visible(
                                        document.querySelector('#aliyunCaptcha-captcha-body')
                                    ),
                                    sliderVisible: visible(
                                        document.querySelector('#aliyunCaptcha-window-float, #aliyunCaptcha-sliding-body')
                                    ),
                                };
                            }"""
                        )
                        if page_state.get("success"):
                            self.log(task_id, "页面已显示滑块验证通过", "success")
                            captcha_solved.set()
                            maybe_submit_after_captcha()
                            break
                        if (
                            page_state.get("failed")
                            and time.monotonic() - last_state_log >= 2
                        ):
                            last_state_log = time.monotonic()
                            self.log(
                                task_id,
                                "页面显示本次滑块未通过，请重新拖动",
                                "warning",
                            )
                        await asyncio.sleep(0.5)

                await page.wait_for_timeout(500)

                # 8. 页面自身通常会发出 signup；若只完成了验证码，再补点一次。
                update_status("RUNNING", "滑块验证通过，正在确认注册提交...")
                self.log(
                    task_id,
                    "滑块验证通过，等待页面提交 /auths/signup...",
                )
                debug_event(
                    "signup.awaiting",
                    task_id=task_id,
                    signup_request_seen=signup_request["seen"],
                    signup_status=signup_response["status"],
                )

                submit_deadline = time.monotonic() + 12
                while time.monotonic() < submit_deadline:
                    if signup_request["seen"] or signup_response["status"] is not None:
                        break
                    await asyncio.sleep(0.25)

                if not signup_request["seen"]:
                    self.log(
                        task_id,
                        "页面尚未发出注册请求，补点一次提交按钮",
                        "warning",
                    )
                    try:
                        await page.locator("#aliyunCaptcha-window-float").wait_for(
                            state="hidden",
                            timeout=3000,
                        )
                    except Exception:
                        pass
                    try:
                        await create_acc_btn.click(timeout=3000)
                    except Exception as click_err:
                        self.log(
                            task_id,
                            f"常规点击被遮挡: {click_err}，改用页面内点击",
                            "info",
                        )
                        await page.evaluate(
                            """() => {
                                const buttons = Array.from(
                                    document.querySelectorAll('button')
                                );
                                const button = buttons.find(
                                    item => /Create Account|创建账号|Sign up|注册/i
                                        .test(item.innerText || '')
                                );
                                if (button) button.click();
                            }"""
                        )

                # 9. 等待服务器响应并跳转至邮箱验证页。
                error_toast = None
                response_deadline = time.monotonic() + 25
                while time.monotonic() < response_deadline:
                    await page.wait_for_timeout(500)
                    if signup_response["completed"]:
                        break
                    if "verify" in page.url:
                        break
                    if signup_response.get("error"):
                        error_toast = signup_response["error"]
                        break

                submitted_ok = bool(
                    signup_response["completed"] or "verify" in page.url
                )
                debug_event(
                    "signup.finished",
                    task_id=task_id,
                    submitted=submitted_ok,
                    request_seen=signup_request["seen"],
                    request_captcha=bool(signup_request["token"]),
                    response_status=signup_response["status"],
                    response_error=signup_response["error"],
                    current_url=page.url,
                )

                current_url = page.url
                self.log(task_id, f"提交后当前 URL: {current_url}")

                if not submitted_ok:
                    # 获取 Svelte Sonner Toast 或常规 Toast 错误
                    error_toast = await page.evaluate("""() => {
                        const sonnerToasts = Array.from(document.querySelectorAll('[data-sonner-toast], [data-title], [data-description]'));
                        for (const st of sonnerToasts) {
                            const txt = (st.querySelector('[data-title]')?.innerText || st.innerText || '').trim();
                            if (txt && !txt.includes('copyright')) return txt;
                        }
                        const toasts = Array.from(document.querySelectorAll('.toast, [role="alert"], [role="status"], .text-red-500, .error, [class*="error"], [class*="toast"]'));
                        for (const t of toasts) {
                            const txt = t.innerText.trim();
                            if (txt && !txt.includes('copyright')) return txt;
                        }
                        return null;
                    }""") or signup_response.get("error")

                    if error_toast:
                        self.log(task_id, f"页面返回提示: {error_toast}", "warning")
                        if "already" in error_toast.lower() or "已存在" in error_toast or "registered" in error_toast.lower():
                            update_status("FAILED", f"邮箱已注册: {error_toast}")
                            await browser.close()
                            return task

                    # 再次尝试点击 Create Account (使用 JS 强制触发)
                    if await create_acc_btn.is_visible() and not submitted_ok:
                        self.log(task_id, "页面未跳转，使用 JS 重新强触 'Create Account'...", "warning")
                        await page.evaluate("""() => {
                            const btns = Array.from(document.querySelectorAll('button'));
                            const btn = btns.find(b => b.innerText && b.innerText.includes('Create Account')) || document.querySelector('button[type="submit"]');
                            if (btn) btn.click();
                        }""")
                        await page.wait_for_timeout(3000)
                        if "verify" in page.url or (signup_response["status"] == 200 and isinstance(signup_response.get("data"), dict) and signup_response["data"].get("success") is True):
                            submitted_ok = True

                if not submitted_ok:
                    if signup_response.get("status") == 405:
                        err_msg = (
                            "注册接口返回 HTTP 405，检查代理出口和页面会话"
                        )
                    else:
                        err_msg = error_toast or (
                            f"注册接口返回 HTTP {signup_response['status']}: "
                            f"{signup_response['data']}"
                            if signup_response["status"]
                            else "未捕获 /auths/signup 请求或响应"
                        )
                    debug_event(
                        "signup.rejected",
                        level=logging.ERROR,
                        task_id=task_id,
                        error=err_msg,
                        response_status=signup_response["status"],
                        request_seen=signup_request["seen"],
                        request_captcha=bool(signup_request["token"]),
                        page_url=page.url,
                    )
                    if proxy_info and is_proxy_error(err_msg):
                        raise Exception(
                            f"当前代理节点提交注册失败 ({err_msg})"
                        )
                    self.log(task_id, err_msg, "error")
                    update_status("FAILED", f"提交失败: {err_msg}")
                    await browser.close()
                    return task

                self.log(task_id, "成功进入邮箱验证页面！", "success")

                # 8. 邮箱验证环节
                signup_submit_time = time.time()
                update_status("WAITING_EMAIL", "已提交注册，正在等待邮箱接收验证邮件...")
                self.log(task_id, f"正在等待邮箱 {email} 接收验证邮件...")

                verify_url = None
                email_provider = str(
                    getattr(self.email_service, "provider", "imap") or "imap"
                ).lower()
                email_configured = bool(
                    getattr(self.email_service, "api_token", "")
                ) if email_provider in {"api", "cf_dynamic"} else bool(
                    self.config.get("imap_host") and self.config.get("imap_user")
                )
                if self.config.get("auto_verify_email", True) and email_configured:
                    verify_url = await asyncio.to_thread(
                        self.email_service.find_verification_link,
                        target_email=email,
                        since_timestamp=signup_submit_time,
                        timeout=email_timeout
                    )

                if verify_url:
                    self.log(task_id, f"成功提取到验证链接: {verify_url}", "success")
                    update_status("VERIFYING", "正在打开验证链接激活账号...")

                    # 打开验证链接激活
                    await page.goto(verify_url, wait_until="domcontentloaded", timeout=30000)
                    await page.wait_for_timeout(1500)

                    # 自动完成邮件验证页面的密码设置（兼容 1 个或 2 个密码框）
                    self.log(task_id, "正在处理邮件验证与账号激活表单...")
                    try:
                        await page.locator("input[type='password']:visible").first.wait_for(
                            state="visible", timeout=8000
                        )
                    except Exception:
                        pass
                    await self._complete_verification_form(page, password)

                    # 等待页面完成账号激活并跳转到 chat.z.ai 主站
                    self.log(task_id, "正在等待账号激活确认并跳转到主站...")
                    try:
                        await page.wait_for_url(lambda u: "/auth/verify" not in u and "chat.z.ai" in u, timeout=25000)
                    except Exception:
                        pass
                    await page.wait_for_timeout(3000)

                    # 9. 提取真实注册账号的 JWT 凭据（严密防止提取到未登录游客 guest token）
                    self.log(task_id, "正在提取账号真实 JWT 认证凭据...")
                    import base64, json
                    web_jwt = ""
                    for _ in range(12):
                        tok_candidate = await page.evaluate("() => localStorage.getItem('token') || localStorage.token || ''")
                        if tok_candidate:
                            try:
                                p_b64 = tok_candidate.split('.')[1]
                                p_b64 += '=' * (4 - len(p_b64) % 4)
                                payload = json.loads(base64.urlsafe_b64decode(p_b64))
                                tok_email = str(payload.get("email", "")).lower()
                                if tok_email and not tok_email.startswith("guest-"):
                                    web_jwt = tok_candidate
                                    break
                            except Exception:
                                pass
                        await asyncio.sleep(1.0)

                    if web_jwt:
                        self.log(
                            task_id,
                            f"已提取 Web JWT ({fingerprint(web_jwt)})",
                            "success",
                        )
                    else:
                        self.log(
                            task_id,
                            "未提取到已认证 Web JWT，继续尝试 OAuth",
                            "warning",
                        )

                    # 10. 通过官方 OAuth 授权流获取 ZCode Coding Plan 专属 JWT（D3-vin/Zcode2Api 所需核心令牌）
                    from zcode_token import fetch_zcode_cli_token, parse_jwt_sub, generate_device_mid
                    self.log(task_id, "正在通过官方 OAuth 授权流提取桌面 CLI 专属 JWT (Coding Plan)...")
                    req_proxy = proxy_info.get("requests_proxy") if proxy_info else None
                    zcode_data = await fetch_zcode_cli_token(page, requests_proxy=req_proxy)

                    extra_data = {
                        "verify_url": verify_url,
                        "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "web_jwt": web_jwt
                    }
                    if zcode_data and zcode_data.get("cli_jwt"):
                        self.log(
                            task_id,
                            "已提取 ZCode CLI JWT "
                            f"({fingerprint(zcode_data.get('cli_jwt'))})",
                            "success",
                        )
                        extra_data["jwt"] = zcode_data["cli_jwt"]
                        extra_data["cli_jwt"] = zcode_data["cli_jwt"]
                        extra_data["device_mid"] = zcode_data["device_mid"]
                        extra_data["sub"] = zcode_data["sub"]
                        extra_data["access_token"] = zcode_data.get("access_token", "")
                    elif web_jwt:
                        self.log(task_id, "已退回使用已认证 Web JWT 作为凭据", "info")
                        extra_data["jwt"] = web_jwt
                        extra_data["sub"] = parse_jwt_sub(web_jwt)
                        extra_data["device_mid"] = generate_device_mid(extra_data["sub"] or web_jwt)

                    if extra_data.get("jwt") or extra_data.get("cli_jwt"):
                        self.log(
                            task_id,
                            "账号激活与 JWT 凭证提取完成",
                            "success",
                        )
                        update_status(
                            "SUCCESS",
                            "注册、验证及真实 JWT 提取成功！",
                            extra_data,
                        )
                    else:
                        self.log(task_id, "⚠️ 邮箱验证链接处理后未能成功提取有效 JWT 凭证", "warning")
                        update_status("WAITING_MANUAL_TOKEN", "邮箱已尝试验证，但未提取到有效 JWT 凭证，请点击「重新提取 JWT」换取凭据。", extra_data)
                else:
                    if email_configured:
                        self.log(task_id, "等待邮件超时，已记录为待手动激活", "warning")
                        update_status("WAITING_MANUAL_TOKEN", "注册已提交，但自动收取验证邮件超时，请在邮件中点击链接或在下方输入链接手动激活。")
                    else:
                        self.log(task_id, "注册已提交！未配置自动读信，请前往邮箱点击验证链接完成激活。", "info")
                        update_status("WAITING_MANUAL_TOKEN", "注册已提交，请收到邮件后点击链接或输入链接完成激活。")

                await browser.close()
                return task

            except Exception as exc:
                err_str = str(exc)
                debug_event(
                    "task.failed",
                    level=logging.ERROR,
                    task_id=task_id,
                    error=err_str,
                    error_type=type(exc).__name__,
                    proxy=(proxy_info or {}).get("display", ""),
                    traceback=traceback.format_exc()[-12000:],
                )
                if browser:
                    try:
                        await browser.close()
                    except Exception:
                        pass
                self.log(task_id, f"捕获到执行异常: {err_str}", "error")

                from proxy_manager import (
                    is_proxy_error,
                    report_proxy_failure,
                    get_next_task_proxy,
                )

                if proxy_info and is_proxy_error(err_str):
                    report_proxy_failure(proxy_info["raw"], err_str)
                    self.log(
                        task_id,
                        f"代理 [{proxy_info['display']}] 连接失效，已移出可用池",
                        "error",
                    )

                    next_proxy = get_next_task_proxy(self.config)
                    if attempt < max_attempts - 1 and next_proxy:
                        self.log(
                            task_id,
                            f"代理异常，切换新节点重试 "
                            f"({attempt + 2}/{max_attempts})",
                            "warning",
                        )
                        update_status(
                            "RUNNING",
                            f"代理连接失败，切换下一节点重试 ({attempt + 1})",
                        )
                        await asyncio.sleep(1)
                        return {"_proxy_retry": True}

                self.log(task_id, f"执行异常: {err_str}", "error")
                update_status("FAILED", f"错误: {err_str}")
                return task
            finally:
                self._current_page = None
                self._current_browser = None
                debug_event(
                    "task.finished",
                    task_id=task_id,
                    status=task.get("status"),
                    message=task.get("message"),
                    debug_log=str(DEBUG_LOG_FILE),
                )

    async def login_and_extract_jwt(
        self,
        email: str,
        password: str,
        task_id: str = "",
    ) -> Dict[str, Any]:
        """Log in locally, wait for the human slider, and extract tokens."""
        timeout = max(60, int(self.config.get("captcha_timeout_sec", 600)))
        debug_event(
            "login.start",
            task_id=task_id,
            email=email,
            timeout_sec=timeout,
        )
        async with async_playwright() as p:
            launch_options = {
                "headless": False,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
                "ignore_default_args": ["--enable-automation"],
            }
            from proxy_manager import get_next_task_proxy

            proxy_info = get_next_task_proxy(self.config)
            if proxy_info:
                launch_options["proxy"] = proxy_info["playwright_cfg"]

            browser = await p.chromium.launch(**launch_options)
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    screen={"width": 1280, "height": 800},
                    locale=str(self.config.get("protocol_locale") or "zh-CN"),
                    timezone_id=str(
                        self.config.get("protocol_timezone") or "Asia/Shanghai"
                    ),
                    user_agent=(
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                )
                page = await context.new_page()
                await self._setup_page_routes(page, task_id)

                def on_console(message):
                    debug_event(
                        "login.console",
                        task_id=task_id,
                        console_type=getattr(message, "type", ""),
                        text=message.text[:2000],
                    )

                def on_request_failed(request):
                    debug_event(
                        "login.request_failed",
                        level=logging.WARNING,
                        task_id=task_id,
                        url=request.url[:1200],
                        failure=str(request.failure or "")[:1000],
                    )

                page.on("console", on_console)
                page.on("requestfailed", on_request_failed)
                self.log(task_id, f"正在打开登录页提取 JWT: {email} ...")
                response = await page.goto(
                    "https://chat.z.ai/auth",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
                debug_event(
                    "login.page_loaded",
                    task_id=task_id,
                    status=response.status if response else 0,
                    url=page.url,
                )
                await page.bring_to_front()
                await page.wait_for_timeout(1000)

                email_input, pwd_input = await self._prepare_email_login(
                    page,
                    task_id,
                )
                await email_input.fill(email)
                await pwd_input.fill(password)
                await page.wait_for_timeout(500)

                sign_in_btn = page.locator("button:visible").filter(
                    has_text=re.compile(r"Sign in|登录", re.I)
                ).first
                await sign_in_btn.wait_for(state="visible", timeout=10000)
                await sign_in_btn.click()
                await page.wait_for_timeout(1000)

                captcha_trigger = page.locator(
                    "#aliyunCaptcha-captcha-body"
                ).first
                if await captcha_trigger.is_visible():
                    try:
                        await captcha_trigger.click(timeout=5000)
                    except Exception:
                        self.log(
                            task_id,
                            "登录验证码入口未自动点击，请在浏览器中手动点击",
                            "warning",
                        )

                await page.bring_to_front()
                self.log(
                    task_id,
                    "请在已弹出的本机 Chromium 窗口中完成登录滑块",
                    "warning",
                )
                debug_event(
                    "login.waiting_for_human",
                    task_id=task_id,
                    timeout_sec=timeout,
                    url=page.url,
                )

                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if page.is_closed():
                        raise RuntimeError("登录验证窗口已关闭")
                    if "auth" not in page.url:
                        break
                    state = await page.evaluate(
                        """() => {
                            const text = [
                                document.querySelector('#aliyunCaptcha-captcha-text')?.innerText,
                                document.querySelector('#aliyunCaptcha-captcha-text-box')?.innerText,
                            ].filter(Boolean).join(' ');
                            return {
                                success: /滑动成功|验证通过|Slide completed|Verification passed/i
                                    .test(text),
                                failed: /验证失败|滑动失败|Verification failed/i
                                    .test(text),
                                text: text.slice(0, 500),
                            };
                        }"""
                    )
                    if state.get("success"):
                        try:
                            await sign_in_btn.click(timeout=3000)
                        except Exception:
                            pass
                        await page.wait_for_timeout(2000)
                        if "auth" not in page.url:
                            break
                    await asyncio.sleep(0.5)

                if "auth" in page.url:
                    raise TimeoutError(
                        f"登录滑块未在 {timeout} 秒内完成"
                    )

                debug_event(
                    "login.completed",
                    task_id=task_id,
                    url=page.url,
                )
                self.log(
                    task_id,
                    "登录成功，正在提取 Web JWT 与 ZCode CLI 凭据",
                )
                web_jwt = await page.evaluate(
                    "() => localStorage.getItem('token') || localStorage.token || ''"
                )
                from zcode_token import (
                    fetch_zcode_cli_token,
                    parse_jwt_sub,
                    generate_device_mid,
                )

                zcode_data = await fetch_zcode_cli_token(page)
                await browser.close()
                res = {"success": True, "web_jwt": web_jwt}
                if zcode_data:
                    res.update(zcode_data)
                elif web_jwt:
                    sub = parse_jwt_sub(web_jwt)
                    res["cli_jwt"] = web_jwt
                    res["sub"] = sub
                    res["device_mid"] = generate_device_mid(sub or web_jwt)
                debug_event(
                    "login.token_result",
                    task_id=task_id,
                    has_web_jwt=bool(web_jwt),
                    has_cli_jwt=bool(res.get("cli_jwt")),
                    web_jwt=fingerprint(web_jwt),
                    cli_jwt=fingerprint(res.get("cli_jwt", "")),
                )
                return res
            except Exception as exc:
                debug_event(
                    "login.failed",
                    level=logging.ERROR,
                    task_id=task_id,
                    error=str(exc),
                    exc_info=True,
                )
                await browser.close()
                return {"success": False, "message": str(exc)}

    async def verify_token_manually(
        self,
        verify_url_or_token: str,
        password: str = "",
        task_id: str = "",
    ) -> Dict[str, Any]:
        """Manually open a verification URL to activate an account and complete signup."""
        url = verify_url_or_token.strip()
        if not url.startswith("http"):
            url = f"https://chat.z.ai/auth/verify_email?token={url}"

        async with async_playwright() as p:
            launch_options = {"headless": False}
            from proxy_manager import get_next_task_proxy

            proxy_info = get_next_task_proxy(self.config)
            if proxy_info:
                launch_options["proxy"] = proxy_info["playwright_cfg"]

            debug_event(
                "manual_verify.start",
                task_id=task_id,
                url=url,
            )
            browser = await p.chromium.launch(**launch_options)
            try:
                page = await browser.new_page()
                await self._setup_page_routes(page, task_id)
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=25000,
                )
                debug_event(
                    "manual_verify.loaded",
                    task_id=task_id,
                    status=response.status if response else 0,
                    url=page.url,
                )
                try:
                    await page.wait_for_selector(
                        "input[type='password'], button, main",
                        timeout=8000,
                    )
                except Exception:
                    pass
                await page.wait_for_timeout(1000)
                await self._complete_verification_form(page, password)

                web_jwt = await page.evaluate(
                    "() => localStorage.getItem('token') || localStorage.token || ''"
                )
                from zcode_token import fetch_zcode_cli_token

                zcode_data = await fetch_zcode_cli_token(page)
                await browser.close()
                debug_event(
                    "manual_verify.completed",
                    task_id=task_id,
                    has_web_jwt=bool(web_jwt),
                    has_cli_jwt=bool(
                        isinstance(zcode_data, dict) and zcode_data.get("cli_jwt")
                    ),
                    web_jwt=fingerprint(web_jwt),
                )
                return {
                    "success": True,
                    "message": "已访问验证链接！账号已激活并提取凭证。",
                    "web_jwt": web_jwt,
                    "zcode_data": zcode_data,
                }
            except Exception as exc:
                debug_event(
                    "manual_verify.failed",
                    level=logging.ERROR,
                    task_id=task_id,
                    error=str(exc),
                    exc_info=True,
                )
                await browser.close()
                return {
                    "success": False,
                    "message": f"访问验证链接失败: {exc}",
                }
