"""Protocol-first registration with a human-only CAPTCHA window."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable, Dict, Optional

from captcha_solver import CaptchaSolution
from captcha_window import LocalCaptchaWindow
from debug_log import event as debug_event, fingerprint
from protocol_client import ProtocolError, ZaiProtocolClient
from protocol_fingerprint import fingerprint_from_task


StatusCallback = Callable[[Dict[str, Any]], None]
ManualVerifyWaiter = Callable[[str, int], Awaitable[str]]


class ProtocolRegistrationWorker:
    """Keep registration on HTTP; open a browser only for the slider."""

    def __init__(
        self,
        config: Dict[str, Any],
        email_service: Any,
        *,
        log_callback: Optional[Callable[[str, str, str], None]] = None,
        manual_verify_waiter: Optional[ManualVerifyWaiter] = None,
        captcha_lock: Optional[asyncio.Lock] = None,
    ) -> None:
        self.config = config
        self.email_service = email_service
        self.log_callback = log_callback
        self.manual_verify_waiter = manual_verify_waiter
        self.captcha_window = LocalCaptchaWindow(
            config,
            log_callback=log_callback,
            captcha_lock=captcha_lock,
        )

    def log(self, task_id: str, message: str, level: str = "info") -> None:
        if not self.log_callback:
            return
        try:
            self.log_callback(task_id, message, level)
        except Exception:
            debug_event(
                "protocol.log_callback_failed",
                level=logging.ERROR,
                task_id=task_id,
                exc_info=True,
            )

    async def execute_task(
        self,
        task: Dict[str, Any],
        *,
        on_status_change: Optional[StatusCallback] = None,
    ) -> Dict[str, Any]:
        task_id = str(task.get("id") or "unknown")
        email = str(task.get("email") or "")
        name = str(task.get("name") or email.split("@")[0])
        password = str(task.get("password") or "")

        def update(status: str, message: str, **fields: Any) -> None:
            task["status"] = status
            task["message"] = message
            task.update(fields)
            if on_status_change:
                on_status_change(task)

        profile = fingerprint_from_task(task, self.config)
        task["fingerprint"] = profile.public_dict()
        task["device_id"] = profile.device_id
        started = time.monotonic()

        # The guest session is bound to one proxy. Retry the whole registration
        # with a fresh client when proxy transport fails before CAPTCHA.
        max_attempts = max(
            1,
            min(
                int(self.config.get("protocol_proxy_retry_attempts", 3)),
                8,
            ),
        )
        if not self.config.get("proxy_enabled", False):
            max_attempts = 1

        for attempt in range(max_attempts):
            proxy_info = self._proxy()
            if self.config.get("proxy_enabled", False) and not proxy_info:
                update(
                    "FAILED",
                    "代理池已启用，但没有可用节点",
                    protocol_error_code="no_healthy_proxy",
                )
                return task
            client = ZaiProtocolClient(
                profile,
                proxy=str((proxy_info or {}).get("requests_proxy") or ""),
                timeout=int(self.config.get("protocol_timeout_sec", 30)),
            )
            debug_event(
                "protocol.start",
                task_id=task_id,
                email=email,
                impersonate=profile.impersonate,
                device_id=profile.device_id,
                proxy=(proxy_info or {}).get("display", ""),
                attempt=attempt + 1,
                max_attempts=max_attempts,
            )
            try:
                result = await self._execute_with_client(
                    task,
                    client,
                    profile,
                    proxy_info or {},
                    name=name,
                    email=email,
                    password=password,
                    task_id=task_id,
                    update=update,
                    on_status_change=on_status_change,
                    started=started,
                )
                if proxy_info:
                    from proxy_manager import report_proxy_success

                    report_proxy_success(proxy_info["raw"])
                return result
            except Exception as exc:
                if proxy_info and self._should_retry_proxy(exc):
                    from proxy_manager import report_proxy_failure

                    info = report_proxy_failure(proxy_info["raw"], str(exc))
                    debug_event(
                        "protocol.proxy_retry",
                        level=logging.WARNING,
                        task_id=task_id,
                        proxy=proxy_info.get("display", ""),
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        failures=info.get("failures"),
                        error=str(exc),
                    )
                    if attempt + 1 < max_attempts:
                        update(
                            "RUNNING",
                            f"代理节点超时，切换节点重试 "
                            f"({attempt + 2}/{max_attempts})",
                        )
                        await asyncio.sleep(1)
                        continue
                self._record_failure(task, task_id, exc, started, update)
                return task

    def _should_retry_proxy(self, exc: Exception) -> bool:
        from proxy_manager import is_proxy_error

        return bool(
            self.config.get("proxy_enabled", False)
            and is_proxy_error(str(exc))
        )

    def _record_failure(
        self,
        task: Dict[str, Any],
        task_id: str,
        exc: Exception,
        started: float,
        update: Callable[..., None],
    ) -> None:
        debug_event(
            "protocol.failed",
            level=logging.ERROR,
            task_id=task_id,
            error=str(exc),
            error_type=type(exc).__name__,
            duration_sec=round(time.monotonic() - started, 3),
            exc_info=True,
        )
        update(
            "FAILED",
            f"协议注册失败: {exc}",
            protocol_error_code=getattr(exc, "code", ""),
        )

    async def _execute_with_client(
        self,
        task: Dict[str, Any],
        client: ZaiProtocolClient,
        profile: Any,
        proxy_info: Dict[str, Any],
        *,
        name: str,
        email: str,
        password: str,
        task_id: str,
        update: Callable[..., None],
        on_status_change: Optional[StatusCallback],
        started: float,
    ) -> Dict[str, Any]:
        update("RUNNING", "纯协议：建立访客会话")
        guest = await asyncio.to_thread(client.bootstrap)
        task["protocol_state"] = client.state_snapshot()
        debug_event(
            "protocol.guest_ready",
            task_id=task_id,
            guest_email=str(guest.get("email") or ""),
            guest_jwt=fingerprint(client.state.guest_jwt),
            cookies=sorted(client.cookie_snapshot()),
        )

        if self.config.get("protocol_check_exists_before_signup", True):
            update("CHECKING_ACCOUNT", "纯协议：检查邮箱状态")
            try:
                exists = await asyncio.to_thread(client.account_exists, email)
            except Exception as exc:
                exists = False
                self.log(
                    task_id,
                    f"邮箱预检未完成，继续注册: {exc}",
                    "warning",
                )
            if exists:
                update(
                    "SKIPPED_EXISTING",
                    f"邮箱预检未完成，继续注册: {exc}",
                    account_exists=True,
                )
                return task

        update("WAITING_CAPTCHA", "请在本机浏览器完成滑块")
        captcha = await self.captcha_window.solve(
            task,
            profile,
            proxy_info or {},
            on_status=self._status_callback(task, update),
        )
        task["captcha_provider"] = captcha.provider
        task["captcha"] = captcha.summary()
        debug_event(
            "protocol.captcha_ready",
            task_id=task_id,
            provider=captcha.provider,
            captcha_fingerprint=fingerprint(captcha.captcha_verify_param),
            cookies=sorted(captcha.cookies),
            browser_signup=bool(
                captcha.signup_response.get("completed")
            ),
        )

        browser_status = int(
            captcha.signup_response.get("status") or 0
        )
        browser_body = captcha.signup_response.get("body")
        browser_signup = bool(captcha.signup_response.get("completed"))
        if browser_status and not browser_signup:
            raise ProtocolError(
                f"Browser signup failed with HTTP {browser_status}",
                code="browser_signup_rejected",
                status=browser_status,
                response_body=browser_body,
            )
        if not browser_signup:
            update("PROTOCOL_SIGNUP", "纯协议：提交注册")
            await asyncio.to_thread(
                client.submit_signup,
                name=name,
                email=email,
                password=password,
                captcha=captcha,
            )
            debug_event("protocol.signup_completed", task_id=task_id)
        else:
            # The browser used its own session to register. Import its
            # cookies before email verification and OAuth.
            client.import_browser_captcha_session(captcha)
            update("PROTOCOL_SIGNUP", "浏览器已完成注册，协议继续激活")

        task["registration_path"] = "protocol_human_captcha"
        task["protocol_signup_submitted"] = True
        task["signup_submitted_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        update("WAITING_EMAIL", "注册已提交，等待验证邮件")
        submitted_at = time.time()
        verify_url = await self._find_verification(
            task_id,
            email,
            submitted_at,
        )
        if not verify_url:
            timeout = int(
                self.config.get("manual_verify_timeout_sec", 600)
            )
            if self.manual_verify_waiter:
                update(
                    "WAITING_MANUAL_VERIFY",
                    "自动收信失败，请手动填写验证链接",
                )
                verify_url = await self.manual_verify_waiter(
                    task_id,
                    timeout,
                )
        if not verify_url:
            update(
                "WAITING_MANUAL_VERIFY",
                    "注册已提交，但未收到验证邮件",
            )
            return task

        update("VERIFYING", "纯协议：激活邮箱")
        await asyncio.to_thread(
            client.finish_signup,
            verify_url_or_token=verify_url,
            name=name,
            email=email,
            password=password,
        )
        task["web_jwt"] = client.state.web_jwt
        task["verify_url"] = verify_url
        debug_event(
            "protocol.email_verified",
            task_id=task_id,
            web_jwt=fingerprint(client.state.web_jwt),
        )

        update("EXTRACTING_TOKEN", "纯协议：换取 ZCode CLI JWT")
        oauth = await asyncio.to_thread(
            client.oauth_exchange,
            timeout_sec=int(
                self.config.get("protocol_oauth_timeout_sec", 30)
            ),
        )
        task.update(
            {
                "status": "SUCCESS",
                    "message": "注册成功，CLI JWT 已提取",
                "cli_jwt": oauth.cli_jwt,
                "jwt": oauth.cli_jwt,
                "web_jwt": oauth.web_jwt or task.get("web_jwt", ""),
                "business_token": oauth.access_token,
                "access_token": oauth.access_token,
                "sub": oauth.sub,
                "device_mid": oauth.device_mid,
                "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        task.pop("jwt_fallback", None)
        debug_event(
            "protocol.completed",
            task_id=task_id,
            duration_sec=round(time.monotonic() - started, 3),
            cli_jwt=fingerprint(oauth.cli_jwt),
            sub=oauth.sub,
            device_mid=oauth.device_mid,
        )
        if on_status_change:
            on_status_change(task)
        await self._import_to_zcode2api(task)
        return task

    async def _import_to_zcode2api(self, task: Dict[str, Any]) -> None:
        if not (
            self.config.get("zcode2api_enabled", False)
            and self.config.get("zcode2api_auto_import", True)
        ):
            return
        task_id = str(task.get("id") or "")
        try:
            from zcode2api_import import Zcode2ApiImporter

            importer = Zcode2ApiImporter(
                str(self.config.get("zcode2api_url") or ""),
                str(self.config.get("zcode2api_admin_password") or ""),
                timeout=int(self.config.get("zcode2api_timeout_sec", 20)),
            )
            result = await asyncio.to_thread(importer.import_task, task)
            task["zcode2api_account_id"] = str(result.get("id") or "")
            task["zcode2api_imported_at"] = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            task["zcode2api_verified"] = bool(result.get("verified"))
            self.log(
                task_id,
                f"已导入 zcode2api 账号库: {task['zcode2api_account_id']}",
                "success",
            )
        except Exception as exc:
            task["zcode2api_import_error"] = str(exc)
            self.log(
                task_id,
                f"zcode2api 自动导入失败: {exc}",
                "warning",
            )
            debug_event(
                "zcode2api.import_failed",
                level=logging.WARNING,
                task_id=task_id,
                error=str(exc),
            )

    def _proxy(self) -> Optional[Dict[str, Any]]:
        if not self.config.get("proxy_enabled", False):
            return None
        from proxy_manager import get_next_task_proxy

        return get_next_task_proxy(self.config)

    def _status_callback(
        self,
        task: Dict[str, Any],
        update: Callable[..., None],
    ) -> Callable[[str, str], Awaitable[None]]:
        async def callback(status: str, message: str) -> None:
            update(status, message)

        return callback

    async def _find_verification(
        self,
        task_id: str,
        email: str,
        since: float,
    ) -> str:
        if not self.config.get("auto_verify_email", True):
            return ""
        if not self.email_service:
            return ""
        provider = str(
            getattr(self.email_service, "provider", "imap") or "imap"
        ).lower()
        configured = bool(getattr(self.email_service, "api_token", ""))
        if provider not in {"api", "cf_dynamic"}:
            configured = all(
                (
                    getattr(self.email_service, "host", ""),
                    getattr(self.email_service, "username", ""),
                    getattr(self.email_service, "password", ""),
                )
            )
        if not configured:
            return ""
        self.log(task_id, "正在轮询邮箱等待验证邮件", "info")
        try:
            return await asyncio.to_thread(
                self.email_service.find_verification_link,
                target_email=email,
                since_timestamp=since,
                timeout=int(
                    self.config.get("email_poll_timeout_sec", 90)
                ),
            ) or ""
        except Exception as exc:
            debug_event(
                "protocol.mail_poll_failed",
                level=logging.WARNING,
                task_id=task_id,
                error=str(exc),
            )
            return ""
