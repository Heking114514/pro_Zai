import asyncio
import os
import secrets
import string
import time
import csv
import io
import json
import logging
import re
from typing import List, Dict, Any, Optional, Callable
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from pydantic import BaseModel

from auth_gate import (
    COOKIE_NAME,
    create_session_value,
    is_authenticated,
    is_public_path,
    login_page,
    login_redirect,
)
from debug_log import LOG_FILE as DEBUG_LOG_FILE, event as debug_event
from traffic_log import TRAFFIC_FILE
from cf_mail import CfMailClient, CfMailError, mailbox_mail_url
from config_manager import load_config, save_config, load_tasks, save_tasks
from email_service import EmailService, parse_mail_api_pool
from protocol_registration import ProtocolRegistrationWorker
from register_worker import RegisterWorker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = FastAPI(title="Z.ai Batch Register WebUI")


@app.middleware("http")
async def remote_access_gate(request: Request, call_next):
    if is_public_path(request.url.path) or is_authenticated(request):
        return await call_next(request)
    if request.headers.get("accept", "").lower().startswith("text/html"):
        return login_redirect(request)
    return Response(content='{"detail":"authentication required"}', status_code=401, media_type="application/json")


@app.get("/login", response_class=HTMLResponse)
async def login_get_api(request: Request):
    if is_authenticated(request):
        return RedirectResponse(request.query_params.get("next", "/"), status_code=303)
    return login_page()


@app.post("/api/login")
async def login_post_api(request: Request):
    form = await request.form()
    supplied = str(form.get("password") or "")
    expected = os.environ.get("PRO_ZAI_PASSWORD", "")
    if expected and secrets.compare_digest(supplied, expected):
        next_path = request.query_params.get("next", "/")
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/"
        response = RedirectResponse(next_path, status_code=303)
        response.set_cookie(
            COOKIE_NAME,
            create_session_value(),
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=7 * 24 * 3600,
        )
        return response
    return login_page("访问密码不正确")
templates = Jinja2Templates(directory=TEMPLATES_DIR)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# In-memory state
config = load_config()
tasks: List[Dict[str, Any]] = load_tasks()

# Automatically recover any tasks left in RUNNING/VERIFYING/QUEUED state from a previous restart
for t in tasks:
    if t.get("status") in [
        "RUNNING",
        "VERIFYING",
        "WAITING_CAPTCHA",
        "WAITING_MANUAL_VERIFY",
        "EXTRACTING_TOKEN",
        "CHECKING_ACCOUNT",
        "SKIPPED_EXISTING",
        "QUEUED_CAPTCHA",
        "QUEUED",
    ]:
        t["status"] = "PENDING"
        t["message"] = "未完成，已自动重置为待执行"
save_tasks(tasks)

active_websockets: Dict[WebSocket, Optional[str]] = {}
is_running_batch = False
stop_requested = False
save_lock = asyncio.Lock()
captcha_lock = asyncio.Lock()
active_task_executions: set[str] = set()
batch_queue_task: Optional[asyncio.Task] = None
manual_verify_waiters: Dict[str, asyncio.Future] = {}


def _resolve_waiter(waiters: Dict[str, asyncio.Future], task_id: str, value: str) -> bool:
    future = waiters.get(task_id)
    if not future or future.done():
        return False
    future.set_result(value)
    return True


async def _send_json_now(websocket: WebSocket, payload: Dict[str, Any]) -> bool:
    try:
        await asyncio.wait_for(websocket.send_json(payload), timeout=1.0)
        return True
    except Exception:
        active_websockets.pop(websocket, None)
        return False


async def wait_for_manual_verify(task_id: str, timeout: int) -> str:
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    manual_verify_waiters[task_id] = future
    try:
        return await asyncio.wait_for(future, timeout=max(30, int(timeout)))
    finally:
        manual_verify_waiters.pop(task_id, None)


def get_email_service(target_email: Optional[str] = None) -> EmailService:
    cfg = load_config()
    provider = str(cfg.get("mail_provider") or "imap").lower()
    if provider in {"api", "cf_dynamic"}:
        entries = parse_mail_api_pool(
            cfg.get("mail_api_pool", ""),
            cfg.get("mail_api_url", ""),
        )
        entry = None
        if target_email:
            target_clean = target_email.strip().lower()
            # A dynamically allocated mailbox is stored on the task itself. This
            # must win over the static pool so retries reuse the same inbox.
            for task in tasks:
                if str(task.get("email", "")).lower() != target_clean:
                    continue
                if task.get("mail_jwt"):
                    entry = {
                        "email": target_clean,
                        "api_url": task.get("mail_api_url")
                        or mailbox_mail_url(str(cfg.get("cf_mail_base") or "")),
                        "token": str(task["mail_jwt"]),
                    }
                break
            if entry is None:
                entry = next((item for item in entries if item["email"] == target_clean), None)
        elif entries:
            entry = entries[0]
        return EmailService(
            provider=provider,
            api_url=entry["api_url"] if entry else cfg.get("mail_api_url", ""),
            api_token=entry["token"] if entry else "",
        )
    return EmailService(
        provider="imap",
        host=cfg.get("imap_host", ""),
        port=int(cfg.get("imap_port", 993)),
        ssl=bool(cfg.get("imap_ssl", True)),
        username=cfg.get("imap_user", ""),
        password=cfg.get("imap_pass", ""),
        folder=cfg.get("imap_folder", "INBOX")
    )

def cdp_callback(task_id: str, action: str, data: Any = None):
    """Legacy notification hook retained for callers that only need status."""
    if action in {"START", "PAGE", "STOP"}:
        target = next((item for item in tasks if item["id"] == task_id), None)
        debug_event(
            "browser.notify",
            task_id=task_id,
            action=action,
            status=(target or {}).get("status"),
            message=(target or {}).get("message"),
        )

async def broadcast(
    event_type: str,
    data: Any,
    *,
    task_id: Optional[str] = None,
):
    payload = {"type": event_type, "data": data, "timestamp": time.time()}
    sockets = [
        websocket
        for websocket, bound_task in list(active_websockets.items())
        if task_id is None or bound_task == task_id
    ]
    if not sockets:
        return
    # A dead tab must not serialize behind other dead tabs. Every send has its
    # own one-second bound and all sockets are attempted concurrently.
    await asyncio.gather(
        *(_send_json_now(websocket, payload) for websocket in sockets),
        return_exceptions=True,
    )

def sync_log_callback(task_id: str, message: str, level: str):
    asyncio.create_task(broadcast("LOG", {
        "task_id": task_id,
        "message": message,
        "level": level,
        "time": time.strftime("%H:%M:%S")
    }))

def on_task_status_change(task: Dict[str, Any]):
    save_tasks(tasks)
    asyncio.create_task(broadcast("TASK_UPDATED", task))

def generate_random_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*" for c in pwd)):
            return pwd


ENGLISH_FIRST_NAMES = (
    "Alex", "Alice", "Amber", "Andrew", "Anna", "Arthur", "Austin", "Ben",
    "Blake", "Brian", "Caleb", "Carol", "Chris", "Claire", "Daniel", "David",
    "Diana", "Ella", "Emily", "Eric", "Ethan", "Eva", "Frank", "Grace",
    "Henry", "Iris", "Jack", "James", "Jason", "Jenny", "John", "Julia",
    "Kevin", "Laura", "Leo", "Linda", "Lucas", "Maria", "Mark", "Mason",
    "Mia", "Michael", "Nancy", "Nina", "Oliver", "Oscar", "Paul", "Peter",
    "Rachel", "Robert", "Ryan", "Sarah", "Sophia", "Steven", "Thomas", "Tina",
    "Victor", "Wendy", "William", "Zoe",
)
ENGLISH_LAST_NAMES = (
    "Adams", "Allen", "Baker", "Bell", "Brooks", "Brown", "Carter", "Clark",
    "Collins", "Cooper", "Davis", "Edwards", "Evans", "Foster", "Garcia",
    "Green", "Hall", "Harris", "Hill", "Howard", "Jackson", "James", "King",
    "Lee", "Lewis", "Martin", "Miller", "Moore", "Morgan", "Nelson", "Parker",
    "Reed", "Roberts", "Smith", "Taylor", "Thomas", "Turner", "Walker",
    "Ward", "White", "Wilson", "Wright", "Young",
)


def generate_english_name(used_names: set[str]) -> str:
    for _ in range(200):
        first = secrets.choice(ENGLISH_FIRST_NAMES)
        if secrets.randbelow(4) == 0:
            name = first
        else:
            name = f"{first} {secrets.choice(ENGLISH_LAST_NAMES)}"
        if name.lower() not in used_names:
            used_names.add(name.lower())
            return name
    name = f"{secrets.choice(ENGLISH_FIRST_NAMES)} {secrets.choice(ENGLISH_LAST_NAMES)} {secrets.token_hex(2)}"
    used_names.add(name.lower())
    return name


def build_task(name: str, email: str, password: str) -> Dict[str, Any]:
    return {
        "id": f"task_{secrets.token_hex(4)}",
        "name": name,
        "email": email,
        "password": password,
        "status": "PENDING",
        "message": "等待执行",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def allocate_cf_task(
    cfg: Dict[str, Any],
    existing_tasks: List[Dict[str, Any]],
    name: str = "",
    password: str = "",
) -> Dict[str, Any]:
    client = CfMailClient(
        str(cfg.get("cf_mail_base") or "https://mail.example.com"),
        site_password=str(cfg.get("cf_mail_site_password") or ""),
        timeout=int(cfg.get("cf_mail_create_timeout_sec", 20)),
    )
    used_emails = {str(task.get("email", "")).lower() for task in existing_tasks}
    used_names = {str(task.get("name", "")).lower() for task in existing_tasks}
    display_name = name.strip() or generate_english_name(used_names)
    mailbox = client.allocate(
        requested_name=display_name,
        domain=str(cfg.get("cf_mail_domain") or "example.com"),
        existing_emails=used_emails,
    )
    client.wait_until_ready(
        mailbox.jwt,
        timeout=int(cfg.get("cf_mail_create_timeout_sec", 20)),
    )
    task = build_task(
        display_name,
        mailbox.email,
        password or generate_random_password(),
    )
    task.update(
        {
            "mail_provider": "cf_dynamic",
            "mail_jwt": mailbox.jwt,
            "mail_api_url": mailbox.api_url,
            "mail_address_id": mailbox.address_id,
        }
    )
    return task


def generate_tasks_from_mailboxes(cfg: Dict[str, Any], existing_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if cfg.get("mail_provider", "imap").lower() != "api":
        return []
    entries = parse_mail_api_pool(
        cfg.get("mail_api_pool", ""),
        cfg.get("mail_api_url", ""),
    )
    used_emails = {str(task.get("email", "")).lower() for task in existing_tasks}
    used_names = {str(task.get("name", "")).lower() for task in existing_tasks}
    generated: List[Dict[str, Any]] = []
    for entry in entries:
        email = entry["email"]
        if not email or email in used_emails:
            continue
        task = build_task(
            generate_english_name(used_names),
            email,
            generate_random_password(),
        )
        generated.append(task)
        used_emails.add(email)
    return generated

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets[websocket] = None
    # Use the authoritative in-memory task objects. Replacing the module list
    # with load_tasks() disconnects the objects held by the running worker.
    await websocket.send_json({"type": "INIT", "tasks": tasks, "config": load_config()})

    try:
        while True:
            # Status and log events are server-to-client. Client messages are
            # drained so a stale browser tab cannot fill the socket buffer.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        active_websockets.pop(websocket, None)

@app.get("/api/health")
async def health_api():
    return {
        "status": "ok",
        "service": "pro-zai",
        "registration_mode": "protocol_with_human_captcha",
        "headless": False,
        "browser_scope": "captcha_only",
        "auth_mode": "protocol",
        "data_dir": os.path.dirname(__import__("config_manager").CONFIG_FILE),
        "playwright": bool(os.environ.get("PLAYWRIGHT_BROWSERS_PATH")),
        "debug_log": str(DEBUG_LOG_FILE),
        "traffic_log": str(TRAFFIC_FILE),
    }


@app.get("/api/runtime")
async def runtime_api():
    runtime_config = load_config()
    return {
        "registration_mode": "protocol_with_human_captcha",
        "captcha_mode": "human_slider_only",
        "captcha_ui_mode": "local_window",
        "mail_provider": runtime_config.get("mail_provider"),
        "browser_windows": 1,
        "target_count": int(runtime_config.get("target_count") or 1),
        "data_dir": os.path.dirname(__import__("config_manager").CONFIG_FILE),
        "debug_log": str(DEBUG_LOG_FILE),
    }


@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


def _tail_text_file(path: str, limit: int = 2000) -> str:
    if not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return "".join(handle.readlines()[-limit:])


@app.get("/api/debug-log", response_class=Response)
async def debug_log_api():
    """Return the current structured debug log for operator troubleshooting."""
    content = _tail_text_file(DEBUG_LOG_FILE)
    return Response(
        content=content or "debug log has not been created yet\n",
        media_type="text/plain",
    )


@app.get("/api/traffic-log", response_class=Response)
async def traffic_log_api():
    """Return sanitized protocol and CAPTCHA-browser traffic records."""
    content = _tail_text_file(TRAFFIC_FILE)
    return Response(
        content=content or "traffic log has not been created yet\n",
        media_type="text/plain",
    )

@app.get("/api/config")
async def get_config_api():
    return get_masked_config()

@app.post("/api/config")
async def update_config_api(data: Dict[str, Any] = Body(...)):
    global config
    current = load_config()
    if data.get("imap_pass") == "******":
        data["imap_pass"] = current.get("imap_pass", "")
    if data.get("proxy_password") == "******":
        data["proxy_password"] = current.get("proxy_password", "")
    if data.get("mail_api_pool") == "******":
        data["mail_api_pool"] = current.get("mail_api_pool", "")
    if data.get("cf_mail_site_password") == "******":
        data["cf_mail_site_password"] = current.get("cf_mail_site_password", "")
    save_config(data)
    config = load_config()
    await broadcast("CONFIG_UPDATED", get_masked_config())
    return {"success": True, "config": get_masked_config()}

def get_masked_config():
    cfg = load_config()
    m = cfg.copy()
    if m.get("imap_pass"):
        m["imap_pass"] = "******"
    if m.get("proxy_password"):
        m["proxy_password"] = "******"
    if m.get("mail_api_pool"):
        m["mail_api_pool"] = "******"
    if m.get("cf_mail_site_password"):
        m["cf_mail_site_password"] = "******"
    return m

@app.post("/api/config/test-proxy")
async def test_proxy_api(data: Dict[str, Any] = Body(...)):
    import requests
    server = data.get("proxy_server", "").strip()
    if not server:
        return {"success": False, "message": "请提供代理服务器地址 (例如: http://1.2.3.4:8080 或 socks5://1.2.3.4:1080)"}

    current = load_config()
    pwd = data.get("proxy_password")
    if pwd == "******" or not pwd:
        pwd = current.get("proxy_password", "")
    username = data.get("proxy_username", "").strip()

    parsed_proxy = server
    if username and pwd and "@" not in server:
        parts = server.split("://", 1)
        if len(parts) == 2:
            parsed_proxy = f"{parts[0]}://{username}:{pwd}@{parts[1]}"
        else:
            parsed_proxy = f"http://{username}:{pwd}@{server}"

    proxies = {
        "http": parsed_proxy,
        "https": parsed_proxy
    }

    def run_test():
        urls = ["https://api.ipify.org?format=json", "https://httpbin.org/ip", "https://ipinfo.io/json"]
        last_err = None
        for u in urls:
            try:
                r = requests.get(u, proxies=proxies, timeout=10)
                if r.status_code == 200:
                    resp_data = r.json()
                    ip = resp_data.get("ip") or resp_data.get("origin")
                    return {"success": True, "ip": ip, "message": f"代理测试连通成功！当前出口 IP 为: {ip}"}
            except Exception as e:
                last_err = e
        return {"success": False, "message": f"代理连接失败: {str(last_err)}"}

    res = await asyncio.to_thread(run_test)
    return res

@app.get("/api/config/disabled-proxies")
async def get_disabled_proxies_api():
    from proxy_manager import get_disabled_proxies
    return {"disabled": list(get_disabled_proxies().values())}

@app.post("/api/config/reset-proxies")
async def reset_proxies_api():
    from proxy_manager import reset_disabled_proxies
    reset_disabled_proxies()
    return {"success": True, "message": "已重置所有被禁用的代理，全部恢复为可用状态"}

@app.post("/api/config/test-proxies")
async def test_proxies_api(data: Dict[str, Any] = Body(...)):
    from proxy_manager import test_proxies_async
    raw_text = data.get("proxy_pool", "") or ""
    lines = [l.strip() for l in raw_text.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines and data.get("proxy_server"):
        lines.append(data["proxy_server"].strip())
    if not lines:
        return {"success": False, "message": "未输入任何有效代理地址，请在文本框中每行填写一个代理"}

    results = await test_proxies_async(lines)
    success_count = sum(1 for r in results if r.get("success"))
    return {
        "success": True,
        "total": len(results),
        "available": success_count,
        "results": results
    }

@app.post("/api/config/test-email")
async def test_email_api(data: Dict[str, Any] = Body(...)):
    current = load_config()
    provider = str(data.get("mail_provider") or current.get("mail_provider", "imap")).lower()

    if provider == "cf_dynamic":
        client = CfMailClient(
            str(data.get("cf_mail_base") or current.get("cf_mail_base") or ""),
            site_password=str(
                data.get("cf_mail_site_password")
                if data.get("cf_mail_site_password") != "******"
                else current.get("cf_mail_site_password", "")
            ),
            timeout=int(data.get("cf_mail_create_timeout_sec") or 20),
        )
        try:
            mailbox = await asyncio.to_thread(
                client.create_address,
                domain=str(data.get("cf_mail_domain") or current.get("cf_mail_domain") or ""),
            )
            await asyncio.to_thread(client.wait_until_ready, mailbox.jwt, 20)
            return {
                "success": True,
                "message": f"CF 邮箱 API 可用，测试地址: {mailbox.email}",
                "test_address": mailbox.email,
            }
        except (CfMailError, ValueError) as exc:
            return {"success": False, "message": f"CF 邮箱 API 测试失败: {exc}"}

    if provider == "api":
        pool_text = data.get("mail_api_pool")
        if pool_text == "******" or not pool_text:
            pool_text = current.get("mail_api_pool", "")
        api_url = data.get("mail_api_url") or current.get("mail_api_url", "")
        entries = parse_mail_api_pool(pool_text, api_url)
        if not entries:
            return {"success": False, "message": "API 邮箱池为空，请按“邮箱----JWT”每行一个填写"}
        svc = EmailService(
            provider="api",
            api_url=entries[0]["api_url"],
            api_token=entries[0]["token"],
        )
    else:
        pwd = data.get("imap_pass")
        if pwd == "******" or not pwd:
            pwd = current.get("imap_pass", "")
        svc = EmailService(
            provider="imap",
            host=data.get("imap_host", ""),
            port=int(data.get("imap_port", 993)),
            ssl=bool(data.get("imap_ssl", True)),
            username=data.get("imap_user", ""),
            password=pwd,
            folder=data.get("imap_folder", "INBOX")
        )

    res = await asyncio.to_thread(svc.test_connection)
    return res

@app.get("/api/tasks")
async def get_tasks_api():
    # Never replace the live task list from disk here. Workers retain direct
    # references to task dictionaries, so swapping the module list makes the
    # API expose stale PENDING copies while the worker advances another object.
    return tasks

class BatchAddRequest(BaseModel):
    batch_text: str
    default_password: Optional[str] = None
    auto_start: Optional[bool] = False
    target_count: Optional[int] = 1

@app.post("/api/tasks/add")
async def add_tasks_api(req: BatchAddRequest):
    lines = [line.strip() for line in req.batch_text.splitlines() if line.strip()]
    added = []
    existing_emails = {t["email"].lower() for t in tasks}
    mail_cfg = load_config()
    mail_provider = str(mail_cfg.get("mail_provider") or "imap").lower()
    api_mode = mail_provider == "api"
    cf_dynamic_mode = mail_provider == "cf_dynamic"
    api_pool = parse_mail_api_pool(
        mail_cfg.get("mail_api_pool", ""),
        mail_cfg.get("mail_api_url", ""),
    ) if api_mode else []
    api_pool_emails = {item["email"] for item in api_pool}
    api_available = [item["email"] for item in api_pool if item["email"] not in existing_emails]

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue

        parts = [p.strip() for p in line_str.replace("，", ",").split(",")]
        name = ""
        email = ""
        pwd = req.default_password or ""

        if len(parts) == 1:
            raw = parts[0]
            if "@" in raw:
                email = raw
                name = email.split("@")[0]
            else:
                # 用户仅输入英文名字，例如 "Alex" 或 "David Miller"
                name = raw
                clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '', name.lower().replace(" ", "_"))
                if not clean_name:
                    clean_name = f"user_{secrets.token_hex(3)}"
                email = "" if cf_dynamic_mode else f"verify+{clean_name}@gotclass.xyz"
        elif len(parts) == 2:
            if "@" in parts[1]:
                name, email = parts[0], parts[1]
            elif "@" in parts[0]:
                email, name = parts[0], parts[1]
            else:
                name = parts[0]
                clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '', name.lower().replace(" ", "_"))
                email = "" if cf_dynamic_mode else f"verify+{clean_name}@gotclass.xyz"
                pwd = parts[1]
        elif len(parts) >= 3:
            name, email, pwd = parts[0], parts[1], parts[2]
            if "@" not in email and not cf_dynamic_mode:
                clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '', email.lower().replace(" ", "_"))
                email = f"verify+{clean_name}@gotclass.xyz"

        if cf_dynamic_mode:
            if email and "@" in email:
                raise HTTPException(
                    status_code=400,
                    detail="CF 动态邮箱模式只需输入英文姓名，系统会自动申请邮箱",
                )
            if not name:
                name = generate_english_name(
                    {str(item.get("name", "")).lower() for item in tasks + added}
                )
            try:
                task = await asyncio.to_thread(
                    allocate_cf_task,
                    mail_cfg,
                    tasks + added,
                    name,
                    pwd,
                )
            except CfMailError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=f"CF 邮箱自动申请失败: {exc}",
                ) from exc
            tasks.append(task)
            added.append(task)
            existing_emails.add(task["email"])
            save_tasks(tasks)
            await broadcast("TASKS_ADDED", [task])
            continue

        if api_mode:
            if not api_pool:
                raise HTTPException(status_code=400, detail="API 邮箱池为空，请先保存邮箱池配置")
            if not email or "@" not in email or email.lower().endswith("@gotclass.xyz"):
                if not api_available:
                    raise HTTPException(status_code=400, detail="API 邮箱池中的可用邮箱已用完")
                email = api_available.pop(0)
            elif email.lower() not in api_pool_emails:
                raise HTTPException(status_code=400, detail=f"邮箱 {email} 不在 API 邮箱池中")
            elif email.lower() in existing_emails:
                raise HTTPException(status_code=400, detail=f"API 邮箱 {email} 已在任务列表中")
            else:
                api_available = [item for item in api_available if item != email.lower()]

        # 确保邮箱唯一（若重复则自动附加短随机后缀）
        base_email = email
        dup_counter = 1
        while email.lower() in existing_emails:
            name_part, domain_part = base_email.split("@")
            email = f"{name_part}_{dup_counter}@{domain_part}"
            dup_counter += 1
        existing_emails.add(email.lower())

        if not pwd:
            pwd = "Password123!@#"

        task = build_task(name, email, pwd)
        tasks.append(task)
        added.append(task)

    save_tasks(tasks)
    await broadcast("TASKS_ADDED", added)

    # 若勾选了自动启动
    global is_running_batch, stop_requested
    requested_target = max(1, int(req.target_count or len(added) or 1))
    pending_total = sum(
        1 for item in tasks if item.get("status") == "PENDING"
    )
    warning = ""
    if req.auto_start and pending_total < requested_target:
        warning = (
            f"目标账号数为 {requested_target}，当前只有 {pending_total} 个 "
            "PENDING 任务；导入已保存，但未自动启动队列。"
        )
        sync_log_callback("SYSTEM", warning, "warning")
    elif req.auto_start and not is_running_batch:
        stop_requested = False
        cfg = load_config()
        cfg["target_count"] = requested_target
        save_config(cfg)
        global batch_queue_task
        batch_queue_task = asyncio.create_task(
            run_batch_queue(requested_target)
        )

    return {
        "success": True,
        "count": len(added),
        "auto_started": bool(req.auto_start and not warning),
        "target_count": requested_target,
        "pending_count": pending_total,
        "warning": warning,
    }

@app.post("/api/tasks/clear")
async def clear_tasks_api(clear_type: str = Body(default="all")):
    global tasks
    if clear_type == "completed":
        tasks = [t for t in tasks if t.get("status") not in ["SUCCESS", "FAILED"]]
    else:
        tasks = []
    save_tasks(tasks)
    await broadcast("TASKS_CLEARED", {"tasks": tasks})
    return {"success": True, "tasks": tasks}

@app.delete("/api/tasks/{task_id}")
async def delete_task_api(task_id: str):
    global tasks
    tasks = [t for t in tasks if t["id"] != task_id]
    save_tasks(tasks)
    await broadcast("TASK_DELETED", {"task_id": task_id})
    return {"success": True}

async def execute_registration_task(
    cfg: Dict[str, Any],
    email_svc: EmailService,
    task: Dict[str, Any],
    on_status_change: Callable[[Dict[str, Any]], None],
) -> Dict[str, Any]:
    """Run protocol registration; open a browser only for the slider."""

    debug_event(
        "registration.dispatch",
        task_id=str(task.get("id") or ""),
        email=str(task.get("email") or ""),
        mode="protocol_with_human_captcha",
        configured_mode=cfg.get("registration_mode"),
        debug_log=str(DEBUG_LOG_FILE),
    )
    worker = ProtocolRegistrationWorker(
        cfg,
        email_svc,
        log_callback=sync_log_callback,
        manual_verify_waiter=wait_for_manual_verify,
        captcha_lock=captcha_lock,
    )
    return await worker.execute_task(
        task,
        on_status_change=on_status_change,
    )


async def run_batch_queue(target_count: int = 1):
    """Run exactly one visible browser at a time for ``target_count`` tasks."""

    global is_running_batch, stop_requested
    is_running_batch = True
    stop_requested = False
    requested = max(1, int(target_count))
    processed = 0

    cfg = load_config()
    await broadcast(
        "BATCH_STATUS",
        {
            "running": True,
            "concurrency": 1,
            "target_count": requested,
            "processed": 0,
        },
    )
    sync_log_callback(
        "SYSTEM",
        f"本机人工滑块队列已启动：目标 {requested} 个账号，浏览器单窗口串行",
        "info",
    )
    debug_event(
        "batch.start",
        target_count=requested,
        browser_windows=1,
    )

    try:
        while not stop_requested and processed < requested:
            task_to_run = None
            async with save_lock:
                for item in tasks:
                    if item["status"] == "PENDING":
                        item["status"] = "QUEUED"
                        item["message"] = (
                            f"目标队列 {processed + 1}/{requested}，准备启动浏览器"
                        )
                        task_to_run = item
                        break

            if task_to_run is None:
                sync_log_callback(
                    "SYSTEM",
                    "没有剩余 PENDING 任务，目标队列提前结束",
                    "warning",
                )
                break

            save_tasks(tasks)
            await broadcast("TASK_UPDATED", task_to_run)
            sync_log_callback(
                task_to_run["id"],
                f"目标进度 {processed + 1}/{requested}：启动本机 Chromium",
                "info",
            )
            email_svc = get_email_service(task_to_run.get("email"))
            try:
                await execute_registration_task(
                    cfg,
                    email_svc,
                    task_to_run,
                    on_task_status_change,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                task_to_run["status"] = "FAILED"
                task_to_run["message"] = f"队列执行异常: {exc}"
                on_task_status_change(task_to_run)
                debug_event(
                    "batch.task_failed",
                    level=logging.ERROR,
                    task_id=task_to_run["id"],
                    error=str(exc),
                    exc_info=True,
                )
            finally:
                processed += 1
                await broadcast(
                    "BATCH_STATUS",
                    {
                        "running": True,
                        "concurrency": 1,
                        "target_count": requested,
                        "processed": processed,
                    },
                )

            if processed < requested and not stop_requested:
                await asyncio.sleep(1)
    finally:
        is_running_batch = False
        await broadcast(
            "BATCH_STATUS",
            {
                "running": False,
                "concurrency": 1,
                "target_count": requested,
                "processed": processed,
            },
        )
        sync_log_callback(
            "SYSTEM",
            f"队列结束：已处理 {processed}/{requested} 个账号",
            "info",
        )
        debug_event(
            "batch.finished",
            target_count=requested,
            processed=processed,
            stopped=stop_requested,
        )

@app.post("/api/tasks/start")
async def start_batch_api(data: Dict[str, Any] = Body(default={})):
    global is_running_batch, stop_requested, batch_queue_task
    cfg = load_config()
    requested = data.get(
        "target_count",
        cfg.get("target_count", 1),
    )
    try:
        target_count = max(1, int(requested))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="目标账号数必须是正整数") from exc

    cfg["target_count"] = target_count
    save_config(cfg)

    if is_running_batch and batch_queue_task and not batch_queue_task.done():
        raise HTTPException(status_code=409, detail="当前已有注册队列正在运行")

    generated = []
    provider = str(cfg.get("mail_provider") or "imap").lower()
    for item in tasks:
        if item.get("status") == "QUEUED":
            item["status"] = "PENDING"
            item["message"] = "等待执行"
    pending_count = sum(1 for item in tasks if item.get("status") == "PENDING")

    if pending_count < target_count and provider == "api":
        mail_pool = parse_mail_api_pool(
            cfg.get("mail_api_pool", ""),
            cfg.get("mail_api_url", ""),
        )
        if mail_pool:
            generated = generate_tasks_from_mailboxes(cfg, tasks)
            generated = generated[: max(0, target_count - pending_count)]
            if generated:
                tasks.extend(generated)
                save_tasks(tasks)
                await broadcast("TASKS_ADDED", generated)
                pending_count += len(generated)
                sync_log_callback(
                    "SYSTEM",
                    f"已从邮箱池生成 {len(generated)} 个任务",
                    "info",
                )

    if pending_count < target_count and provider == "cf_dynamic":
        while pending_count < target_count and not stop_requested:
            try:
                task = await asyncio.to_thread(allocate_cf_task, cfg, tasks)
            except CfMailError as exc:
                debug_event(
                    "batch.mail_allocation_failed",
                    level=logging.ERROR,
                    error=str(exc),
                    requested_target=target_count,
                    pending_count=pending_count,
                )
                break
            tasks.append(task)
            generated.append(task)
            pending_count += 1
            save_tasks(tasks)
            await broadcast("TASKS_ADDED", [task])
            sync_log_callback(
                "SYSTEM",
                f"CF 动态邮箱已申请: {task['email']}",
                "info",
            )

    if pending_count <= 0:
        raise HTTPException(
            status_code=409,
            detail="没有可执行的 PENDING 任务，请先导入账号",
        )

    effective_target = min(target_count, pending_count)
    if effective_target < target_count:
        sync_log_callback(
            "SYSTEM",
            f"目标账号数为 {target_count}，当前可用 {pending_count} 个；"
            f"本次只处理 {effective_target} 个",
            "warning",
        )

    stop_requested = False
    debug_event(
        "batch.requested",
        requested_target=target_count,
        effective_target=effective_target,
        pending_count=pending_count,
        generated_count=len(generated),
        browser_windows=1,
    )

    batch_queue_task = asyncio.create_task(run_batch_queue(effective_target))
    await asyncio.sleep(0)
    return {
        "success": True,
        "requested_target": target_count,
        "target_count": effective_target,
        "pending_count": pending_count,
        "concurrency": 1,
        "generated_count": len(generated),
    }

@app.post("/api/tasks/pause")
async def pause_batch_api():
    global stop_requested
    stop_requested = True
    return {"success": True, "message": "已发送暂停指令，当前账号处理完成后将停止"}

@app.post("/api/tasks/{task_id}/retry")
async def retry_task_api(task_id: str):
    target = next((t for t in tasks if t["id"] == task_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")
    if task_id in active_task_executions:
        raise HTTPException(status_code=409, detail="该任务已有执行实例在运行")
    active_task_executions.add(task_id)

    target["status"] = "RUNNING"
    target["message"] = "准备重试"
    save_tasks(tasks)
    await broadcast("TASK_UPDATED", target)

    cfg = load_config()
    email_svc = get_email_service(target.get("email"))

    async def run_retry() -> None:
        try:
            await execute_registration_task(
                cfg,
                email_svc,
                target,
                on_task_status_change,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            target["status"] = "FAILED"
            target["message"] = f"重试异常: {exc}"
            on_task_status_change(target)
        finally:
            active_task_executions.discard(task_id)

    asyncio.create_task(run_retry())
    return {"success": True}

@app.post("/api/tasks/{task_id}/manual-verify")
async def manual_verify_api(task_id: str, data: Dict[str, str] = Body(...)):
    verify_url = data.get("verify_url", "").strip()
    if not verify_url:
        raise HTTPException(status_code=400, detail="请提供验证链接或Token")

    target = next((t for t in tasks if t["id"] == task_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")

    if _resolve_waiter(manual_verify_waiters, task_id, verify_url):
        target["message"] = "已提交验证链接，纯协议工作器将在原会话中继续激活"
        save_tasks(tasks)
        await broadcast("TASK_UPDATED", target)
        return {
            "success": True,
            "message": "验证链接已提交到正在运行的纯协议会话",
            "protocol_waiter": True,
        }

    cfg = load_config()
    worker = RegisterWorker(cfg, None, log_callback=sync_log_callback)
    res = await worker.verify_token_manually(
        verify_url,
        password=target.get("password", ""),
        task_id=task_id,
    )

    if res["success"]:
        target["status"] = "SUCCESS"
        target["message"] = "已手动激活完成并提取凭证！"
        target["verify_url"] = verify_url
        target["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        if res.get("web_jwt"):
            target["web_jwt"] = res["web_jwt"]
        if res.get("zcode_data"):
            zd = res["zcode_data"]
            target["cli_jwt"] = zd.get("cli_jwt", "")
            target["jwt"] = zd.get("cli_jwt", "")
            target["device_mid"] = zd.get("device_mid")
            target["sub"] = zd.get("sub")
            target["access_token"] = zd.get("access_token")
            target.pop("jwt_fallback", None)
    else:
        target["message"] = f"手动激活失败: {res['message']}"

    save_tasks(tasks)
    await broadcast("TASK_UPDATED", target)
    return res

@app.post("/api/tasks/{task_id}/extract-jwt")
async def extract_jwt_api(task_id: str):
    target = next((t for t in tasks if t["id"] == task_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")

    cfg = load_config()
    proxy_cfg = None
    if cfg.get("proxy_enabled") and cfg.get("proxy_server"):
        proxy_server = cfg["proxy_server"].strip()
        proxy_cfg = {"server": proxy_server}
        if cfg.get("proxy_username"):
            proxy_cfg["username"] = cfg["proxy_username"].strip()
        if cfg.get("proxy_password"):
            proxy_cfg["password"] = cfg["proxy_password"]

    from zcode_token import exchange_web_jwt_to_zcode_cli, parse_jwt_sub, generate_device_mid

    # 1. 通过已有 Web JWT 直接用纯协议完成 OAuth，不启动浏览器。
    if target.get("web_jwt") and not target["web_jwt"].startswith("guest-"):
        sync_log_callback(task_id, "正在通过纯协议 OAuth 换取 ZCode Coding Plan JWT...", "info")
        try:
            from protocol_client import ZaiProtocolClient
            from protocol_fingerprint import fingerprint_from_task
            from proxy_manager import get_next_task_proxy

            proxy_info = get_next_task_proxy(cfg)
            profile = fingerprint_from_task(target, cfg)
            client = ZaiProtocolClient(
                profile,
                proxy=(proxy_info or {}).get("requests_proxy", ""),
                timeout=int(cfg.get("protocol_timeout_sec", 30)),
            )
            client.set_cookies({"token": target["web_jwt"]})
            client.state.web_jwt = target["web_jwt"]
            oauth = await asyncio.to_thread(
                client.oauth_exchange,
                timeout_sec=int(cfg.get("protocol_oauth_timeout_sec", 30)),
            )
            target["jwt"] = oauth.cli_jwt
            target["cli_jwt"] = oauth.cli_jwt
            target["device_mid"] = oauth.device_mid
            target["sub"] = oauth.sub
            target["access_token"] = oauth.access_token
            target["message"] = "🎉 已通过纯协议 OAuth 提取 ZCode Coding Plan JWT！"
            save_tasks(tasks)
            await broadcast("TASK_UPDATED", target)
            return {
                "success": True,
                "message": "官方 ZCode JWT 提取成功！",
                "jwt": oauth.cli_jwt,
                "device_mid": oauth.device_mid,
                "protocol_mode": True,
            }
        except Exception as exc:
            sync_log_callback(
                task_id,
                f"纯协议 OAuth 未成功（{exc}），回退到浏览器换票",
                "warning",
            )

    # 2. 兼容旧会话：纯协议失败时回退到浏览器 OAuth。
    sync_log_callback(
        task_id,
        "正在启动本机可见浏览器登录流程提取凭据，请在 Chromium 中完成滑块...",
        "info",
    )
    worker = RegisterWorker(cfg, None, log_callback=sync_log_callback)
    res = await worker.login_and_extract_jwt(
        target["email"],
        target["password"],
        task_id=task_id,
    )
    if res.get("success"):
        if res.get("web_jwt"):
            target["web_jwt"] = res["web_jwt"]
        if res.get("cli_jwt"):
            target["jwt"] = res["cli_jwt"]
            target["cli_jwt"] = res["cli_jwt"]
            target["device_mid"] = res.get("device_mid", "")
            target["sub"] = res.get("sub", "")
            target["access_token"] = res.get("access_token", "")
            target.pop("jwt_fallback", None)
        elif res.get("web_jwt"):
            target["jwt"] = res["web_jwt"]
            target["jwt_fallback"] = "web_jwt"
        target["message"] = "已重新登录并成功提取官方最新 CLI JWT"
        save_tasks(tasks)
        await broadcast("TASK_UPDATED", target)
        return {
            "success": True,
            "message": "CLI JWT 提取成功",
            "jwt": target.get("cli_jwt", ""),
            "device_mid": target.get("device_mid"),
        }
    return {"success": False, "message": f"提取失败: {res.get('message')}"}

@app.post("/api/tasks/{task_id}/save-jwt")
async def save_jwt_api(task_id: str, data: Dict[str, str] = Body(...)):
    target = next((t for t in tasks if t["id"] == task_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")

    jwt_val = data.get("jwt", "").strip()
    if not jwt_val:
        raise HTTPException(status_code=400, detail="JWT 不能为空")

    from zcode_token import parse_jwt_sub, generate_device_mid
    sub = parse_jwt_sub(jwt_val)
    device_mid = generate_device_mid(sub or jwt_val)

    target["jwt"] = jwt_val
    target["cli_jwt"] = jwt_val
    target["sub"] = sub
    target["device_mid"] = device_mid
    target["message"] = "已手动录入 JWT 凭证"

    save_tasks(tasks)
    await broadcast("TASK_UPDATED", target)
    return {"success": True, "message": "JWT 保存成功！"}

@app.post("/api/oauth-cli/start/{task_id}")
async def oauth_cli_start_api(task_id: str):
    target = next((t for t in tasks if t["id"] == task_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")

    poll_token = secrets.token_hex(32)
    import requests
    res = requests.post(
        "https://zcode.z.ai/api/v1/oauth/cli/init",
        headers={"Authorization": f"Bearer {poll_token}"},
        json={"provider": "zai"},
        timeout=10
    ).json()

    if res.get("code") != 0 or "data" not in res:
        return {"success": False, "message": "向官方发起 OAuth 流程失败"}

    flow_id = res["data"]["flow_id"]
    authorize_url = res["data"]["authorize_url"]

    sync_log_callback(task_id, f"已生成官方 OAuth CLI 授权会话，正在等待授权: {target['email']}", "info")

    async def poll_flow():
        start_t = time.time()
        while time.time() - start_t < 300:
            await asyncio.sleep(2)
            try:
                p_res = requests.get(
                    f"https://zcode.z.ai/api/v1/oauth/cli/poll/{flow_id}",
                    headers={"Authorization": f"Bearer {poll_token}"},
                    timeout=10
                ).json()
                p_data = p_res.get("data", {})
                if p_data.get("status") == "ready" and p_data.get("token"):
                    cli_jwt = p_data["token"]
                    user_info = p_data.get("user", {})
                    access_token = p_data.get("zai", {}).get("access_token", "")

                    from zcode_token import parse_jwt_sub, generate_device_mid
                    sub = parse_jwt_sub(cli_jwt)
                    device_mid = generate_device_mid(sub or cli_jwt)

                    target["jwt"] = cli_jwt
                    target["cli_jwt"] = cli_jwt
                    target["sub"] = sub
                    target["device_mid"] = device_mid
                    target["access_token"] = access_token
                    target["status"] = "SUCCESS"
                    target["message"] = f"🎉 官方 OAuth 授权成功！已绑定账号 {user_info.get('email', target['email'])}"
                    save_tasks(tasks)
                    await broadcast("TASK_UPDATED", target)
                    sync_log_callback(task_id, f"🎉 账号 {target['email']} 已成功提取官方 Coding Plan 专用 JWT！", "success")
                    break
            except Exception:
                pass

    asyncio.create_task(poll_flow())
    return {
        "success": True,
        "authorize_url": authorize_url,
        "flow_id": flow_id
    }

@app.get("/api/export-tokens")
async def export_tokens_txt():
    """Export only real CLI JWTs accepted by ZCode clients."""
    import base64

    # Read the live task objects rather than a stale disk snapshot.
    current_tasks = tasks
    lines: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in current_tasks:
        email = str(item.get("email") or item.get("id") or "")
        cli_jwt = str(item.get("cli_jwt") or "").strip()
        if not cli_jwt:
            skipped.append({"email": email, "reason": "missing_cli_jwt"})
            continue
        parts = cli_jwt.split(".")
        if len(parts) != 3:
            skipped.append(
                {"email": email, "reason": f"jwt_segments={len(parts)}"}
            )
            continue
        try:
            payload = parts[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except Exception as exc:
            skipped.append(
                {"email": email, "reason": f"decode_error:{type(exc).__name__}"}
            )
            continue
        if not isinstance(claims, dict):
            skipped.append({"email": email, "reason": "claims_not_object"})
            continue
        # CLI JWT identifies the account through sub/user_id. A web JWT has
        # email and cli=web, so reject it even if an old record put it in jwt.
        if claims.get("cli") == "web":
            skipped.append({"email": email, "reason": "web_cli_claim"})
            continue
        if claims.get("email"):
            skipped.append({"email": email, "reason": "web_email_claim"})
            continue
        if not (claims.get("sub") or claims.get("user_id")):
            skipped.append({"email": email, "reason": "missing_subject"})
            continue
        lines.append(cli_jwt)

    debug_event(
        "export.cli_jwt",
        exported=len(lines),
        skipped=skipped,
        required_field="cli_jwt",
    )
    return Response(
        content="\n".join(lines),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=tokens.txt"}
    )

@app.post("/api/zcode2api/toggle")
async def zcode2api_toggle_api(data: Dict[str, Any] = Body(default={})):
    """Toggle auto-import without touching other zcode2api settings."""

    desired = data.get("enabled")
    current = load_config()
    enabled = (
        bool(desired)
        if isinstance(desired, bool)
        else not bool(current.get("zcode2api_enabled", False))
    )
    if enabled and not current.get("zcode2api_url"):
        raise HTTPException(
            status_code=400,
            detail="请先配置 zcode2api 地址和管理密码",
        )
    update = {"zcode2api_enabled": enabled}
    save_config(update)
    cfg = load_config()
    debug_event(
        "zcode2api.toggle",
        enabled=enabled,
        url=str(cfg.get("zcode2api_url") or ""),
        auto_import=bool(cfg.get("zcode2api_auto_import", True)),
    )
    await broadcast("CONFIG_UPDATED", get_masked_config())
    return {
        "success": True,
        "enabled": enabled,
        "url": str(cfg.get("zcode2api_url") or ""),
        "auto_import": bool(cfg.get("zcode2api_auto_import", True)),
    }


@app.post("/api/zcode2api/import-one/{task_id}")
async def zcode2api_import_one_api(task_id: str):
    """Import a single task regardless of the auto-import switch."""

    target = next(
        (item for item in tasks if item.get("id") == task_id), None
    )
    if not target:
        raise HTTPException(status_code=404, detail="Task not found")
    if not target.get("cli_jwt"):
        raise HTTPException(
            status_code=409,
            detail="该任务还没有 CLI JWT，无法导入",
        )
    cfg = load_config()
    if not cfg.get("zcode2api_url") or not cfg.get(
        "zcode2api_admin_password"
    ):
        raise HTTPException(
            status_code=400,
            detail="请先在「协议与指纹」页配置 zcode2api 地址和管理密码",
        )
    from zcode2api_import import Zcode2ApiImporter

    importer = Zcode2ApiImporter(
        str(cfg.get("zcode2api_url") or ""),
        str(cfg.get("zcode2api_admin_password") or ""),
        timeout=int(cfg.get("zcode2api_timeout_sec", 20)),
    )
    try:
        result = await asyncio.to_thread(importer.import_task, target)
    except Exception as exc:
        target["zcode2api_import_error"] = str(exc)
        save_tasks(tasks)
        await broadcast("TASK_UPDATED", target)
        raise HTTPException(
            status_code=502,
            detail=f"导入失败: {exc}",
        ) from exc
    target["zcode2api_account_id"] = str(result.get("id") or "")
    target["zcode2api_imported_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    target["zcode2api_verified"] = bool(result.get("verified"))
    target.pop("zcode2api_import_error", None)
    save_tasks(tasks)
    await broadcast("TASK_UPDATED", target)
    return {
        "success": True,
        "task_id": task_id,
        "email": target.get("email"),
        "account_id": target["zcode2api_account_id"],
        "updated": bool(result.get("updated")),
        "verified": bool(result.get("verified")),
    }


@app.post("/api/zcode2api/test")
async def zcode2api_test_api():
    cfg = load_config()
    if not cfg.get("zcode2api_url") or not cfg.get(
        "zcode2api_admin_password"
    ):
        raise HTTPException(
            status_code=400,
            detail="请先填写 zcode2api 地址和管理密码",
        )
    from zcode2api_import import Zcode2ApiImporter

    importer = Zcode2ApiImporter(
        str(cfg.get("zcode2api_url") or ""),
        str(cfg.get("zcode2api_admin_password") or ""),
        timeout=int(cfg.get("zcode2api_timeout_sec", 20)),
    )
    try:
        health = await asyncio.to_thread(importer.health)
        await asyncio.to_thread(importer.login)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"zcode2api 连接失败: {exc}",
        ) from exc
    return {
        "success": True,
        "health": health,
        "url": importer.base_url,
    }


@app.post("/api/zcode2api/import")
async def zcode2api_import_api(data: Dict[str, Any] = Body(default={})):
    cfg = load_config()
    task_ids = {
        str(value)
        for value in (data.get("task_ids") or [])
        if str(value)
    }
    selected = [
        item
        for item in tasks
        if item.get("status") == "SUCCESS"
        and item.get("cli_jwt")
        and (not task_ids or str(item.get("id")) in task_ids)
    ]
    if not selected:
        raise HTTPException(
            status_code=409,
            detail="没有可导入的已注册 CLI JWT 账号",
        )
    from zcode2api_import import Zcode2ApiImporter

    importer = Zcode2ApiImporter(
        str(cfg.get("zcode2api_url") or ""),
        str(cfg.get("zcode2api_admin_password") or ""),
        timeout=int(cfg.get("zcode2api_timeout_sec", 20)),
    )
    results = []
    for item in selected:
        try:
            result = await asyncio.to_thread(importer.import_task, item)
            item["zcode2api_account_id"] = str(result.get("id") or "")
            item["zcode2api_imported_at"] = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            item["zcode2api_verified"] = bool(result.get("verified"))
            item.pop("zcode2api_import_error", None)
            results.append(
                {
                    "task_id": item.get("id"),
                    "email": item.get("email"),
                    "success": True,
                    "account_id": item["zcode2api_account_id"],
                    "updated": bool(result.get("updated")),
                    "verified": bool(result.get("verified")),
                }
            )
        except Exception as exc:
            item["zcode2api_import_error"] = str(exc)
            results.append(
                {
                    "task_id": item.get("id"),
                    "email": item.get("email"),
                    "success": False,
                    "error": str(exc),
                }
            )
    save_tasks(tasks)
    for item in selected:
        await broadcast("TASK_UPDATED", item)
    return {
        "success": any(result["success"] for result in results),
        "imported": sum(1 for result in results if result["success"]),
        "failed": sum(1 for result in results if not result["success"]),
        "results": results,
    }


@app.get("/api/export-web-tokens")
async def export_web_tokens_txt():
    """Export verified account Web JWTs as email<TAB>jwt pairs."""
    import base64

    lines: list[str] = []
    skipped: list[dict[str, str]] = []
    for item in tasks:
        email = str(item.get("email") or item.get("id") or "")
        web_jwt = str(item.get("web_jwt") or "").strip()
        parts = web_jwt.split(".")
        if len(parts) != 3:
            skipped.append({"email": email, "reason": "missing_web_jwt"})
            continue
        try:
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
        except Exception as exc:
            skipped.append(
                {"email": email, "reason": f"decode_error:{type(exc).__name__}"}
            )
            continue
        claim_email = str(claims.get("email") or "").lower()
        if (
            claims.get("cli") != "web"
            or not claim_email
            or claim_email.startswith("guest-")
        ):
            skipped.append({"email": email, "reason": "not_account_web_jwt"})
            continue
        lines.append(f"{claim_email}\t{web_jwt}")

    debug_event(
        "export.web_jwt",
        exported=len(lines),
        skipped=skipped,
        format="email<TAB>jwt",
    )
    return Response(
        content="\n".join(lines),
        media_type="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=web-tokens.txt"
        },
    )


@app.get("/api/export")
async def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "姓名", "邮箱", "密码", "CLI_JWT(ZCode/桌面客户端)", "Web_JWT", "Device_MID(防3012)", "状态", "完成时间"])

    for t in tasks:
        writer.writerow([
            t.get("id"),
            t.get("name"),
            t.get("email"),
            t.get("password"),
            t.get("cli_jwt", ""),
            t.get("web_jwt", ""),
            t.get("device_mid", ""),
            t.get("status"),
            t.get("completed_at", "")
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=z_ai_registered_accounts.csv"}
    )
