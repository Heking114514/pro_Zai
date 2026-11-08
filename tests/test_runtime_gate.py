from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).parents[1]


def test_runtime_is_protocol_with_captcha_only_browser():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    runtime = source[source.index("async def runtime_api") :]
    runtime = runtime[: runtime.index("@app.", 1)]
    assert '"registration_mode": "protocol_with_human_captcha"' in runtime
    assert '"captcha_mode": "human_slider_only"' in runtime
    assert '"captcha_ui_mode": "local_window"' in runtime
    assert "captcha_auto_solve" not in runtime


def test_registration_dispatch_uses_protocol_worker():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    dispatch = source[source.index("async def execute_registration_task") :]
    dispatch = dispatch[: dispatch.index("async def ", 10)]
    assert "ProtocolRegistrationWorker(" in dispatch
    assert "RegisterWorker(" not in dispatch
    assert "BrowserCaptchaBridge" not in dispatch


def test_captcha_window_is_scoped_to_captcha():
    source = (ROOT / "captcha_window.py").read_text(encoding="utf-8")
    assert '"headless": False' in source
    assert "captcha.signup_request" in source
    assert "captcha.window.completed" in source
    assert "page.mouse.move" not in source
    assert "startScreencast" not in source
    assert "BrowserSliderSolver" not in source


def test_browser_worker_forces_visible_manual_captcha():
    source = (ROOT / "register_worker.py").read_text(encoding="utf-8")
    execute = source[source.index("async def _run_register_attempt") :]
    execute = execute[: execute.index("async def login_and_extract_jwt")]
    assert "headless = False" in execute
    assert "captcha.waiting_for_human" in execute
    assert "BrowserSliderSolver" not in execute
    assert "startScreencast" not in execute
    assert "page.mouse.move" not in execute
    assert 'page.on("request", on_request)' in execute
    assert 'page.on("response", on_response)' in execute
    assert "captcha_verify_param" in execute


def test_automatic_solver_and_bridge_modules_are_removed():
    removed = (
        "browser_captcha_solver.py",
        "captcha_bridge.py",
        "captcha_runtime.py",
        "captcha_runtime.cjs",
        "protocol_register_worker.py",
        "local_captcha_bridge.py",
        "templates/verify.html",
        "templates/local_captcha.html",
    )
    for relative in removed:
        assert not (ROOT / relative).exists(), relative


def test_runtime_config_defaults_to_protocol():
    from config_manager import DEFAULT_CONFIG

    assert DEFAULT_CONFIG["registration_mode"] == "protocol"
    assert DEFAULT_CONFIG["headless"] is False
    assert DEFAULT_CONFIG["protocol_fallback_browser"] is False
    assert DEFAULT_CONFIG["captcha_timeout_sec"] >= 60
    assert DEFAULT_CONFIG["target_count"] >= 1
    assert "captcha_auto_solve" not in DEFAULT_CONFIG
    assert "captcha_solver_url" not in DEFAULT_CONFIG


def test_protocol_client_matches_capture_verification_order():
    source = (ROOT / "protocol_client.py").read_text(encoding="utf-8")
    finish = source[source.index("def finish_signup(") :]
    finish = finish[: finish.index("def _has_account_web_jwt", 1)]
    assert finish.index("VERIFY_EMAIL_URL") < finish.index("FINISH_SIGNUP_URL")
    assert "include_device_id=False" in finish
    assert finish.count('"token": token') >= 2


def test_captcha_window_waits_for_signup_response():
    source = (ROOT / "captcha_window.py").read_text(encoding="utf-8")
    assert "response_deadline = time.monotonic() + 20" in source
    assert 'signup_response["status"] is None' in source


def test_captcha_window_does_not_reclick_after_human_slider():
    source = (ROOT / "captcha_window.py").read_text(encoding="utf-8")
    success = source[source.index("if state.get(\"success\")") :]
    success = success[: success.index("captcha.window.completed", 1)]
    assert "create_button.click" not in success
    assert "captcha.trigger_click_failed" in source


def test_captcha_window_waits_and_clicks_create_account():
    source = (ROOT / "captcha_window.py").read_text(encoding="utf-8")
    trigger = source[source.index("async def _trigger_captcha") :]
    trigger = trigger[: trigger.index("async def _open_signup", 1)]
    assert "deadline = time.monotonic() + 25" in trigger
    assert "await create_button.click(timeout=8000)" in trigger
    assert '"captcha.trigger_ready"' in trigger


def test_analytics_routes_fulfill_instead_of_abort():
    from browser_routes import ANALYTICS_HOSTS

    source = (ROOT / "browser_routes.py").read_text(encoding="utf-8")
    assert "route.fulfill" in source
    assert "route.abort" not in source
    assert "rum.aliyuncs.com" not in ANALYTICS_HOSTS
    worker = (ROOT / "register_worker.py").read_text(encoding="utf-8")
    assert "install_analytics_route" in worker
    assert "route.abort()" not in worker


def test_browser_capture_does_not_replace_protocol_guest_token():
    source = (ROOT / "protocol_client.py").read_text(encoding="utf-8")
    importer = source[source.index("def import_browser_captcha_session(") :]
    importer = importer[: importer.index("def submit_signup(", 1)]
    assert 'str(name) != "token"' in importer
    assert "self.state.web_jwt = token" not in importer


def test_oauth_rejects_guest_web_jwt():
    source = (ROOT / "protocol_client.py").read_text(encoding="utf-8")
    oauth = source[source.index("def oauth_exchange(") :]
    oauth = oauth[: oauth.index("def state_snapshot", 1)]
    assert "account_web_jwt_required" in oauth
    assert 'claim_email.startswith("guest-")' in oauth
    finish = source[source.index("def finish_signup(") :]
    finish = finish[: finish.index("def _has_account_web_jwt", 1)]
    assert "self._has_account_web_jwt(email)" in finish


def test_traffic_capture_cannot_break_registration():
    source = (ROOT / "protocol_client.py").read_text(encoding="utf-8")
    request = source[source.index("def _request(") :]
    request = request[: request.index("def _raise_for_status", 1)]
    assert request.count("try:\n                capture_traffic") >= 1
    assert request.count("try:\n            capture_traffic") >= 1
    assert "Capture is diagnostic only" in request


def test_protocol_worker_uses_captcha_window_and_protocol_client():
    source = (ROOT / "protocol_registration.py").read_text(encoding="utf-8")
    assert "client.bootstrap" in source
    assert "self.captcha_window.solve" in source
    assert "client.submit_signup" in source
    assert "client.finish_signup" in source
    assert "client.oauth_exchange" in source
    assert "RegisterWorker" not in source
    assert "page.mouse" not in source
    assert "startScreencast" not in source


def test_token_export_rejects_web_jwt_fallbacks():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    export = source[source.index("async def export_tokens_txt") :]
    export = export[: export.index("@app.get", 1)]
    assert "current_tasks = tasks" in export
    assert 'item.get("cli_jwt")' in export
    assert 'claims.get("cli") == "web"' in export
    assert "claims.get(\"sub\") or claims.get(\"user_id\")" in export
    assert 'item.get("jwt")' not in export


def test_traffic_capture_redacts_sensitive_values():
    import traffic_log

    traffic_log.capture(
        source="test",
        phase="request",
        method="POST",
        url="https://chat.z.ai/api/test?token=secret-query",
        request_headers={
            "Authorization": "Bearer secret-header",
            "Content-Type": "application/json",
        },
        request_body='{"password":"secret-password","email":"user@example.com"}',
        task_id="task-traffic",
    )
    text = traffic_log.TRAFFIC_FILE.read_text(encoding="utf-8")
    assert "task-traffic" in text
    assert "secret-query" not in text
    assert "secret-header" not in text
    assert "secret-password" not in text
    assert "user@example.com" not in text
    assert "traffic-capture.jsonl" in str(traffic_log.TRAFFIC_FILE)


def test_traffic_capture_accepts_mapping_body():
    import traffic_log

    traffic_log.capture(
        source="test",
        phase="request",
        method="POST",
        url="https://zcode.z.ai/api/v1/oauth/cli/init",
        request_headers={"Content-Type": "application/json"},
        request_body={"provider": "zai", "token": "secret-token"},
        task_id="task-mapping",
    )
    text = traffic_log.TRAFFIC_FILE.read_text(encoding="utf-8")
    assert "task-mapping" in text
    assert "secret-token" not in text


def test_protocol_retries_proxy_transport_failures():
    source = (ROOT / "protocol_registration.py").read_text(encoding="utf-8")
    assert 'protocol_proxy_retry_attempts' in source
    assert "for attempt in range(max_attempts)" in source
    assert "self._should_retry_proxy(exc)" in source
    assert "report_proxy_failure(proxy_info[\"raw\"], str(exc))" in source
    assert "report_proxy_success(proxy_info[\"raw\"])" in source
    assert "await asyncio.sleep(1)" in source
    proxy = (ROOT / "proxy_manager.py").read_text(encoding="utf-8")
    assert '"curl: (28)"' in proxy
    assert '"operation timed out"' in proxy


def test_zcode2api_auto_import_is_wired():
    source = (ROOT / "protocol_registration.py").read_text(encoding="utf-8")
    assert "await self._import_to_zcode2api(task)" in source
    assert "zcode2api_enabled" in source
    assert '"business_token": oauth.access_token' in source
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '@app.post("/api/zcode2api/test")' in app
    assert '@app.post("/api/zcode2api/import")' in app
    importer = (ROOT / "zcode2api_import.py").read_text(encoding="utf-8")
    assert '"/api/accounts/import-registration"' in importer
    assert '"zcodeJwt"' in importer
    assert '"businessToken"' in importer


def test_zcode2api_toggle_and_single_import_endpoints():
    app = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '@app.post("/api/zcode2api/toggle")' in app
    assert '@app.post("/api/zcode2api/import-one/{task_id}")' in app
    toggle = app[app.index("async def zcode2api_toggle_api") :]
    toggle = toggle[: toggle.index("@app.post", 1)]
    assert '"zcode2api_enabled": enabled' in toggle
    single = app[app.index("async def zcode2api_import_one_api") :]
    single = single[: single.index("@app.post", 1)]
    assert "importer.import_task, target" in single
    assert "cli_jwt" in single
    js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    assert "function renderZcode2ApiToggle" in js
    assert "toggleZcode2ApiImport" in js
    assert "importTaskToZcode2Api" in js
    assert 'case "CONFIG_UPDATED":' in js
    template = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="btnZcode2ApiToggle"' in template


def test_web_token_export_is_separate_from_cli_export():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '@app.get("/api/export-web-tokens")' in source
    web_export = source[source.index("async def export_web_tokens_txt") :]
    web_export = web_export[: web_export.index("@app.get", 1)]
    assert 'claims.get("cli") != "web"' in web_export
    assert 'claim_email.startswith("guest-")' in web_export
    assert 'filename=web-tokens.txt' in web_export
    template = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'href="/api/export-web-tokens"' in template


def test_traffic_log_endpoint_is_available():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    assert '@app.get("/api/traffic-log"' in source
    assert "TRAFFIC_FILE" in source
    assert '"traffic_log": str(TRAFFIC_FILE)' in source


def test_debug_log_is_available_and_redacted():
    import logging

    import debug_log

    debug_log.event(
        "test.secret",
        level=logging.INFO,
        password="plain-password",
        captcha_verify_param="opaque-captcha",
        task_id="task-debug",
        name="Task Display Name",
    )
    text = debug_log.LOG_FILE.read_text(encoding="utf-8")
    assert "test.secret" in text
    assert "plain-password" not in text
    assert "opaque-captcha" not in text
    assert "task-debug" in text
    assert "Task Display Name" in text


def test_retry_rejects_duplicate_execution_for_same_task():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    retry = source[source.index("async def retry_task_api") :]
    retry = retry[: retry.index("@app.", 1)]
    assert "if task_id in active_task_executions:" in retry
    assert "active_task_executions.add(task_id)" in retry
    assert "finally:" in retry
    assert "active_task_executions.discard(task_id)" in retry


def test_task_start_yields_to_background_worker():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    create = source.index(
        "batch_queue_task = asyncio.create_task(run_batch_queue(effective_target))"
    )
    yield_point = source.index("await asyncio.sleep(0)", create)
    response = source.index('"success": True', yield_point)
    assert create < yield_point < response


def test_target_count_controls_single_browser_queue():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    queue = source[source.index("async def run_batch_queue") :]
    queue = queue[: queue.index("@app.post", 1)]
    assert "while not stop_requested and processed < requested:" in queue
    assert "processed += 1" in queue
    assert "concurrency\": 1" in queue
    assert "asyncio.gather" not in queue


def test_import_modal_accepts_target_count():
    source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    template = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    assert "addTargetCountInput" in source
    assert "target_count: targetCount" in source
    assert 'id="addTargetCountInput"' in template
    assert 'id="targetCountInput"' in template


def test_start_clamps_target_to_available_pending_tasks():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    start = source[source.index("async def start_batch_api") :]
    start = start[: start.index("@app.post", 1)]
    assert "effective_target = min(target_count, pending_count)" in start
    assert "run_batch_queue(effective_target)" in start
    assert '"requested_target": target_count' in start


def test_tasks_api_does_not_replace_live_task_objects():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    endpoint = source[source.index("async def get_tasks_api") :]
    endpoint = endpoint[: endpoint.index("@app.", 1)]
    assert "load_tasks()" not in endpoint
    assert "return tasks" in endpoint


def test_websocket_is_status_only():
    source = (ROOT / "app.py").read_text(encoding="utf-8")
    websocket_source = source[source.index("async def websocket_endpoint") :]
    websocket_source = websocket_source[
        : websocket_source.index("@app.get", 1)
    ]
    assert "REMOTE_MOUSE" not in websocket_source
    assert "CAPTCHA_FRAME" not in websocket_source
    assert "await websocket.receive_text()" in websocket_source


def test_remote_gate_and_runtime_snapshot(monkeypatch):
    monkeypatch.setenv("PRO_ZAI_PASSWORD", "test-web-password")
    monkeypatch.setenv("PRO_ZAI_SESSION_SECRET", "test-session-secret")
    import importlib

    import auth_gate
    import app

    importlib.reload(auth_gate)
    importlib.reload(app)
    client = TestClient(app.app, follow_redirects=False)
    assert client.get("/").status_code == 401
    assert client.get("/api/tasks").status_code == 401

    login = client.post(
        "/api/login",
        data={"password": "test-web-password"},
        params={"next": "/"},
    )
    assert login.status_code == 303
    cookie = login.cookies.get("pro_zai_session")
    assert cookie

    client.cookies.set("pro_zai_session", cookie)
    runtime = client.get("/api/runtime")
    assert runtime.status_code == 200
    payload = runtime.json()
    assert payload["registration_mode"] == "protocol_with_human_captcha"
    assert payload["captcha_mode"] == "human_slider_only"
    assert "captcha_auto_solve" not in payload
