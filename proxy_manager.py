import time
import random
import socket
import requests
import asyncio
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse, quote

# Disable a node only after repeated failures so one transient timeout does not
# remove an otherwise healthy proxy from the pool.
_DISABLED_PROXIES: Dict[str, Dict[str, Any]] = {}
_PROXY_FAILURES: Dict[str, Dict[str, Any]] = {}
_SCHEME_CACHE: Dict[str, str] = {}
_FAILURE_THRESHOLD = 3
_ROTATOR_INDEX = 0

def is_proxy_error(err_str: str) -> bool:
    """Detects whether an exception message is caused by proxy failure or proxy timeout."""
    if not err_str:
        return False
    err_lower = err_str.lower()
    proxy_keywords = [
        "err_proxy_connection_failed",
        "err_tunnel_connection_failed",
        "err_socks_connection_failed",
        "err_proxy_auth_requested",
        "proxy connection failed",
        "proxyerror",
        "sockserror",
        "socks5",
        "connection refused",
        "host is unreachable",
        "proxy closed connection",
        "err_connection_timed_out",
        "err_connection_reset",
        "err_name_not_resolved",
        "net::err_timed_out",
        "unexpected_eof",
        "unexpected_eof_while_reading",
        "eof occurred in violation",
        "operation timed out",
        "curl: (28)",
        "timed out after",
        "err_cert_authority_invalid",
        "cert_authority_invalid",
        "certificate",
        "sslerror",
        "ssl:",
        "gateway timeout",
        "bad gateway"
    ]
    return any(k in err_lower for k in proxy_keywords)


def _detect_auto_scheme(hostname: str, port: int, has_auth: bool) -> str:
    """Pick a protocol that both the endpoint and Playwright can use.

    Chromium cannot use SOCKS5 username/password authentication. When a mixed
    endpoint requires auth, auto mode therefore prefers HTTP.
    """
    key = f"{hostname.lower()}:{port}:{int(has_auth)}"
    if key in _SCHEME_CACHE:
        return _SCHEME_CACHE[key]
    scheme = "http"
    sock = None
    try:
        sock = socket.create_connection((hostname, port), timeout=3)
        sock.settimeout(3)
        # Offer no-auth and username/password SOCKS5 methods.
        sock.sendall(b"\x05\x02\x00\x02")
        reply = sock.recv(2)
        if len(reply) == 2 and reply[0] == 5 and reply[1] == 0:
            scheme = "socks5h"
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    _SCHEME_CACHE[key] = scheme
    return scheme


def parse_proxy(raw: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single proxy string into Playwright and requests compatible configurations.
    Supports:
      - host:port:user:password (auto-detects HTTP or SOCKS5H)
      - user:password:host:port (auto-detects HTTP or SOCKS5H)
      - host:port (auto-detects HTTP or SOCKS5H)
      - user:password@host:port
      - http(s)://host:port:user:password
      - socks5://host:port:user:password
      - socks5://ip:port or socks5h://ip:port
      - http://ip:port or https://ip:port
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None

    scheme = "auto"
    rest = raw
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        scheme = scheme.lower()

    hostname = None
    port = None
    username = None
    password = None

    parts = rest.split(":")

    # 1. Check if rest starts with host:port (where parts[1] is a numeric port like 8080)
    # e.g. host:port, host:port:user:password
    if len(parts) >= 2 and parts[1].isdigit():
        hostname = parts[0]
        port = int(parts[1])
        if len(parts) >= 4:
            username = parts[2]
            password = ":".join(parts[3:])
    # 2. Check user:pass:host:port (where parts[3] is a numeric port)
    elif len(parts) == 4 and parts[3].isdigit():
        username = parts[0]
        password = parts[1]
        hostname = parts[2]
        port = int(parts[3])
    # 3. Standard URL / user:pass@host:port
    else:
        try:
            parsed = urlparse(f"{scheme}://{rest}")
            hostname = parsed.hostname
            port = parsed.port
            username = parsed.username
            password = parsed.password
        except Exception:
            return None

    if not hostname or not port:
        return None

    if scheme == "auto":
        scheme = _detect_auto_scheme(hostname, port, username is not None and password is not None)
    is_socks = "socks" in scheme
    pw_scheme = "socks5" if is_socks else ("https" if scheme == "https" else "http")

    pw_cfg = {"server": f"{pw_scheme}://{hostname}:{port}"}
    if username is not None:
        pw_cfg["username"] = username
    if password is not None:
        pw_cfg["password"] = password

    # Construct requests_proxy URL with URL encoding for auth credentials
    if username is not None and password is not None:
        req_auth = f"{quote(username)}:{quote(password)}@"
    elif username is not None:
        req_auth = f"{quote(username)}@"
    else:
        req_auth = ""

    requests_proxy = f"{scheme}://{req_auth}{hostname}:{port}"

    return {
        "raw": raw,
        "display": f"{scheme.upper()}://{hostname}:{port}",
        "scheme": scheme.upper(),
        "playwright_cfg": pw_cfg,
        "requests_proxy": requests_proxy,
        "playwright_supported": not (is_socks and (username is not None or password is not None)),
    }

def get_proxy_list(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extracts all configured proxies from config."""
    pool_text = cfg.get("proxy_pool", "") or ""
    lines = [line.strip() for line in pool_text.splitlines() if line.strip() and not line.strip().startswith("#")]

    # Also support single legacy proxy_server if pool_text is empty
    if not lines and cfg.get("proxy_server"):
        srv = cfg["proxy_server"].strip()
        user = cfg.get("proxy_username", "").strip()
        pwd = cfg.get("proxy_password", "")
        if user and pwd and "@" not in srv:
            parts = srv.split("://")
            if len(parts) == 2:
                srv = f"{parts[0]}://{user}:{pwd}@{parts[1]}"
            else:
                srv = f"http://{user}:{pwd}@{srv}"
        lines.append(srv)

    results = []
    for l in lines:
        parsed = parse_proxy(l)
        if parsed:
            results.append(parsed)
    return results

def report_proxy_failure(proxy_raw: str, error_msg: str) -> Dict[str, Any]:
    """Track failures and disable a proxy only after repeated errors."""
    parsed = parse_proxy(proxy_raw)
    display = parsed["display"] if parsed else proxy_raw

    info = _PROXY_FAILURES.get(proxy_raw, {
        "raw": proxy_raw,
        "display": display,
        "failures": 0,
    })
    info["failures"] += 1
    info["last_error"] = str(error_msg)
    info["disabled"] = info["failures"] >= _FAILURE_THRESHOLD
    if info["disabled"]:
        info["disabled_at"] = time.strftime("%H:%M:%S")
        _DISABLED_PROXIES[proxy_raw] = info
    _PROXY_FAILURES[proxy_raw] = info
    return info


def report_proxy_success(proxy_raw: str):
    """Restore a proxy after a successful request."""
    _PROXY_FAILURES.pop(proxy_raw, None)
    _DISABLED_PROXIES.pop(proxy_raw, None)


def get_disabled_proxies() -> Dict[str, Dict[str, Any]]:
    """Returns disabled proxies whose failure threshold was reached."""
    return _DISABLED_PROXIES.copy()


def reset_disabled_proxies():
    """Clear failure counters and re-enable every proxy."""
    _PROXY_FAILURES.clear()
    _DISABLED_PROXIES.clear()

def get_next_task_proxy(cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Selects the next HEALTHY proxy according to proxy_strategy ('round_robin' or 'random').
    Automatically skips any proxy that has failed and been disabled.
    Returns Playwright launch proxy dict or None if no healthy proxies remain.
    """
    global _ROTATOR_INDEX
    if not cfg.get("proxy_enabled", False):
        return None

    all_proxies = get_proxy_list(cfg)
    if not all_proxies:
        return None

    # Keep only browser-compatible, non-disabled proxies.
    healthy_proxies = [
        p for p in all_proxies
        if p["raw"] not in _DISABLED_PROXIES and p.get("playwright_supported", True)
    ]

    if not healthy_proxies:
        # All proxies failed
        return None

    strategy = cfg.get("proxy_strategy", "round_robin")
    if strategy == "random":
        chosen = random.choice(healthy_proxies)
    else:
        chosen = healthy_proxies[_ROTATOR_INDEX % len(healthy_proxies)]
        _ROTATOR_INDEX += 1

    return chosen

def test_proxy_sync(proxy_str: str) -> Dict[str, Any]:
    """Test one proxy with a retry and report its public egress IP."""
    parsed = parse_proxy(proxy_str)
    if not parsed:
        return {"proxy": proxy_str, "success": False, "message": "无效的代理格式"}
    if not parsed.get("playwright_supported", True):
        return {
            "proxy": parsed["display"],
            "raw": proxy_str,
            "scheme": parsed["scheme"],
            "success": False,
            "message": "Chromium 不支持带用户名密码的 SOCKS5，请改用 HTTP 代理格式",
        }

    req_proxy = parsed["requests_proxy"]
    proxies = {
        "http": req_proxy,
        "https": req_proxy
    }
    last_error = "未知错误"
    for attempt in range(2):
        start_time = time.time()
        try:
            resp = requests.get(
                "https://api.ipify.org?format=json",
                proxies=proxies,
                timeout=12,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            latency = int((time.time() - start_time) * 1000)
            if resp.status_code == 200:
                data = resp.json()
                ip = data.get("ip") or data.get("origin") or "未知IP"
                report_proxy_success(proxy_str)
                return {
                    "proxy": parsed["display"],
                    "raw": proxy_str,
                    "scheme": parsed["scheme"],
                    "success": True,
                    "ip": ip,
                    "latency_ms": latency,
                    "message": f"连通正常 (出口IP: {ip}, 延迟: {latency}ms)"
                }
            last_error = f"HTTP状态码: {resp.status_code}"
        except Exception as e:
            last_error = str(e)
        if attempt == 0:
            time.sleep(0.4)

    report_proxy_failure(proxy_str, last_error)
    return {
        "proxy": parsed["display"],
        "raw": proxy_str,
        "scheme": parsed["scheme"],
        "success": False,
        "message": f"连接失败（已重试 2 次）: {last_error}"
    }


async def test_proxies_async(proxy_strings: List[str], max_concurrency: int = 6) -> List[Dict[str, Any]]:
    """Test proxies concurrently without flooding the upstream proxy service."""
    valid = [p for p in proxy_strings if p.strip() and not p.strip().startswith("#")]
    if not valid:
        return []
    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def run_one(proxy: str) -> Dict[str, Any]:
        async with semaphore:
            return await asyncio.to_thread(test_proxy_sync, proxy)

    return await asyncio.gather(*(run_one(proxy) for proxy in valid))
