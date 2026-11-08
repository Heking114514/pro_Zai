"""Structured request/response capture for registration debugging.

The capture is intentionally metadata-first: URLs, methods, statuses, headers,
and bounded body previews are retained, while secrets are replaced with a
fingerprint. It is not a HAR file and does not contain reusable credentials.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from debug_log import fingerprint


BASE_DIR = Path(__file__).resolve().parent
_DEFAULT_DATA_DIR = Path(os.environ.get("PRO_ZAI_DATA_DIR", str(BASE_DIR)))
LOG_DIR = Path(os.environ.get("PRO_ZAI_LOG_DIR", str(_DEFAULT_DATA_DIR / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
TRAFFIC_FILE = LOG_DIR / "traffic-capture.jsonl"
MAX_BODY_CHARS = 4000
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-aliyun-captcha-verify-param",
}
SENSITIVE_FIELDS = {
    "access_token",
    "authorization",
    "captcha_verify_param",
    "cli_jwt",
    "code",
    "cookie",
    "cookies",
    "email",
    "jwt",
    "password",
    "securitytoken",
    "token",
    "web_jwt",
}
SENSITIVE_QUERY_NAMES = {
    "access_token",
    "captcha_verify_param",
    "code",
    "email",
    "jwt",
    "state",
    "token",
    "username",
}


logger = logging.getLogger("pro_zai.traffic")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(
        TRAFFIC_FILE,
        maxBytes=32 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False


def _sanitize_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        query = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            query.append(
                (key, fingerprint(value) if key.lower() in SENSITIVE_QUERY_NAMES else value)
            )
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                "&".join(f"{key}={value}" for key, value in query),
                parsed.fragment,
            )
        )
    except Exception:
        return url[:2000]


def _sanitize_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_key, raw_value in dict(headers or {}).items():
        key = str(raw_key)
        value = str(raw_value)
        if key.lower() in SENSITIVE_HEADERS:
            result[key] = fingerprint(value)
        else:
            result[key] = value[:2000]
    return result


def _sanitize_value(value: Any, key: str = "") -> Any:
    if key.lower() in SENSITIVE_FIELDS:
        return fingerprint(value)
    if isinstance(value, Mapping):
        return {str(k): _sanitize_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        return value[:MAX_BODY_CHARS]
    return value


def parse_body(body: Any, content_type: str = "") -> Any:
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return _sanitize_value(body)
    if isinstance(body, bytes):
        raw = body
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "encoding": "base64",
                "size": len(raw),
                "preview": base64.b64encode(raw[:MAX_BODY_CHARS]).decode("ascii"),
            }
    else:
        text = str(body)
    text = text[:MAX_BODY_CHARS]
    if "json" in content_type.lower() or text.lstrip().startswith(("{", "[")):
        try:
            return _sanitize_value(json.loads(text))
        except Exception:
            pass
    return text


def capture(
    *,
    source: str,
    phase: str,
    method: str = "",
    url: str = "",
    request_headers: Mapping[str, Any] | None = None,
    request_body: bytes | str | None = None,
    status: int = 0,
    response_headers: Mapping[str, Any] | None = None,
    response_body: bytes | str | None = None,
    duration_ms: int = 0,
    task_id: str = "",
    error: str = "",
    **extra: Any,
) -> None:
    record = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "source": source,
        "phase": phase,
        "task_id": task_id,
        "method": method,
        "url": _sanitize_url(url),
        "status": int(status or 0),
        "duration_ms": int(duration_ms or 0),
        "request_headers": _sanitize_headers(request_headers),
        "request_body": parse_body(
            request_body,
            str((request_headers or {}).get("content-type", "")),
        ),
        "response_headers": _sanitize_headers(response_headers),
        "response_body": parse_body(
            response_body,
            str((response_headers or {}).get("content-type", "")),
        ),
        "error": error[:3000],
    }
    record.update(_sanitize_value(extra))
    try:
        logger.info(json.dumps(record, ensure_ascii=False, default=str))
    except Exception as exc:
        # Diagnostics must never alter the registration flow.
        try:
            logger.info(
                json.dumps(
                    {
                        "at": record["at"],
                        "source": source,
                        "phase": phase,
                        "task_id": task_id,
                        "error": f"traffic_record_serialization_failed:{type(exc).__name__}",
                    },
                    ensure_ascii=False,
                )
            )
        except Exception:
            pass
