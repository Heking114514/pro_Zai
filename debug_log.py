"""Structured, redacted debug logging for local registration runs.

The log intentionally stores operational metadata rather than reusable
secrets. CAPTCHA parameters, cookies, passwords, and JWTs are reduced to
fingerprints so a failed run can be diagnosed without copying credentials.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
_DEFAULT_DATA_DIR = Path(os.environ.get("PRO_ZAI_DATA_DIR", str(BASE_DIR)))
LOG_DIR = Path(
    os.environ.get("PRO_ZAI_LOG_DIR", str(_DEFAULT_DATA_DIR / "logs"))
)
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "register-debug.log"

_SENSITIVE_KEYS = {
    "authorization",
    "captcha_verify_param",
    "cli_jwt",
    "cookie",
    "cookies",
    "jwt",
    "mail_jwt",
    "password",
    "proxy_password",
    "security_token",
    "securitytoken",
    "token",
    "web_jwt",
}


def fingerprint(value: Any) -> str:
    raw = str(value or "")
    if not raw:
        return ""
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"{raw[:6]}...{raw[-4:]} len={len(raw)} sha256={digest}"


def redact(value: Any, *, key: str = "") -> Any:
    if key.lower() in _SENSITIVE_KEYS:
        return fingerprint(value)
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str) and len(value) > 1200:
        return value[:1200] + f"... <truncated len={len(value)}>"
    return value


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


logger = logging.getLogger("pro_zai.debug")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    _handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=20 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    _handler.setFormatter(JsonLineFormatter())
    logger.addHandler(_handler)
    logger.propagate = False


def event(
    event_name: str,
    /,
    *,
    level: int = logging.INFO,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    """Append one structured event.

    ``event_name`` is positional-only so callers may safely include an
    ordinary ``name`` field for a registration task.
    """

    logger.log(
        level,
        event_name,
        extra={"fields": fields},
        exc_info=exc_info,
    )
