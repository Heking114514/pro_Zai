"""CAPTCHA value types and validation shared by the HTTP helpers.

The registration workflow no longer invokes an automatic CAPTCHA solver.
This module retains the opaque value container and payload validator used by
the protocol client and its tests.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any, Dict


class CaptchaSolverError(RuntimeError):
    """A CAPTCHA value is missing or malformed."""


@dataclass(frozen=True)
class CaptchaSolution:
    captcha_verify_param: str
    provider: str
    cookies: Dict[str, str] = field(default_factory=dict)
    device_id: str = ""
    signup_response: Dict[str, Any] = field(default_factory=dict, compare=False)

    def summary(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "has_cookies": bool(self.cookies),
            "has_device_id": bool(self.device_id),
        }


def _decode_captcha_param(value: str) -> Dict[str, Any]:
    raw = (value or "").strip()
    if not raw:
        raise CaptchaSolverError("CAPTCHA value is empty")
    try:
        raw += "=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(raw.encode("ascii"))
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError) as exc:
        raise CaptchaSolverError("captcha_verify_param is not valid base64 JSON") from exc
    if not isinstance(payload, dict):
        raise CaptchaSolverError("captcha_verify_param payload must be an object")
    if not payload.get("certifyId") or not payload.get("sceneId"):
        raise CaptchaSolverError("captcha_verify_param is missing certifyId or sceneId")
    if not payload.get("securityToken"):
        raise CaptchaSolverError("captcha_verify_param is missing securityToken")
    return payload


def validate_captcha_param(value: str) -> Dict[str, Any]:
    """Validate an opaque CAPTCHA value returned by the browser."""

    return _decode_captcha_param(value)
