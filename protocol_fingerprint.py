"""Coherent desktop browser profiles for the protocol-first registration path.

The profile is intentionally stable for one account. It supplies the fields used
by the Z.ai web client and by an optional external CAPTCHA solver, while
curl_cffi owns the TLS/HTTP2 fingerprint through a matching browser profile.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import random
import secrets
import struct
import uuid
import zlib
from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Optional


CHROME_PROFILES = (
    ("chrome131", 131),
    ("chrome136", 136),
    ("chrome142", 142),
    ("chrome145", 145),
    ("chrome146", 146),
)

SCREEN_PROFILES = (
    (1920, 1080, 1536, 864, 1.0, 8),
    (2560, 1440, 1280, 720, 1.25, 12),
    (3440, 1440, 1486, 764, 1.25, 16),
)

LANGUAGE_PROFILES = {
    "zh-CN": {
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "languages": ("zh-CN", "zh", "en"),
    },
    "en-US": {
        "accept_language": "en-US,en;q=0.9",
        "languages": ("en-US", "en"),
    },
    "ja-JP": {
        "accept_language": "ja-JP,ja;q=0.9,en;q=0.7",
        "languages": ("ja-JP", "ja", "en"),
    },
}


def stable_seed(*parts: Any) -> str:
    value = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _device_id(rng: random.Random) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "uid_" + "".join(rng.choice(alphabet) for _ in range(16))


@dataclass(frozen=True)
class BrowserFingerprint:
    seed: str
    impersonate: str
    major_version: int
    full_version: str
    user_agent: str
    sec_ch_ua: str
    sec_ch_ua_full_version_list: str
    platform: str
    platform_version: str
    accept_language: str
    locale: str
    languages: tuple[str, ...]
    timezone: str
    timezone_offset_min: int
    screen_width: int
    screen_height: int
    viewport_width: int
    viewport_height: int
    pixel_ratio: float
    hardware_concurrency: int
    device_memory: int
    color_depth: int
    device_id: str
    session_id: str
    max_touch_points: int = 0

    @classmethod
    def create(
        cls,
        seed: str,
        *,
        impersonate: str = "auto",
        locale: str = "zh-CN",
        timezone: str = "Asia/Shanghai",
        timezone_offset_min: int = -480,
    ) -> "BrowserFingerprint":
        """Create a deterministic, internally consistent profile.

        ``seed`` should identify the account rather than the process so retries
        keep the same HTTP/JS identity.
        """

        rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32], 16))
        if impersonate and impersonate != "auto":
            profile = next((item for item in CHROME_PROFILES if item[0] == impersonate), None)
            if profile is None:
                supported = ", ".join(item[0] for item in CHROME_PROFILES)
                raise ValueError(f"Unsupported impersonation profile: {impersonate}. Supported: {supported}")
        else:
            profile = rng.choice(CHROME_PROFILES)

        profile_name, major = profile
        full_version = f"{major}.0.0.0"
        locale = locale if locale in LANGUAGE_PROFILES else "zh-CN"
        language_profile = LANGUAGE_PROFILES[locale]
        (
            screen_width,
            screen_height,
            viewport_width,
            viewport_height,
            dpr,
            cores,
        ) = rng.choice(SCREEN_PROFILES)
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{full_version} Safari/537.36"
        )
        sec_ch_ua = (
            f'"Not_A Brand";v="24", "Chromium";v="{major}", '
            f'"Google Chrome";v="{major}"'
        )
        sec_ch_ua_full = (
            f'"Not_A Brand";v="24.0.0.0", "Chromium";v="{full_version}", '
            f'"Google Chrome";v="{full_version}"'
        )
        return cls(
            seed=seed,
            impersonate=profile_name,
            major_version=major,
            full_version=full_version,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            sec_ch_ua_full_version_list=sec_ch_ua_full,
            platform="Windows",
            platform_version="15.0.0",
            accept_language=language_profile["accept_language"],
            locale=locale,
            languages=tuple(language_profile["languages"]),
            timezone=timezone,
            timezone_offset_min=int(timezone_offset_min),
            screen_width=screen_width,
            screen_height=screen_height,
            viewport_width=viewport_width,
            viewport_height=viewport_height,
            pixel_ratio=dpr,
            hardware_concurrency=cores,
            device_memory=8,
            color_depth=24,
            device_id=_device_id(rng),
            session_id=str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        )

    def validate(self) -> None:
        """Fail closed when profile fields contradict each other."""

        if self.impersonate not in {item[0] for item in CHROME_PROFILES}:
            raise ValueError("Unknown impersonation profile")
        if f"Chrome/{self.full_version}" not in self.user_agent:
            raise ValueError("User agent version does not match the profile")
        if f'Google Chrome";v="{self.major_version}"' not in self.sec_ch_ua:
            raise ValueError("Client hints version does not match the profile")
        if not self.device_id.startswith("uid_") or len(self.device_id) != 20:
            raise ValueError("Invalid device id")
        if not self.languages:
            raise ValueError("At least one navigator language is required")

    def api_headers(
        self,
        *,
        origin: str = "https://chat.z.ai",
        referer: str = "https://chat.z.ai/auth",
        authorization: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Dict[str, str]:
        self.validate()
        headers = {
            "Accept": "*/*",
            "Accept-Language": self.accept_language,
            "Origin": origin,
            "Referer": referer,
            "User-Agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{self.platform}"',
            "sec-ch-ua-platform-version": f'"{self.platform_version}"',
            "sec-ch-ua-full-version-list": self.sec_ch_ua_full_version_list,
            "x-device-id": self.device_id,
            "x-region": "overseas",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        if authorization:
            headers["Authorization"] = f"Bearer {authorization}"
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def navigation_headers(self) -> Dict[str, str]:
        self.validate()
        return {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": self.accept_language,
            "User-Agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": f'"{self.platform}"',
            "sec-ch-ua-platform-version": f'"{self.platform_version}"',
            "sec-ch-ua-full-version-list": self.sec_ch_ua_full_version_list,
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        }

    def nav_fingerprint(self) -> Dict[str, Any]:
        """Return non-secret values for an external CAPTCHA solver."""

        return {
            "user_agent": self.user_agent,
            "platform": "Win32",
            "vendor": "Google Inc.",
            "language": self.locale,
            "languages": list(self.languages),
            "timezone": self.timezone,
            "timezone_offset_min": self.timezone_offset_min,
            "screen_width": self.screen_width,
            "screen_height": self.screen_height,
            "viewport_width": self.viewport_width,
            "viewport_height": self.viewport_height,
            "pixel_ratio": self.pixel_ratio,
            "hardware_concurrency": self.hardware_concurrency,
            "device_memory": self.device_memory,
            "color_depth": self.color_depth,
            "max_touch_points": self.max_touch_points,
            "webdriver": False,
            "client_hints": {
                "sec-ch-ua": self.sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": f'"{self.platform}"',
                "sec-ch-ua-platform-version": f'"{self.platform_version}"',
                "sec-ch-ua-full-version-list": self.sec_ch_ua_full_version_list,
            },
        }

    def public_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
    )


def generate_profile_image(seed: str, size: int = 100) -> str:
    """Generate a small deterministic PNG data URI without image dependencies."""

    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    base = tuple(24 + value % 160 for value in digest[:3])
    accent = tuple(32 + value % 192 for value in digest[3:6])
    rows = []
    for y in range(size):
        row = bytearray([0])  # PNG filter: none
        for x in range(size):
            blend = (x + y) / max(1, 2 * (size - 1))
            checker = 18 if ((x // 10) + (y // 10)) % 2 else 0
            row.extend(
                max(0, min(255, int(base[i] * (1 - blend) + accent[i] * blend) + checker))
                for i in range(3)
            )
        rows.append(bytes(row))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(b"".join(rows), 9))
        + _png_chunk(b"IEND", b"")
    )
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


def fingerprint_from_task(
    task: Mapping[str, Any], config: Mapping[str, Any]
) -> BrowserFingerprint:
    seed_material = (
        task.get("email", ""),
        config.get("protocol_fingerprint_salt", "pro-zai"),
        task.get("id", ""),
    )
    profile = BrowserFingerprint.create(
        stable_seed(*seed_material),
        impersonate=str(config.get("protocol_impersonate") or "auto"),
        locale=str(config.get("protocol_locale") or "zh-CN"),
        timezone=str(config.get("protocol_timezone") or "Asia/Shanghai"),
        timezone_offset_min=int(config.get("protocol_timezone_offset_min", -480)),
    )
    profile.validate()
    return profile


def new_manual_session_id() -> str:
    return secrets.token_hex(16)
