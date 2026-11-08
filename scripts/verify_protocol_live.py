"""Non-mutating live check for the protocol client.

This script only opens the auth page and creates an anonymous guest session.
It never calls signup, CAPTCHA verification, email activation, or OAuth.

Usage:
    python scripts/verify_protocol_live.py [--proxy URL] [--profile chrome136]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from protocol_client import ZaiProtocolClient
from protocol_fingerprint import BrowserFingerprint, stable_seed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", default="")
    parser.add_argument("--profile", default="chrome136")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    fingerprint = BrowserFingerprint.create(
        stable_seed("pro-zai-live-check"),
        impersonate=args.profile,
    )
    client = ZaiProtocolClient(
        fingerprint,
        proxy=args.proxy,
        timeout=args.timeout,
    )
    guest = client.bootstrap()
    print(
        json.dumps(
            {
                "success": True,
                "role": guest.get("role"),
                "guest_id": guest.get("id"),
                "guest_email": guest.get("email"),
                "has_guest_token": bool(client.state.guest_jwt),
                "cookie_names": sorted(client.cookie_snapshot()),
                "http_profile": fingerprint.impersonate,
                "device_id": fingerprint.device_id,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
