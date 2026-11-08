from __future__ import annotations

import os
import time

from auth_gate import (
    create_session_value,
    is_public_path,
    verify_session_value,
)


def test_public_paths_and_static_assets():
    assert is_public_path("/login")
    assert is_public_path("/api/health")
    assert is_public_path("/static/app.js")
    assert not is_public_path("/api/tasks")


def test_signed_session_round_trip(monkeypatch):
    monkeypatch.setenv("PRO_ZAI_PASSWORD", "deploy-test-password")
    monkeypatch.setenv("PRO_ZAI_SESSION_SECRET", "test-session-secret")
    value = create_session_value()
    assert verify_session_value(value)


def test_tampered_or_expired_session_rejected(monkeypatch):
    monkeypatch.setenv("PRO_ZAI_PASSWORD", "deploy-test-password")
    monkeypatch.setenv("PRO_ZAI_SESSION_SECRET", "test-session-secret")
    value = create_session_value()
    assert not verify_session_value(value + "x")
    old = f"{int(time.time()) - 8 * 24 * 3600}.{value.split('.', 1)[1]}"
    assert not verify_session_value(old)
