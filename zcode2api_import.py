"""Push completed pro-zai registrations into a zcode2api account pool."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urljoin

import requests

from debug_log import event as debug_event, fingerprint


class Zcode2ApiImportError(RuntimeError):
    pass


def _base_url(value: str) -> str:
    base = (value or "").strip().rstrip("/")
    if not base:
        return ""
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base + "/"


def _token_value(item: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = str(item.get(name) or "").strip()
        if value:
            return value
    return ""


class Zcode2ApiImporter:
    """Use zcode2api's authenticated admin API instead of editing its DB."""

    def __init__(
        self,
        base_url: str,
        password: str,
        *,
        timeout: int = 20,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = _base_url(base_url)
        self.password = str(password or "")
        self.timeout = max(3, int(timeout))
        self.session = session or requests.Session()
        self._token = ""

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.password)

    def _url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Mapping[str, Any]] = None,
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if authenticated:
            if not self._token:
                self.login()
            headers["Authorization"] = f"Bearer {self._token}"
        response = self.session.request(
            method,
            self._url(path),
            headers=headers,
            json=dict(body) if body is not None else None,
            timeout=self.timeout,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"ok": False, "error": response.text[:1000]}
        if response.status_code == 401 and authenticated:
            self._token = ""
            self.login()
            return self._request(
                method,
                path,
                body=body,
                authenticated=False,
            )
        if response.status_code >= 400:
            message = (
                payload.get("error")
                if isinstance(payload, Mapping)
                else None
            ) or f"HTTP {response.status_code}"
            raise Zcode2ApiImportError(str(message))
        if not isinstance(payload, Mapping):
            raise Zcode2ApiImportError("zcode2api returned non-object JSON")
        return dict(payload)

    def login(self) -> str:
        if not self.enabled:
            raise Zcode2ApiImportError("zcode2api URL or admin password missing")
        payload = self._request(
            "POST",
            "/api/auth/login",
            body={"password": self.password},
            authenticated=False,
        )
        token = str(payload.get("token") or "")
        if payload.get("ok") is not True or not token:
            raise Zcode2ApiImportError(
                str(payload.get("error") or "zcode2api admin login failed")
            )
        self._token = token
        return token

    def import_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        zcode_jwt = _token_value(task, "cli_jwt", "zcode_jwt")
        web_jwt = _token_value(task, "web_jwt")
        business_token = _token_value(
            task,
            "business_token",
            "access_token",
        )
        if not zcode_jwt:
            raise Zcode2ApiImportError("task has no CLI JWT")
        payload = self._request(
            "POST",
            "/api/accounts/import-registration",
            body={
                "label": str(
                    task.get("email") or task.get("name") or "pro-zai"
                )[:60],
                "provider": "zai",
                "zcodeJwt": zcode_jwt,
                "webJwt": web_jwt,
                "businessToken": business_token,
                "deviceMid": str(task.get("device_mid") or ""),
            },
        )
        if payload.get("ok") is not True:
            raise Zcode2ApiImportError(
                str(payload.get("error") or payload.get("reason") or "import failed")
            )
        debug_event(
            "zcode2api.imported",
            task_id=str(task.get("id") or ""),
            account_id=str(payload.get("id") or ""),
            updated=bool(payload.get("updated")),
            verified=bool(payload.get("verified")),
            cli_jwt=fingerprint(zcode_jwt),
            web_jwt=fingerprint(web_jwt),
            business_token=fingerprint(business_token),
            device_mid=str(task.get("device_mid") or ""),
        )
        return payload

    def health(self) -> Dict[str, Any]:
        response = self.session.get(
            self._url("/healthz"),
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return dict(payload) if isinstance(payload, Mapping) else {}
