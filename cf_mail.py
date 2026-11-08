"""Dynamic mailbox allocation for the Cloudflare Temp Email service."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

import requests


class CfMailError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        response_body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.response_body = response_body


@dataclass(frozen=True)
class CfMailbox:
    email: str
    jwt: str
    api_base: str
    api_url: str
    address_id: int = 0

    def public_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "api_base": self.api_base,
            "api_url": self.api_url,
            "address_id": self.address_id,
            "has_jwt": bool(self.jwt),
        }


def normalize_cf_base(value: str) -> str:
    base = (value or "").strip().rstrip("/")
    if not base:
        base = "https://mail.example.com"
    if not re.match(r"^https?://", base, re.I):
        base = "https://" + base
    if not base.lower().startswith("https://"):
        raise ValueError("CF mailbox API must use HTTPS")
    if base.endswith("/api"):
        base = base[:-4]
    return base


def mailbox_mail_url(base: str, limit: int = 20, offset: int = 0) -> str:
    return f"{normalize_cf_base(base)}/api/mails?limit={int(limit)}&offset={int(offset)}"


class CfMailClient:
    def __init__(
        self,
        base_url: str = "https://mail.example.com",
        *,
        site_password: str = "",
        timeout: int = 20,
    ) -> None:
        self.base = normalize_cf_base(base_url)
        self.site_password = (site_password or "").strip()
        self.timeout = max(5, int(timeout))
        self.session = requests.Session()
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "pro-zai/1.0",
        }
        if self.site_password:
            headers["x-custom-auth"] = self.site_password
        self.session.headers.update(headers)

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str = "",
        **kwargs: Any,
    ) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = self.session.request(
                method,
                f"{self.base}{path}",
                headers=headers,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise CfMailError(f"CF mailbox request failed: {exc}") from exc
        if response.status_code >= 400:
            raise CfMailError(
                f"CF mailbox returned HTTP {response.status_code}: {response.text[:300]}",
                status=response.status_code,
                response_body=response.text[:2000],
            )
        return response

    def create_address(
        self,
        *,
        name: str = "",
        domain: str = "",
        password: str = "",
    ) -> CfMailbox:
        body: Dict[str, Any] = {}
        if name.strip():
            body["name"] = name.strip()
        if domain.strip():
            body["domain"] = domain.strip()
        if password:
            body["password"] = password
        response = self._request("POST", "/api/new_address", json=body)
        try:
            data = response.json()
        except ValueError as exc:
            raise CfMailError("CF mailbox creation returned invalid JSON") from exc
        email = str(data.get("address") or "").strip()
        jwt = str(data.get("jwt") or "").strip()
        if "@" not in email or not jwt:
            raise CfMailError("CF mailbox creation response is missing address or JWT")
        return CfMailbox(
            email=email.lower(),
            jwt=jwt,
            api_base=self.base,
            api_url=mailbox_mail_url(self.base),
            address_id=int(data.get("address_id") or 0),
        )

    def settings(self, token: str) -> Dict[str, Any]:
        response = self._request("GET", "/api/settings", token=token)
        data = response.json()
        return dict(data) if isinstance(data, Mapping) else {}

    def list_mails(
        self,
        token: str,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        response = self._request(
            "GET",
            f"/api/mails?limit={max(1, int(limit))}&offset={max(0, int(offset))}",
            token=token,
        )
        try:
            data = response.json()
        except ValueError as exc:
            raise CfMailError("CF mailbox list returned invalid JSON") from exc
        results = data.get("results") if isinstance(data, Mapping) else None
        if not isinstance(results, list):
            return []
        return [dict(item) for item in results if isinstance(item, Mapping)]

    def allocate(
        self,
        *,
        requested_name: str,
        domain: str,
        existing_emails: set[str],
    ) -> CfMailbox:
        clean = re.sub(r"[^a-z0-9]", "", requested_name.lower())[:18]
        if len(clean) < 3:
            clean = "user" + secrets.token_hex(3)
        candidates = [clean, f"{clean}{secrets.token_hex(2)}"]
        last_error: Optional[Exception] = None
        for candidate in candidates:
            try:
                mailbox = self.create_address(name=candidate, domain=domain)
            except CfMailError as exc:
                last_error = exc
                # Some deployments choose a random address instead of honoring
                # the requested name. That is acceptable as long as it is unique.
                try:
                    mailbox = self.create_address(domain=domain)
                except CfMailError:
                    continue
            if mailbox.email not in existing_emails:
                return mailbox
        raise CfMailError(
            f"Unable to allocate a unique CF mailbox: {last_error or 'duplicate address'}"
        )

    def wait_until_ready(self, token: str, timeout: int = 20) -> Dict[str, Any]:
        deadline = time.monotonic() + max(5, int(timeout))
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            try:
                return self.settings(token)
            except CfMailError as exc:
                last_error = exc
                time.sleep(1)
        raise CfMailError(f"CF mailbox JWT was not accepted: {last_error}")
