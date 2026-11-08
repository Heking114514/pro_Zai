"""Shared Playwright route policy for analytics requests."""

from __future__ import annotations

from typing import Any, Callable, Optional


# These are beacon/ad domains. Fulfilling them avoids page-visible network
# errors while keeping their scripts and event payloads off the network.
ANALYTICS_HOSTS = (
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googleadservices.com",
    "googlesyndication.com",
    "doubleclick.net",
    "facebook.com",
    "facebook.net",
    "alb.reddit.com",
    "reddit.com",
    "redditstatic.com",
    "clarity.ms",
    "hotjar.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "sentry.io",
    "bugsnag.com",
    "datadoghq.com",
    "newrelic.com",
)

# RUM endpoints are intentionally not in ANALYTICS_HOSTS. They are part of the
# site's own telemetry path and blocking them creates false network failures.


def host_matches(url: str, markers: tuple[str, ...] | list[str]) -> bool:
    try:
        host = url.split("/", 3)[2].lower()
    except Exception:
        return False
    return any(marker in host for marker in markers)


async def install_analytics_route(
    page: Any,
    *,
    task_id: str = "",
    on_fulfilled: Optional[Callable[[str], None]] = None,
) -> None:
    """Return successful empty responses for third-party telemetry."""

    async def handle_route(route: Any) -> None:
        url = route.request.url
        if host_matches(url, ANALYTICS_HOSTS):
            if on_fulfilled:
                on_fulfilled(url)
            await route.fulfill(
                status=204,
                headers={
                    "access-control-allow-origin": "*",
                    "cache-control": "no-store",
                    "content-length": "0",
                },
                body=b"",
            )
            return
        await route.continue_()

    await page.route("**/*", handle_route)
