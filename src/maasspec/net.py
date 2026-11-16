"""The only outbound HTTP in MaaSSpec.

Every request names the hosts it may reach. HTTPS is required, except plain
HTTP to a loopback host when the caller opts in. Redirects are refused, so a
key never follows a 3xx to another host. Credentials in the URL are refused.
Responses are read up to a cap. Exceptions never carry headers or the query.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
USER_AGENT = "maasspec/0.1.0"

Opener = Callable[[urllib.request.Request, float], Any]


class HttpError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _default_opener(request: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.build_opener(_NoRedirect()).open(request, timeout=timeout)


def request(
    url: str,
    *,
    allow_hosts: Iterable[str],
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    allow_loopback_http: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = 30.0,
    opener: Opener | None = None,
    error_body: bool = False,
) -> bytes:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    if not host or parts.username or parts.password:
        raise HttpError("Refused: the URL has no host, or carries credentials.")
    if host not in {h.lower() for h in allow_hosts}:
        raise HttpError("Refused: host is not on this request's allowlist.")
    if scheme != "https" and not (
        scheme == "http" and allow_loopback_http and host in LOOPBACK_HOSTS
    ):
        raise HttpError("Refused: HTTPS is required (HTTP only to loopback when allowed).")

    sent = {"User-Agent": USER_AGENT, **(headers or {})}
    for value in sent.values():
        if "\r" in value or "\n" in value:
            raise HttpError("Refused: a header value contains a line break.")
    req = urllib.request.Request(url, data=body, method=method, headers=sent)
    send = opener or _default_opener
    try:
        response = send(req, timeout)
    except urllib.error.HTTPError as exc:
        detail = ""
        if error_body:
            detail = " " + exc.read(500).decode("utf-8", errors="replace")
        raise HttpError(f"HTTP {exc.code}.{detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HttpError("The endpoint was unreachable.") from exc
    try:
        payload = response.read(max_bytes + 1)
    finally:
        close = getattr(response, "close", None)
        if close:
            close()
    if len(payload) > max_bytes:
        raise HttpError(f"Response exceeded the {max_bytes} byte cap.")
    return payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
