"""Local web UI server: the built UI plus a small JSON API, on loopback only.

The browser never holds a key and never talks to a feed or to NocTORnal. It
asks this process, which reads keys from its own environment and goes out
through `maasspec.net`. Every API call needs a per-run token that is printed
in the URL fragment (never sent as part of a request line), the Host header
must be a loopback name with this port, and a cross-origin request is refused.
Spectra live in memory for the session; nothing is written to disk except a
short-lived temp file while one upload is analyzed.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sys
import tempfile
import threading
import traceback
import uuid
from collections import OrderedDict
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from maasspec import __version__, net
from maasspec.engine import MAX_REPORT_BYTES, analyze_path, spectra_from_feed
from maasspec.feeds import ADAPTERS, get_adapter
from maasspec.feeds.base import MAX_IMPORT_BYTES, FeedFormatError, FetchOptions
from maasspec.ingest.noctornal import IngestClient, check_base_url
from maasspec.models import Spectrum
from maasspec.stream import parse_spectra

INGEST_URL_ENV = "MAASSPEC_NOCTORNAL_URL"
INGEST_KEY_ENV = "MAASSPEC_INGEST_KEY"
ABUSECH_KEY_ENV = "MAASSPEC_ABUSECH_KEY"
DEFAULT_PORT = 8787
MAX_JSON_BODY = 1024 * 1024
MAX_ANALYZE_BYTES = MAX_REPORT_BYTES
MAX_SPECTRA = 5000
MAX_FETCHES = 8
MAX_SEND = 500
IMPORT_LIMIT = MAX_SPECTRA
NAME_SAFE = re.compile(r"[^A-Za-z0-9._ -]")
STATUS_IN_MESSAGE = re.compile(r"HTTP (\d{3})")
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".txt": "text/plain; charset=utf-8",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str, *, close: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.close = close


def default_ui_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "ui" / "app" / "dist"


class Session:
    """Spectra and fetched feed responses for one server run."""

    def __init__(self, env: Mapping[str, str], opener: net.Opener | None = None) -> None:
        self.env = env
        self.opener = opener
        self._lock = threading.Lock()
        self._spectra: OrderedDict[str, Spectrum] = OrderedDict()
        self._fetches: OrderedDict[str, tuple[str, bytes]] = OrderedDict()

    def status(self) -> dict[str, Any]:
        has_abusech = bool(self.env.get(ABUSECH_KEY_ENV))
        return {
            "version": __version__,
            "env": {"ingestUrl": INGEST_URL_ENV, "ingestKey": INGEST_KEY_ENV, "abusech": ABUSECH_KEY_ENV},
            "ingest": {**self._ingest_address(), "keySet": bool(self.env.get(INGEST_KEY_ENV))},
            "feeds": {
                name: {
                    "needsKey": adapter.needs_key,
                    "keySet": has_abusech if adapter.needs_key else False,
                    "queries": dict(adapter.queries),
                }
                for name, adapter in ADAPTERS.items()
            },
        }

    def _ingest_address(self) -> dict[str, Any]:
        """Scheme, host and port of the configured NocTORnal, once the client's own checks pass. Never the raw string."""
        raw = self.env.get(INGEST_URL_ENV, "")
        empty: dict[str, Any] = {"url": None, "scheme": None, "host": None, "port": None, "problem": None}
        if not raw:
            return empty
        try:
            parts = check_base_url(raw)
        except ValueError as exc:
            return {**empty, "problem": str(exc)}
        host = (parts.hostname or "").lower()
        origin_host = f"[{host}]" if ":" in host else host
        port = parts.port
        return {
            "url": f"{parts.scheme}://{origin_host}" + (f":{port}" if port else ""),
            "scheme": parts.scheme,
            "host": host,
            "port": port,
            "problem": None,
        }

    def all_spectra(self) -> list[dict]:
        with self._lock:
            return [s.model_dump(mode="json") for s in self._spectra.values()]

    def add(self, spectra: list[Spectrum]) -> list[dict]:
        with self._lock:
            for spectrum in spectra:
                key = str(spectrum.analysis_id)
                self._spectra.pop(key, None)
                self._spectra[key] = spectrum
            while len(self._spectra) > MAX_SPECTRA:
                self._spectra.popitem(last=False)
        return [s.model_dump(mode="json") for s in spectra]

    def parse(self, data: bytes) -> list[dict]:
        try:
            spectra = list(parse_spectra(data))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ApiError(400, str(exc) or "Not a valid spectrum file.") from exc
        if not spectra:
            raise ApiError(400, "The file holds no spectra.")
        return self.add(spectra)

    def analyze(self, filename: str, data: bytes) -> list[dict]:
        name = NAME_SAFE.sub("_", Path(filename or "upload").name)[:120].strip(" .") or "upload"
        with tempfile.TemporaryDirectory(prefix="maasspec-") as folder:
            path = Path(folder) / "upload.bin"
            path.write_bytes(data)
            spectrum = analyze_path(path)
        spectrum.input.filename = name
        return self.add([spectrum])

    def import_feed(self, feed: str, data: bytes, limit: int) -> list[dict]:
        adapter = _adapter(feed)
        try:
            spectra = list(spectra_from_feed(adapter, data, limit=limit))
        except FeedFormatError as exc:
            raise ApiError(400, str(exc)) from exc
        if not spectra:
            raise ApiError(400, "No records found in that input.")
        return self.add(spectra)

    def fetch(self, payload: dict) -> dict:
        feed = _text(payload, "feed")
        adapter = _adapter(feed)
        query = _text(payload, "query")
        options = FetchOptions(
            limit=_int(payload, "limit"),
            days=_int(payload, "days"),
            selector=_text(payload, "selector", required=False),
            exact=_flag(payload, "exact"),
        )
        key = self.env.get(ABUSECH_KEY_ENV) if adapter.needs_key else None
        if adapter.needs_key and not key:
            raise ApiError(409, f"Set {ABUSECH_KEY_ENV} in the environment that started maasspec serve.")
        try:
            body = adapter.fetch(
                query, _text(payload, "term", required=False), options, key=key, opener=self.opener
            )
        except ValueError as exc:
            raise ApiError(400, str(exc)) from exc
        except net.HttpError as exc:
            raise ApiError(502, str(exc)) from exc
        fetch_id = uuid.uuid4().hex
        with self._lock:
            self._fetches[fetch_id] = (feed, body)
            while len(self._fetches) > MAX_FETCHES:
                self._fetches.popitem(last=False)
        return {"fetchId": fetch_id, "bytes": len(body)}

    def import_fetched(self, payload: dict) -> list[dict]:
        fetch_id = _text(payload, "fetchId")
        with self._lock:
            held = self._fetches.get(fetch_id)
        if held is None:
            raise ApiError(404, "That fetch is no longer held. Fetch again.")
        limit = _int(payload, "limit") or 1000
        return self.import_feed(held[0], held[1], _limit(limit))

    def send(self, payload: dict) -> list[dict]:
        ids = payload.get("ids")
        if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
            raise ApiError(400, "ids must be a non-empty list of analysis ids.")
        ids = list(dict.fromkeys(ids))[:MAX_SEND]
        url = self.env.get(INGEST_URL_ENV, "")
        key = self.env.get(INGEST_KEY_ENV, "")
        if not url or not key:
            raise ApiError(409, f"Set {INGEST_URL_ENV} and {INGEST_KEY_ENV} in the environment that started maasspec serve.")
        try:
            client = IngestClient(url, key)
        except ValueError as exc:
            raise ApiError(409, str(exc)) from exc
        results: list[dict] = []
        stopped = False
        for spectrum_id in ids:
            if stopped:
                results.append({"id": spectrum_id, "status": "not_sent"})
                continue
            with self._lock:
                spectrum = self._spectra.get(spectrum_id)
            if spectrum is None:
                results.append({"id": spectrum_id, "status": "failed", "message": "Unknown spectrum id."})
                stopped = True
                continue
            try:
                body = client.submit_spectrum(spectrum, opener=self.opener)
            except net.HttpError as exc:
                found = STATUS_IN_MESSAGE.match(str(exc))
                results.append(
                    {
                        "id": spectrum_id,
                        "status": "failed",
                        "httpStatus": int(found.group(1)) if found else None,
                        "message": str(exc)[:300],
                    }
                )
                stopped = True
                continue
            results.append({"id": spectrum_id, "status": "ok", **_ingest_reply(body)})
        return results


def make_server(
    ui_dir: Path,
    *,
    port: int = DEFAULT_PORT,
    env: Mapping[str, str] | None = None,
    opener: net.Opener | None = None,
    token: str | None = None,
) -> tuple[ThreadingHTTPServer, str]:
    ui_dir = Path(ui_dir).resolve()
    if not (ui_dir / "index.html").is_file():
        raise ValueError(
            f"The UI is not built ({ui_dir}). Run: npm --prefix ui/app install && npm --prefix ui/app run build"
        )
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    server.daemon_threads = True
    actual = server.server_address[1]
    server.session = Session(env if env is not None else {}, opener)  # type: ignore[attr-defined]
    server.token = token or secrets.token_urlsafe(24)  # type: ignore[attr-defined]
    server.ui_dir = ui_dir  # type: ignore[attr-defined]
    server.allowed_hosts = {f"127.0.0.1:{actual}", f"localhost:{actual}"}  # type: ignore[attr-defined]
    server.allowed_origins = {f"http://{host}" for host in server.allowed_hosts}  # type: ignore[attr-defined]
    return server, server.token  # type: ignore[attr-defined]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "maasspec"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def _handle(self, method: str) -> None:
        self._body_read = False
        self._framing_error = False
        self._authed = False
        try:
            self._guard()
            parts = urlsplit(self.path)
            path = parts.path
            if path.startswith("/api/"):
                self._api(method, path, parse_qs(parts.query))
            elif method == "GET":
                self._static(path)
            else:
                raise ApiError(405, "Method not allowed.", close=True)
        except ApiError as exc:
            close = exc.close
            if method == "POST":
                close = self._framing_error or not self._drain(
                    MAX_ANALYZE_BYTES if self._authed else MAX_JSON_BODY
                )
            self._json(exc.status, {"error": exc.message}, close=close)
        except Exception as exc:  # noqa: BLE001 - never leak internals to the browser
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            print(
                f"maasspec serve: {type(exc).__name__} at {Path(frame.filename).name}:{frame.lineno}",
                file=sys.stderr,
                flush=True,
            )
            self._json(500, {"error": "Internal error."}, close=True)

    def _guard(self) -> None:
        server = self.server
        if self.headers.get("Host", "").lower() not in server.allowed_hosts:  # type: ignore[attr-defined]
            raise ApiError(403, "Host not allowed.", close=True)
        origin = self.headers.get("Origin")
        if origin is not None and origin not in server.allowed_origins:  # type: ignore[attr-defined]
            raise ApiError(403, "Cross-origin request refused.", close=True)

    def _api(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        sent = self.headers.get("X-MaaSSpec-Token", "")
        if not hmac.compare_digest(sent.encode("utf-8", "replace"), self.server.token.encode("utf-8")):  # type: ignore[attr-defined]
            raise ApiError(401, "Open the URL printed by maasspec serve.", close=True)
        self._authed = True
        session: Session = self.server.session  # type: ignore[attr-defined]
        if method == "GET" and path == "/api/status":
            self._json(200, session.status())
        elif method == "GET" and path == "/api/spectra":
            self._json(200, {"spectra": session.all_spectra()})
        elif method == "POST" and path == "/api/spectra/parse":
            self._json(200, {"spectra": session.parse(self._body(MAX_IMPORT_BYTES))})
        elif method == "POST" and path == "/api/analyze":
            name = (query.get("filename") or ["upload"])[0]
            self._json(200, {"spectra": session.analyze(name, self._body(MAX_ANALYZE_BYTES))})
        elif method == "POST" and path == "/api/import":
            feed = (query.get("feed") or [""])[0]
            limit = _limit(_query_int(query, "limit", 1000))
            self._json(200, {"spectra": session.import_feed(feed, self._body(MAX_IMPORT_BYTES), limit)})
        elif method == "POST" and path == "/api/feeds/fetch":
            self._json(200, session.fetch(self._json_body()))
        elif method == "POST" and path == "/api/feeds/import":
            self._json(200, {"spectra": session.import_fetched(self._json_body())})
        elif method == "POST" and path == "/api/send":
            self._json(200, {"results": session.send(self._json_body())})
        else:
            raise ApiError(404, "No such endpoint.", close=method == "POST")

    def _body(self, cap: int) -> bytes:
        header = self.headers.get("Content-Length")
        if header is None or not header.isdigit():
            self._framing_error = True
            raise ApiError(411, "Content-Length is required.", close=True)
        length = int(header)
        if length > cap:
            self._framing_error = True
            raise ApiError(413, "Request body is too large.", close=True)
        self._body_read = True
        return self.rfile.read(length)

    def _drain(self, cap: int) -> bool:
        """Read an unread request body so the reply is not lost to a connection reset.

        False means the body was not read and the connection must close.
        """
        if self._body_read:
            return True
        header = self.headers.get("Content-Length")
        if header is None or not header.isdigit() or int(header) > cap:
            return False
        remaining = int(header)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1024 * 1024))
            if not chunk:
                return False
            remaining -= len(chunk)
        self._body_read = True
        return True

    def _json_body(self) -> dict:
        try:
            value = json.loads(self._body(MAX_JSON_BODY).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, "Body is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise ApiError(400, "Body must be a JSON object.")
        return value

    def _static(self, request_path: str) -> None:
        root: Path = self.server.ui_dir  # type: ignore[attr-defined]
        relative = unquote(request_path).lstrip("/")
        try:
            target = (root / relative).resolve() if relative else root / "index.html"
        except ValueError as exc:
            raise ApiError(404, "Not found.") from exc
        inside = target == root or root in target.parents
        if not inside or not target.is_file():
            last = relative.rsplit("/", 1)[-1]
            if "." in last:
                raise ApiError(404, "Not found.")
            target = root / "index.html"
        body = target.read_bytes()
        headers = {"Content-Type": MIME.get(target.suffix.lower(), "application/octet-stream")}
        if target.suffix.lower() == ".html":
            headers["Content-Security-Policy"] = CSP
        self._send(200, body, headers)

    def _json(self, status: int, payload: Any, *, close: bool = False) -> None:
        self._send(
            status,
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            {"Content-Type": "application/json"},
            close=close,
        )

    def _send(self, status: int, body: bytes, headers: dict[str, str], *, close: bool = False) -> None:
        self.send_response(status)
        for name, value in {**SECURITY_HEADERS, **headers}.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)


def _adapter(feed: str):
    try:
        return get_adapter(feed)
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc


def _text(payload: dict, name: str, *, required: bool = True) -> str | None:
    value = payload.get(name)
    if value is None or value == "":
        if required:
            raise ApiError(400, f"{name} is required.")
        return None
    if not isinstance(value, str) or len(value) > 512:
        raise ApiError(400, f"{name} must be a short string.")
    return value


def _int(payload: dict, name: str) -> int | None:
    value = payload.get(name)
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(400, f"{name} must be a whole number.")
    return value


def _flag(payload: dict, name: str) -> bool:
    value = payload.get(name, False)
    if not isinstance(value, bool):
        raise ApiError(400, f"{name} must be true or false.")
    return value


def _query_int(query: dict[str, list[str]], name: str, default: int) -> int:
    raw = (query.get(name) or [""])[0]
    if raw == "":
        return default
    if not raw.isdigit():
        raise ApiError(400, f"{name} must be a whole number.")
    return int(raw)


def _limit(value: int) -> int:
    if not 1 <= value <= IMPORT_LIMIT:
        raise ApiError(400, f"limit must be between 1 and {IMPORT_LIMIT}.")
    return value


def _ingest_reply(body: bytes) -> dict[str, Any]:
    try:
        reply = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(reply, dict):
        return {}
    out: dict[str, Any] = {}
    if isinstance(reply.get("batch_id"), str):
        out["batchId"] = reply["batch_id"][:64]
    for source, target in (("accepted", "accepted"), ("duplicate", "duplicate")):
        if isinstance(reply.get(source), bool):
            out[target] = reply[source]
    return out
