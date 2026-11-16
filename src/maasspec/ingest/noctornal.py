"""Post a spectrum as raw bytes to NocTORnal's ingest API.

NocTORnal stores the body content-addressed and does not accept a typed
proposal at this edge. Parsing, grading, and case attachment are later,
human-gated steps. This client does not call them.
"""

from __future__ import annotations

import json
import re
from urllib.parse import SplitResult, urlsplit

from maasspec import net
from maasspec.models import Spectrum

INGEST_PATH = "/api/v1/ingest"
INGEST_KEY = re.compile(r"noct_sk_(live|test)_[A-Za-z0-9]{32}")
IngestError = net.HttpError
Opener = net.Opener


def spectrum_document(spectrum: Spectrum) -> bytes:
    """One compact JSON object on one line. NocTORnal sniffs this as a JSON object."""
    return spectrum.model_dump_json().encode("utf-8")


def spectrum_ndjson(spectrum: Spectrum) -> bytes:
    """Header record plus one record per finding. A local review form, not sent."""
    header = {
        "record_type": "maasspec.spectrum",
        "maasspec_version": spectrum.maasspec_version,
        "analysis_id": str(spectrum.analysis_id),
        "input": spectrum.input.model_dump(mode="json"),
        "summary": spectrum.summary.model_dump(mode="json") if spectrum.summary else None,
    }
    lines = [json.dumps(header, separators=(",", ":"), default=str)]
    for finding in spectrum.findings:
        row = {"record_type": "maasspec.finding", **finding.model_dump(mode="json")}
        lines.append(json.dumps(row, separators=(",", ":"), default=str))
    return ("\n".join(lines) + "\n").encode("utf-8")


def check_base_url(base_url: str) -> SplitResult:
    """The rules for a NocTORnal address. Raises ValueError with a message that never repeats the URL."""
    parts = urlsplit(base_url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"https", "http"} or not host:
        raise ValueError("Ingest URL must be an https URL, or http on loopback.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Ingest URL must not carry credentials, a query, or a fragment.")
    try:
        parts.port  # noqa: B018 - reading the port is what validates it
    except ValueError:
        raise ValueError("Ingest URL has an invalid port.") from None
    if parts.scheme == "http" and host not in net.LOOPBACK_HOSTS:
        raise ValueError("Ingest URL must be https, or http on loopback for a local NocTORnal.")
    return parts


class IngestClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0):
        if not INGEST_KEY.fullmatch(api_key):
            raise ValueError(
                "Refusing to send without a NocTORnal ingest key "
                "(noct_sk_live_ or noct_sk_test_ followed by 32 characters)."
            )
        parts = check_base_url(base_url)
        host = (parts.hostname or "").lower()
        self.base_url = base_url.rstrip("/")
        self.host = host
        self.api_key = api_key
        self.timeout = timeout

    def submit_spectrum(self, spectrum: Spectrum, opener: Opener | None = None) -> bytes:
        return net.request(
            self.base_url + INGEST_PATH,
            allow_hosts={self.host},
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Idempotency-Key": str(spectrum.analysis_id),
                "Content-Type": "application/json",
            },
            body=spectrum_document(spectrum),
            allow_loopback_http=True,
            max_bytes=1024 * 1024,
            timeout=self.timeout,
            opener=opener,
            error_body=True,
        )
