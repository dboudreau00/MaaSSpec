"""Contract and shared helpers for public-feed adapters.

An adapter does two separate jobs. `records` and `run` are pure: they read
bytes and return drafts, with no network. `fetch` is the only part that
touches the network, and it goes through `maasspec.net`. Feed data is a claim
by a third party: every finding carries `claimed` and a grade that says so.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, ClassVar

from maasspec import net
from maasspec.models import AnalysisError, ProposedGrade, Selector
from maasspec.modules.base import ModuleOutput

MAX_IMPORT_BYTES = 64 * 1024 * 1024
MAX_VALUE_CHARS = 2048
MAX_TAGS = 20
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_KEY = re.compile(r"[A-Za-z0-9_\-]{8,128}")
_HEX = {kind: re.compile(f"[a-f0-9]{{{size}}}") for kind, size in HASH_LENGTHS.items()}
_FUZZY = re.compile(r"[A-Za-z0-9:/+]{1,200}")
_TERM = re.compile(r"[A-Za-z0-9._\- ]{1,64}")


class FeedFormatError(ValueError):
    pass


@dataclass(frozen=True)
class FetchOptions:
    limit: int | None = None
    days: int | None = None
    selector: str | None = None
    exact: bool = False


class FeedAdapter:
    feed = "feed"
    name = "feed.base"
    version = "0.3.1"
    hosts: frozenset[str] = frozenset()
    queries: ClassVar[dict[str, str]] = {}
    needs_key = True

    def records(self, data: bytes) -> Iterator[dict]:
        raise NotImplementedError

    def record_id(self, record: dict) -> str | None:
        return None

    def sample_sha256(self, record: dict) -> str | None:
        return None

    def sighting_time(self, record: dict) -> datetime | None:
        """When the feed says it saw the record, in UTC. None when it does not say."""
        for key in ("first_seen", "created"):
            parsed = parse_time(record.get(key))
            if parsed is not None:
                return parsed
        return None

    def run(self, record: dict) -> ModuleOutput:
        raise NotImplementedError

    def fetch(
        self,
        query: str,
        term: str | None,
        options: FetchOptions,
        key: str | None = None,
        opener: net.Opener | None = None,
    ) -> bytes:
        raise NotImplementedError


def parse_time(value: Any) -> datetime | None:
    cleaned = text(value, 64)
    if cleaned is None:
        return None
    cleaned = cleaned.removesuffix("UTC").removesuffix("utc").strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def decode(data: bytes) -> str:
    if len(data) > MAX_IMPORT_BYTES:
        raise FeedFormatError("Input exceeds the import size cap.")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FeedFormatError("Input is not UTF-8 text.") from exc


def load_json(data: bytes) -> Any:
    try:
        return json.loads(decode(data))
    except json.JSONDecodeError as exc:
        raise FeedFormatError("Input is not valid JSON.") from exc


def read_commented_csv(text: str, header_hint: str) -> Iterator[dict[str, str]]:
    """Header-driven CSV where the header may sit on a `#` comment line."""
    header: list[str] | None = None
    body: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            if header is None and header_hint in candidate:
                header = _split_row(candidate)
            continue
        if header is None and header_hint in stripped:
            header = _split_row(stripped)
            continue
        body.append(stripped)
    if header is None:
        raise FeedFormatError(f"CSV header with a {header_hint!r} column was not found.")
    for row in csv.reader(io.StringIO("\n".join(body)), skipinitialspace=True):
        if row:
            yield dict(zip(header, (cell.strip() for cell in row), strict=False))


def _split_row(line: str) -> list[str]:
    return [cell.strip().strip('"') for cell in next(csv.reader([line], skipinitialspace=True))]


def text(value: Any, limit: int = MAX_VALUE_CHARS) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    cleaned = "".join(ch for ch in str(value) if ch.isprintable())[:limit].strip()
    return cleaned or None


def hex_digest(value: Any, kind: str) -> str | None:
    cleaned = text(value, 128)
    if cleaned is None:
        return None
    cleaned = cleaned.lower()
    return cleaned if _HEX[kind].fullmatch(cleaned) else None


def fuzzy_digest(value: Any) -> str | None:
    cleaned = text(value, 200)
    return cleaned if cleaned and _FUZZY.fullmatch(cleaned) else None


def tag_list(value: Any, prefix: str = "tag:") -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value[:MAX_TAGS]:
        cleaned = text(item, 64)
        if cleaned:
            out.append(prefix + cleaned.lower())
    return out


def claim_grade(rationale: str, credibility: str = "3") -> ProposedGrade:
    return ProposedGrade(
        source_reliability="C",
        information_credibility=credibility,  # type: ignore[arg-type]
        rationale=rationale,
    )


def hash_selectors(values: dict[str, str | None]) -> list[Selector]:
    return [
        Selector(kind=kind, value=value, normalized=value.lower())
        for kind, value in values.items()
        if value
    ]


def warning(module: str, message: str) -> AnalysisError:
    return AnalysisError(severity="warning", module=module, message=message, recoverable=True)


def info(module: str, message: str) -> AnalysisError:
    return AnalysisError(severity="info", module=module, message=message, recoverable=True)


def check_key(key: str | None, env_name: str) -> str:
    if not key:
        raise ValueError(f"Set {env_name}.")
    if not _KEY.fullmatch(key):
        raise ValueError(f"{env_name} is not shaped like an abuse.ch Auth-Key.")
    return key


def check_term(term: str | None, what: str) -> str:
    if not term or not _TERM.fullmatch(term):
        raise ValueError(f"A {what} is required: 1 to 64 letters, digits, space, dot, dash, underscore.")
    return term


def check_limit(limit: int | None, default: int = 100, ceiling: int = 1000) -> int:
    if limit is None:
        return default
    if not 1 <= limit <= ceiling:
        raise ValueError(f"--limit must be between 1 and {ceiling}.")
    return limit
