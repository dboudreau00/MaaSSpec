"""ThreatFox (abuse.ch): API responses and JSON or CSV exports, metadata only.

The API shape is from https://threatfox.abuse.ch/api/ (POST JSON, `Auth-Key`
header, `query_status` plus `data`). The export layouts are not public (they
sit behind the abuse.ch login), so the export readers accept the older
`ioc_value` and `first_seen_utc` names as aliases and have only been
exercised on synthetic files.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator
from typing import ClassVar
from urllib.parse import urlsplit

from maasspec import net
from maasspec.feeds import base
from maasspec.feeds.base import FeedAdapter, FeedFormatError, FetchOptions
from maasspec.models import Artifact, DraftFinding, FamilySummary, Selector, SourceRef
from maasspec.modules.base import ModuleOutput
from maasspec.selectors import is_unroutable

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
_ALIASES = {
    "ioc_value": "ioc",
    "ioc_id": "id",
    "first_seen_utc": "first_seen",
    "last_seen_utc": "last_seen",
}
_HASH_TYPES = {"md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}
_KNOWN_TYPES = {"url", "domain", "ip:port", *_HASH_TYPES}
_CAPABILITY_THREATS = {"botnet_cc", "payload_delivery"}
_CONFIDENCE_CEILING = 0.7
_PRIVATE_GRADE = base.claim_grade(
    "Private or loopback address, not reachable from outside. A C2 claim for it is doubtful.",
    credibility="4",
)
MAX_SAMPLES = 20


class ThreatFoxFeed(FeedAdapter):
    feed = "threatfox"
    name = "feed.threatfox"
    hosts = frozenset({"threatfox-api.abuse.ch"})
    queries: ClassVar[dict[str, str]] = {
        "recent": "IOCs first seen in the last --days (1 to 7, default 1)",
        "hash": "IOCs tied to an MD5 or SHA-256 hash",
        "malware": "IOCs for a Malpedia family name (--limit 1 to 1000)",
        "search": "IOC search by value (--exact for an exact match)",
    }

    def records(self, data: bytes) -> Iterator[dict]:
        raw = base.decode(data)
        if raw.lstrip()[:1] not in {"{", "["}:
            for row in base.read_commented_csv(raw, "ioc_value"):
                yield _normalize(row)
            return
        document = base.load_json(data)
        if isinstance(document, dict) and "query_status" in document:
            status = base.text(document.get("query_status"), 64)
            if status != "ok":
                raise FeedFormatError(f"ThreatFox returned query_status {status!r}.")
            rows = document.get("data")
            if not isinstance(rows, list):
                raise FeedFormatError("ThreatFox response has no data list.")
            yield from (_normalize(row) for row in rows if isinstance(row, dict))
        elif isinstance(document, dict):
            for key, rows in document.items():
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict):
                            yield _normalize({"id": key, **row})
        elif isinstance(document, list):
            yield from (_normalize(row) for row in document if isinstance(row, dict))
        else:
            raise FeedFormatError("ThreatFox input is not an object or a list.")

    def record_id(self, record: dict) -> str | None:
        return base.text(record.get("id"), 64)

    def sample_sha256(self, record: dict) -> str | None:
        if base.text(record.get("ioc_type"), 32) == "sha256_hash":
            return base.hex_digest(record.get("ioc"), "sha256")
        for sample in _dicts(record.get("malware_samples")):
            digest = base.hex_digest(sample.get("sha256_hash"), "sha256")
            if digest:
                return digest
        return None

    def run(self, record: dict) -> ModuleOutput:
        out = ModuleOutput()
        ioc = base.text(record.get("ioc"), 1024)
        ioc_type = (base.text(record.get("ioc_type"), 32) or "").lower()
        if not ioc:
            out.errors.append(base.warning(self.name, "Record has no ioc value. No finding."))
            return out
        level = _level(record.get("confidence_level"))
        confidence = round(_CONFIDENCE_CEILING * level / 100, 2) if level is not None else 0.35
        grade = base.claim_grade(
            "Confidence level stated by ThreatFox: "
            + (str(level) if level is not None else "not given")
            + ". MaaSSpec has not checked it.",
            credibility="2" if level is not None and level >= 75 else "3",
        )
        threat = (base.text(record.get("threat_type"), 64) or "").lower()
        tags = ["feed", "feed:threatfox", "claimed", *base.tag_list(record.get("tags"))]
        if threat:
            tags.append(f"threat:{threat}")
        if threat in _CAPABILITY_THREATS:
            tags.append(f"capability:{threat}")
        context = _context(record, level)
        source = None
        for index, entry in enumerate(_dicts(record.get("malware_samples"))[:MAX_SAMPLES], start=1):
            digest = base.hex_digest(entry.get("sha256_hash"), "sha256")
            if digest:
                out.artifacts.append(
                    Artifact(
                        id=f"art_sample_ref_{index}",
                        type="sample_reference",
                        sha256=digest,
                        description="Sample linked to this IOC by ThreatFox. Not fetched.",
                        produced_by=f"{self.name}@{self.version}",
                    )
                )
                source = source or SourceRef(artifact_id=f"art_sample_ref_{index}", method="feed")
        source = source or SourceRef(method="feed")

        draft = _ioc_finding(ioc, ioc_type, confidence, grade, tags, context, source)
        if draft is None:
            reason = (
                "did not validate for its type"
                if ioc_type in _KNOWN_TYPES
                else "is not a type this adapter maps"
            )
            out.errors.append(base.info(self.name, f"IOC {ioc_type!r} {reason}. Kept as other."))
            draft = DraftFinding(
                type="other",
                subtype=ioc_type or "unknown",
                value=ioc,
                confidence=min(confidence, 0.3),
                confidence_method="feed_claim",
                technique="threatfox_record",
                source=source,
                context=context,
                proposed_grade=grade,
                tags=[*tags, "unmapped_ioc_type"],
            )
        out.findings.append(draft)

        family = base.text(record.get("malware_printable"), 128) or base.text(record.get("malware"), 128)
        if family and family.lower() not in {"unknown", "unknown malware"}:
            out.family = FamilySummary(name=family, confidence=confidence, method="threatfox_malware")
            out.findings.append(
                DraftFinding(
                    type="family_indicator",
                    subtype="malware_family",
                    value=family,
                    confidence=confidence,
                    confidence_method="feed_claim",
                    technique="threatfox_malware",
                    source=source,
                    family_data=_pick(record, ("malware", "malware_alias", "malware_malpedia")),
                    proposed_grade=grade,
                    tags=tags,
                )
            )
        return out

    def fetch(
        self,
        query: str,
        term: str | None,
        options: FetchOptions,
        key: str | None = None,
        opener: net.Opener | None = None,
    ) -> bytes:
        payload = _payload(query, term, options)
        return net.request(
            API_URL,
            allow_hosts=self.hosts,
            method="POST",
            headers={
                "Auth-Key": base.check_key(key, "MAASSPEC_ABUSECH_KEY"),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body=json.dumps(payload).encode("ascii"),
            max_bytes=base.MAX_IMPORT_BYTES,
            opener=opener,
        )


def _ioc_finding(
    ioc: str,
    ioc_type: str,
    confidence: float,
    grade,
    tags: list[str],
    context: dict,
    source: SourceRef,
) -> DraftFinding | None:
    common = {
        "confidence_method": "feed_claim",
        "technique": "threatfox_record",
        "source": source,
        "context": context,
        "proposed_grade": grade,
    }
    if ioc_type == "url":
        host = (urlsplit(ioc).hostname or "").lower()
        selectors = [Selector(kind="url", value=ioc, normalized=host or ioc.lower())]
        if host:
            selectors.append(Selector(kind="domain", value=host, normalized=host))
        return DraftFinding(
            type="c2", subtype="url", value=ioc, normalized=host or ioc.lower(),
            confidence=confidence, selectors=selectors, tags=tags, **common,
        )  # fmt: skip
    if ioc_type == "domain":
        host = ioc.lower().rstrip(".")
        return DraftFinding(
            type="c2", subtype="domain", value=ioc, normalized=host, confidence=confidence,
            selectors=[Selector(kind="domain", value=ioc, normalized=host)], tags=tags, **common,
        )  # fmt: skip
    if ioc_type == "ip:port":
        address, _, port = ioc.rpartition(":")
        try:
            ip = ipaddress.ip_address(address.strip("[]"))
            number = int(port)
        except ValueError:
            return None
        if not 1 <= number <= 65535:
            return None
        private = is_unroutable(str(ip))
        kind = "ipv4" if ip.version == 4 else "ipv6"
        return DraftFinding(
            type="c2", subtype="ip_port", value=ioc, normalized=f"{ip}:{number}",
            confidence=min(confidence, 0.35) if private else confidence,
            selectors=[
                Selector(kind=kind, value=str(ip), normalized=str(ip)),
                Selector(kind=f"{kind}_port", value=ioc, normalized=f"{ip}:{number}"),
            ],
            tags=[*tags, "scope:private"] if private else tags,
            **(common | {"proposed_grade": _PRIVATE_GRADE} if private else common),
        )  # fmt: skip
    kind = _HASH_TYPES.get(ioc_type)
    if kind is not None:
        digest = base.hex_digest(ioc, kind)
        if digest is None:
            return None
        return DraftFinding(
            type="embedded_artifact", subtype="sample_hash", value=digest, normalized=digest,
            confidence=confidence, selectors=[Selector(kind=kind, value=digest, normalized=digest)],
            tags=tags, **common,
        )  # fmt: skip
    return None


def _payload(query: str, term: str | None, options: FetchOptions) -> dict:
    if query == "recent":
        days = options.days if options.days is not None else 1
        if not 1 <= days <= 7:
            raise ValueError("--days must be between 1 and 7.")
        return {"query": "get_iocs", "days": days}
    if query == "hash":
        cleaned = (term or "").lower()
        if not (base.hex_digest(cleaned, "md5") or base.hex_digest(cleaned, "sha256")):
            raise ValueError("An MD5 or SHA-256 hash is required.")
        return {"query": "search_hash", "hash": cleaned}
    if query == "malware":
        return {
            "query": "malwareinfo",
            "malware": base.check_term(term, "malware family"),
            "limit": base.check_limit(options.limit),
        }
    if query == "search":
        if not term or len(term) > 256 or not term.isprintable():
            raise ValueError("A search term of 1 to 256 printable characters is required.")
        return {"query": "search_ioc", "search_term": term, "exact_match": bool(options.exact)}
    raise ValueError(f"Unknown ThreatFox query {query!r}.")


def _normalize(row: dict) -> dict:
    record = dict(row)
    for old, new in _ALIASES.items():
        if old in record and new not in record:
            record[new] = record.pop(old)
    tags = record.get("tags")
    if isinstance(tags, str):
        record["tags"] = [item.strip() for item in tags.split(",") if item.strip()]
    return record


def _level(value: object) -> int | None:
    try:
        level = int(str(value))
    except (TypeError, ValueError):
        return None
    return level if 0 <= level <= 100 else None


def _context(record: dict, level: int | None) -> dict:
    context = _pick(record, ("first_seen", "last_seen", "reference", "reporter", "comment"))
    if level is not None:
        context["confidence_level"] = level
    return context


def _pick(source: dict, keys: tuple[str, ...]) -> dict:
    picked = {}
    for key in keys:
        cleaned = base.text(source.get(key), 512)
        if cleaned is not None:
            picked[key] = cleaned
    return picked


def _dicts(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
