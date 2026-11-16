"""CAPE parser output: the `configs` and `payloads` lists in a CAPE report.

CAPE runs its configuration parsers on payloads it dumps during detonation and keeps each result as
`{family: {fields}}` in `CAPE.configs`, with `_associated_config_hashes` linking it to the payload it came
from. Field names are each parser's own, so this reads them generically: fields named like a C2, a key or
an identifier become findings, and every other string goes through the same selector scan as a local sample.
These rows come from a sandbox run, not from MaaSSpec, so they are tagged `sandbox` and `cape` and capped
at 0.6.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from itertools import islice
from typing import Any
from urllib.parse import urlsplit

from maasspec.models import (
    Artifact,
    DraftFinding,
    FamilySummary,
    ProposedGrade,
    Selector,
    SourceRef,
)
from maasspec.modules.base import ModuleOutput
from maasspec.selectors import selector_findings

MAX_CONFIGS = 20
MAX_PAIRS = 200
MAX_CONTEXT = 30
MAX_PAYLOADS = 50
MAX_DEPTH = 4
MAX_LIST = 50
MAX_TEXT = 2048
CONFIG_CONFIDENCE = 0.6
TAGS = ["sandbox", "cape", "cape_config"]
_C2_FIELD = re.compile(r"c2|cnc|c&c|server|host|domain|address|url|gate|panel|relay|proxy|\bip\b", re.IGNORECASE)
_KEY_FIELD = re.compile(r"key|passw|secret|token|rc4|aes|xor|salt|\biv\b|cipher", re.IGNORECASE)
_ID_FIELD = re.compile(r"campaign|botnet|mutex|affid|affiliate|group|build|version", re.IGNORECASE)
_SELECTOR_ID = re.compile(r"campaign|botnet|mutex", re.IGNORECASE)
_DOMAIN = re.compile(
    r"(?=.{1,253}$)(?P<host>[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24})(?::(?P<port>\d{1,5}))?"
)
_HEX = {kind: re.compile(f"[A-Fa-f0-9]{{{size}}}") for kind, size in {"md5": 32, "sha1": 40, "sha256": 64}.items()}
_PARSER_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="2",
    rationale="Decoded from a payload by a CAPE configuration parser. MaaSSpec has not confirmed it.",
)
_PRIVATE_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="4",
    rationale="Private or loopback address in a CAPE config. A C2 claim for it is doubtful.",
)
_PAYLOAD_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="3",
    rationale="Payload hash taken from a sandbox report. MaaSSpec has not seen the payload.",
)


def normalize_cape_section(document: dict, producer: str) -> ModuleOutput:
    out = ModuleOutput()
    section = document.get("CAPE")
    if not isinstance(section, dict):
        return out
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(_dicts(section.get("configs"))[:MAX_CONFIGS], start=1):
        _config(out, entry, index, seen, producer)
    for index, payload in enumerate(_dicts(section.get("payloads"))[:MAX_PAYLOADS], start=1):
        _payload(out, payload, index, producer)
    return out


def _config(out: ModuleOutput, entry: dict, index: int, seen: set[tuple[str, str]], producer: str) -> None:
    linked = _hashes(entry.get("_associated_config_hashes"))
    for key, fields in entry.items():
        if str(key).startswith("_") or not isinstance(fields, dict):
            continue
        family = _text(key, 128)
        hashes = linked or _hashes(fields.get("_associated_config_hashes"))
        artifact_id = None
        if hashes.get("sha256"):
            artifact_id = f"art_cape_config_{index}"
            out.artifacts.append(
                Artifact(
                    id=artifact_id,
                    type="sandbox_payload",
                    sha256=hashes["sha256"],
                    description="Payload CAPE parsed for this config. Not fetched.",
                    produced_by=producer,
                )
            )
        source = SourceRef(artifact_id=artifact_id, method="cape_config", section=family)
        pairs = list(islice(_flatten(fields, "", family), MAX_PAIRS))
        out.findings.append(
            DraftFinding(
                type="config",
                subtype="cape_parser_config",
                value=family,
                confidence=CONFIG_CONFIDENCE,
                confidence_method="cape_parser",
                technique="cape_config_parser",
                source=source,
                context={name: value for name, _, value in pairs[:MAX_CONTEXT]},
                selectors=_hash_selectors(hashes),
                proposed_grade=_PARSER_GRADE,
                tags=TAGS,
                family_data={"cape_name": family},
            )
        )
        candidate = FamilySummary(name=family, confidence=CONFIG_CONFIDENCE, method="cape_parser")
        if out.family is None or candidate.confidence > out.family.confidence:
            out.family = candidate
        for name, path, value in pairs:
            where = SourceRef(artifact_id=artifact_id, method="cape_config", section=path)
            found = _classify(name, value, where)
            if found is not None:
                if (found.subtype or "", str(found.value).lower()) not in seen:
                    seen.add((found.subtype or "", str(found.value).lower()))
                    out.findings.append(found)
                continue
            for draft in selector_findings([value])[0]:
                key_seen = (draft.subtype or "", str(draft.value).lower())
                if key_seen in seen:
                    continue
                seen.add(key_seen)
                private = "scope:private" in draft.tags
                draft.source = where
                draft.confidence = min(draft.confidence, CONFIG_CONFIDENCE)
                draft.tags = [*TAGS, "scope:private"] if private else list(TAGS)
                draft.proposed_grade = _PRIVATE_GRADE if private else _PARSER_GRADE
                out.findings.append(draft)


def _classify(name: str, value: str, source: SourceRef) -> DraftFinding | None:
    if _C2_FIELD.search(name):
        c2 = _c2(value, source)
        if c2 is not None:
            return c2
    if _KEY_FIELD.search(name):
        return DraftFinding(
            type="crypto_material",
            subtype=name.lower()[:64],
            value=value[:256],
            confidence=CONFIG_CONFIDENCE,
            confidence_method="cape_parser",
            technique="cape_config_parser",
            source=source,
            proposed_grade=_PARSER_GRADE,
            tags=TAGS,
        )
    if _ID_FIELD.search(name):
        selectors = [Selector(kind=name.lower()[:32], value=value, normalized=value.lower())] if _SELECTOR_ID.search(name) else []
        return DraftFinding(
            type="config",
            subtype=name.lower()[:64],
            value=value[:256],
            confidence=CONFIG_CONFIDENCE,
            confidence_method="cape_parser",
            technique="cape_config_parser",
            source=source,
            selectors=selectors,
            proposed_grade=_PARSER_GRADE,
            tags=TAGS,
        )
    return None


def _c2(raw: str, source: SourceRef) -> DraftFinding | None:
    value = raw.strip()
    if not value or " " in value or len(value) > 512:
        return None
    common = {
        "type": "c2",
        "confidence_method": "cape_parser",
        "technique": "cape_config_parser",
        "source": source,
    }
    if re.match(r"https?://", value, re.IGNORECASE):
        host = (urlsplit(value).hostname or "").lower()
        selectors = [Selector(kind="url", value=value, normalized=host or value.lower())]
        if host:
            selectors.append(Selector(kind="domain", value=host, normalized=host))
        return DraftFinding(
            subtype="url", value=value, normalized=host or value.lower(), confidence=CONFIG_CONFIDENCE,
            selectors=selectors, proposed_grade=_PARSER_GRADE, tags=TAGS, **common,
        )  # fmt: skip
    parsed = _ip_port(value)
    if parsed is not None:
        ip, port = parsed
        private = ip.is_private or ip.is_loopback
        kind = "ipv4" if ip.version == 4 else "ipv6"
        selectors = [Selector(kind=kind, value=str(ip), normalized=str(ip))]
        if port is not None:
            selectors.append(Selector(kind=f"{kind}_port", value=value, normalized=f"{ip}:{port}"))
        return DraftFinding(
            subtype="ip_port" if port is not None else kind, value=value,
            normalized=f"{ip}:{port}" if port is not None else str(ip),
            confidence=0.35 if private else CONFIG_CONFIDENCE, selectors=selectors,
            proposed_grade=_PRIVATE_GRADE if private else _PARSER_GRADE,
            tags=[*TAGS, "scope:private"] if private else TAGS, **common,
        )  # fmt: skip
    match = _DOMAIN.fullmatch(value)
    if match is not None and (match["port"] is None or 1 <= int(match["port"]) <= 65535):
        host = match["host"].lower()
        selectors = [Selector(kind="domain", value=host, normalized=host)]
        if match["port"] is not None:
            selectors.append(Selector(kind="domain_port", value=value, normalized=f"{host}:{match['port']}"))
        return DraftFinding(
            subtype="domain", value=value, normalized=host, confidence=CONFIG_CONFIDENCE,
            selectors=selectors, proposed_grade=_PARSER_GRADE, tags=TAGS, **common,
        )  # fmt: skip
    return None


def _ip_port(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int | None] | None:
    try:
        return ipaddress.ip_address(value.strip("[]")), None
    except ValueError:
        pass
    if value.count(":") != 1 and not value.startswith("["):
        return None
    host, _, port = value.rpartition(":")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    try:
        return ipaddress.ip_address(host.strip("[]")), int(port)
    except ValueError:
        return None


def _payload(out: ModuleOutput, payload: dict, index: int, producer: str) -> None:
    hashes = _hashes(payload)
    if not hashes.get("sha256"):
        return
    kind = _text(payload.get("cape_type") or payload.get("type"), 128)
    artifact_id = f"art_cape_payload_{index}"
    out.artifacts.append(
        Artifact(
            id=artifact_id,
            type="sandbox_payload",
            sha256=hashes["sha256"],
            description=f"CAPE payload{': ' + kind if kind else ''}. Not fetched.",
            produced_by=producer,
        )
    )
    out.findings.append(
        DraftFinding(
            type="embedded_artifact",
            subtype="cape_payload",
            value=hashes["sha256"],
            normalized=hashes["sha256"],
            confidence=0.5,
            confidence_method="cape_report",
            technique="cape_payloads",
            source=SourceRef(artifact_id=artifact_id, method="cape_payloads"),
            context={"cape_type": kind} if kind else None,
            selectors=_hash_selectors(hashes),
            proposed_grade=_PAYLOAD_GRADE,
            tags=["sandbox", "cape"],
        )
    )


def _flatten(value: Any, name: str = "", path: str = "", depth: int = 0) -> Iterator[tuple[str, str, str]]:
    if isinstance(value, dict):
        if depth >= MAX_DEPTH:
            return
        for key, item in value.items():
            if str(key).startswith("_"):
                continue
            label = _text(key, 64)
            yield from _flatten(item, label, f"{path}.{label}" if path else label, depth + 1)
    elif isinstance(value, list):
        for position, item in enumerate(value[:MAX_LIST]):
            yield from _flatten(item, name, f"{path}[{position}]", depth + 1)
    elif isinstance(value, bool):
        yield name, path, "true" if value else "false"
    elif isinstance(value, (str, int, float)):
        text = _text(value, MAX_TEXT)
        if text:
            yield name, path, text


def _hashes(value: Any) -> dict[str, str]:
    candidates = value if isinstance(value, list) else [value]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        found = {}
        for kind, pattern in _HEX.items():
            raw = item.get(kind)
            if isinstance(raw, str) and pattern.fullmatch(raw):
                found[kind] = raw.lower()
        if found.get("sha256"):
            return found
    return {}


def _hash_selectors(hashes: dict[str, str]) -> list[Selector]:
    return [Selector(kind=kind, value=value, normalized=value) for kind, value in hashes.items()]


def _text(value: Any, limit: int) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return "".join(ch for ch in str(value) if ch.isprintable())[:limit].strip()


def _dicts(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
