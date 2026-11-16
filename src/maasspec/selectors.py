"""Pull a small set of selector kinds out of strings. Not a string dump."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from maasspec.models import DraftFinding, ProposedGrade, Selector

_URL = re.compile(r"https?://[^\s'\"<>]{4,200}", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_BTC = re.compile(r"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,87}\b")

MAX_SELECTOR_FINDINGS = 200


def _grade_static(private: bool = False) -> ProposedGrade:
    if private:
        return ProposedGrade(
            source_reliability="C",
            information_credibility="4",
            rationale="Private or loopback address found by a static scan. Not a routable C2 candidate.",
        )
    return ProposedGrade(
        source_reliability="C",
        information_credibility="2",
        rationale="Extracted from the sample by a static scan. Not dynamically confirmed.",
    )


def selector_findings(strings: list[str]) -> tuple[list[DraftFinding], bool]:
    drafts: list[DraftFinding] = []
    seen: set[tuple[str, str]] = set()
    truncated = False

    def add(kind: str, value: str, confidence: float, tags: list[str]) -> None:
        nonlocal truncated
        key = (kind, value.lower())
        if key in seen:
            return
        if len(drafts) >= MAX_SELECTOR_FINDINGS:
            truncated = True
            return
        seen.add(key)
        drafts.append(
            DraftFinding(
                type=_type_for(kind),
                subtype=kind,
                value=value,
                normalized=_normalize(kind, value),
                confidence=confidence,
                confidence_method="static_selector_scan",
                technique="selector_scan",
                selectors=[Selector(kind=kind, value=value, normalized=_normalize(kind, value))],
                proposed_grade=_grade_static(private="scope:private" in tags),
                tags=tags,
            )
        )

    blob_limit = 8000
    for text in strings:
        if len(drafts) >= MAX_SELECTOR_FINDINGS:
            truncated = True
            break
        window = text[:blob_limit]
        for match in _URL.finditer(window):
            add("url", match.group(0).rstrip(").,;"), 0.72, ["static"])
        for match in _EMAIL.finditer(window):
            add("email", match.group(0), 0.7, ["static"])
        for match in _BTC.finditer(window):
            add("bitcoin", match.group(0), 0.66, ["static", "wallet"])
        for match in _IPV4.finditer(window):
            raw = match.group(0)
            private = _is_private(raw)
            add(
                "ipv4",
                raw,
                0.35 if private else 0.55,
                ["static", "scope:private"] if private else ["static"],
            )
    return drafts, truncated


def _type_for(kind: str) -> str:
    if kind in {"url", "domain", "ipv4"}:
        return "c2"
    if kind == "bitcoin":
        return "wallet"
    if kind == "email":
        return "credential_pattern"
    return "other"


def _normalize(kind: str, value: str) -> str:
    if kind == "url":
        try:
            host = urlsplit(value).hostname
        except ValueError:
            host = None
        return host.rstrip(".") if host else value.lower()
    if kind == "email":
        return value.lower()
    return value


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_unroutable(raw: str) -> bool:
    """True for any address that is not a public unicast one.

    Spelled out rather than left to `is_global` alone: the standard library has moved
    the edges of that property between releases, and a grade must not move with it.
    """
    try:
        ip = ipaddress.ip_address(raw.strip().strip("[]"))
    except ValueError:
        return False
    return (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or (ip.version == 4 and ip in _CGNAT)
    )


def _is_private(raw: str) -> bool:
    return is_unroutable(raw)
