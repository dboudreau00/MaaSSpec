"""Normalize a small, documented slice of a CAPE report. Behavior is not proof."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from maasspec.context import AnalysisContext
from maasspec.models import (
    AnalysisError,
    DraftFinding,
    FamilySummary,
    ProposedGrade,
    Selector,
)
from maasspec.modules.base import Module, ModuleOutput
from maasspec.modules.cape_configs import normalize_cape_section
from maasspec.selectors import is_unroutable

_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="3",
    rationale="Taken from a sandbox report. Not statically confirmed.",
)
_PRIVATE_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="4",
    rationale="Non-public address in a sandbox report, often the sandbox itself. A C2 claim for it is doubtful.",
)
MAX_NETWORK_PER_KIND = 200


class CapeModule(Module):
    name = "cape"
    version = "0.1.0"

    def accepts(self, ctx: AnalysisContext) -> bool:
        return ctx.input_type == "cape_report"

    def run(self, ctx: AnalysisContext) -> ModuleOutput:
        out = ModuleOutput()
        document = ctx.parsed_json
        if not isinstance(document, dict):
            out.errors.append(
                AnalysisError(
                    severity="error",
                    module=self.name,
                    message="CAPE input was not a JSON object.",
                    recoverable=False,
                )
            )
            return out

        network = document.get("network") if isinstance(document.get("network"), dict) else {}
        seen: set[tuple[str, str]] = set()
        capped: set[str] = set()

        def add(kind: str, value: object, technique: str) -> None:
            if not isinstance(value, str) or not value:
                return
            if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
                # A sandbox report is hostile input: a value with a control character (a NUL, say) is not a host.
                return
            key = (kind, value.lower())
            if key in seen:
                return
            if sum(1 for seen_kind, _ in seen if seen_kind == kind) >= MAX_NETWORK_PER_KIND:
                capped.add(kind)
                return
            seen.add(key)
            out.findings.append(_net(kind, value, technique))

        for host in _as_dicts(network.get("hosts")):
            add("ipv4", host.get("ip"), "cape_host")
            add("domain", host.get("hostname") or host.get("domain"), "cape_host")
        for flow in _as_dicts(network.get("http")) + _as_dicts(network.get("https")):
            add("url", flow.get("uri") or flow.get("url"), "cape_http")
        for row in _as_dicts(network.get("dns")):
            add("domain", row.get("request") or row.get("hostname"), "cape_dns")
        if capped:
            out.errors.append(
                AnalysisError(
                    severity="warning",
                    module=self.name,
                    message=f"CAPE network rows hit the cap of {MAX_NETWORK_PER_KIND} per kind ({', '.join(sorted(capped))}). Later rows were not emitted.",
                    recoverable=True,
                )
            )
        for signature in _as_dicts(document.get("signatures"))[:40]:
            name = signature.get("name") or signature.get("description")
            if isinstance(name, str) and name:
                out.findings.append(
                    DraftFinding(
                        type="behavior",
                        subtype="cape_signature",
                        value=name,
                        confidence=0.4,
                        confidence_method="cape_signature_name",
                        technique="cape_behavior",
                        proposed_grade=_GRADE,
                        tags=["sandbox", "cape"],
                    )
                )

        parsed = normalize_cape_section(document, f"{self.name}@{self.version}")
        out.findings.extend(parsed.findings)
        out.artifacts.extend(parsed.artifacts)
        out.errors.extend(parsed.errors)
        family = document.get("malfamily")
        if isinstance(family, str) and family.strip():
            out.family = FamilySummary(name=family.strip(), confidence=0.5, method="cape_malfamily")
        if parsed.family is not None and (out.family is None or parsed.family.confidence > out.family.confidence):
            out.family = parsed.family
        if not out.findings:
            out.errors.append(
                AnalysisError(
                    severity="info",
                    module=self.name,
                    message="CAPE report had none of the fields this normalizer understands (network.hosts, network.http, network.dns, signatures, CAPE.configs, CAPE.payloads).",
                    recoverable=True,
                )
            )
        return out


def parse_cape(data: bytes) -> dict | None:
    try:
        text = data.decode("utf-8")
        parsed = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) and _is_cape_shaped(parsed) else None


def _is_cape_shaped(document: dict) -> bool:
    """A key alone is not enough: `behavior` and `network` are common names. Each section needs CAPE's own shape."""
    network = document.get("network")
    if isinstance(network, dict) and any(
        isinstance(network.get(key), list) for key in ("hosts", "http", "https", "dns", "tcp", "udp", "domains")
    ):
        return True
    signatures = document.get("signatures")
    if isinstance(signatures, list) and any(
        isinstance(item, dict) and isinstance(item.get("name") or item.get("description"), str)
        for item in signatures
    ):
        return True
    behavior = document.get("behavior")
    if isinstance(behavior, dict) and (
        isinstance(behavior.get("processes"), list)
        or isinstance(behavior.get("summary"), dict)
        or isinstance(behavior.get("processtree"), list)
    ):
        return True
    section = document.get("CAPE")
    return isinstance(section, dict) and (
        isinstance(section.get("configs"), list) or isinstance(section.get("payloads"), list)
    )


def _as_dicts(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _net(kind: str, value: str, technique: str) -> DraftFinding:
    finding_type = "c2" if kind in {"url", "domain", "ipv4"} else "other"
    private = (kind == "ipv4" and is_unroutable(value)) or (
        kind == "url" and is_unroutable(_url_host(value))
    )
    return DraftFinding(
        type=finding_type,
        subtype=kind,
        value=value,
        normalized=value.lower(),
        confidence=0.35 if private else 0.45,
        confidence_method="cape_report",
        technique=technique,
        selectors=[Selector(kind=kind, value=value, normalized=value.lower())],
        proposed_grade=_PRIVATE_GRADE if private else _GRADE,
        tags=["sandbox", "cape", "scope:private"] if private else ["sandbox", "cape"],
    )


def _url_host(value: str) -> str:
    try:
        return urlsplit(value).hostname or ""
    except ValueError:
        return ""
