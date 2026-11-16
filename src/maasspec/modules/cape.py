"""Normalize a small, documented slice of a CAPE report. Behavior is not proof."""

from __future__ import annotations

import json

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

_GRADE = ProposedGrade(
    source_reliability="C",
    information_credibility="3",
    rationale="Taken from a sandbox report. Not statically confirmed.",
)


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
        for host in _as_dicts(network.get("hosts")):
            ip = host.get("ip")
            hostname = host.get("hostname") or host.get("domain")
            if isinstance(ip, str) and ip:
                out.findings.append(_net("ipv4", ip, "cape_host"))
            if isinstance(hostname, str) and hostname:
                out.findings.append(_net("domain", hostname, "cape_host"))
        for flow in _as_dicts(network.get("http")) + _as_dicts(network.get("https")):
            uri = flow.get("uri") or flow.get("url")
            if isinstance(uri, str) and uri:
                out.findings.append(_net("url", uri, "cape_http"))
        for row in _as_dicts(network.get("dns")):
            request = row.get("request") or row.get("hostname")
            if isinstance(request, str) and request:
                out.findings.append(_net("domain", request, "cape_dns"))
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
    if isinstance(parsed, dict) and (
        "network" in parsed or "signatures" in parsed or "behavior" in parsed or "CAPE" in parsed
    ):
        return parsed
    return None


def _as_dicts(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _net(kind: str, value: str, technique: str) -> DraftFinding:
    finding_type = "c2" if kind in {"url", "domain", "ipv4"} else "other"
    return DraftFinding(
        type=finding_type,
        subtype=kind,
        value=value,
        normalized=value.lower(),
        confidence=0.45,
        confidence_method="cape_report",
        technique=technique,
        selectors=[Selector(kind=kind, value=value, normalized=value.lower())],
        proposed_grade=_GRADE,
        tags=["sandbox", "cape"],
    )
