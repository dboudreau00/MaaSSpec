"""Run the default module set and assemble one spectrum."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from maasspec import __version__
from maasspec.context import AnalysisContext
from maasspec.feeds.base import FeedAdapter
from maasspec.models import (
    AnalysisError,
    Artifact,
    DraftFinding,
    ExtractedBy,
    FamilySummary,
    Finding,
    InputInfo,
    Spectrum,
    Summary,
    ToolInfo,
)
from maasspec.modules.base import Module, ModuleOutput
from maasspec.modules.cape import CapeModule, parse_cape
from maasspec.modules.example_family import ExampleFamilyModule
from maasspec.modules.static import StaticModule
from maasspec.scan import extract_segment_strings, hash_file, read_scan_segments

MAX_REPORT_BYTES = 128 * 1024 * 1024
FEED_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def default_modules() -> list[Module]:
    return [StaticModule(), CapeModule(), ExampleFamilyModule()]


def analyze_path(
    path: Path,
    *,
    analysis_id: UUID | None = None,
    now: datetime | None = None,
    modules: list[Module] | None = None,
) -> Spectrum:
    if not path.is_file():
        raise FileNotFoundError(path)
    sha256, size = hash_file(path)
    segments, truncated = read_scan_segments(path, size)
    window = b"".join(segments)
    cape = _read_report(path, size, window, truncated)
    if cape is not None:
        truncated = False
        input_type = "cape_report"
    elif window.startswith(b"PK\x03\x04"):
        input_type = "archive"
    else:
        input_type = "sample"
    strings, strings_truncated = extract_segment_strings(segments)
    ctx = AnalysisContext(
        path=path,
        filename=path.name,
        data_for_scan=window,
        sha256=sha256,
        size_bytes=size,
        input_type=input_type,
        truncated=truncated,
        strings=strings,
        parsed_json=cape,
    )
    stamp = now or datetime.now(UTC)
    chosen = modules if modules is not None else default_modules()
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    errors: list[AnalysisError] = []
    family: FamilySummary | None = None
    if strings_truncated:
        errors.append(
            AnalysisError(
                severity="warning",
                module="scan",
                message="String extraction hit its cap.",
                recoverable=True,
            )
        )
    if truncated and size > MAX_REPORT_BYTES and window.lstrip()[:1] == b"{":
        errors.append(
            AnalysisError(
                severity="warning",
                module="engine",
                message=f"JSON larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB was analyzed as a raw file, not as a CAPE report.",
                recoverable=True,
            )
        )
    if size == 0:
        errors.append(
            AnalysisError(
                severity="warning",
                module="engine",
                message="Input file is empty.",
                recoverable=True,
            )
        )

    sequence = 0
    for module in chosen:
        if not module.accepts(ctx):
            continue
        result = _run_guarded(module.name, lambda module=module: module.run(ctx))
        family = _better_family(family, result.family)
        for draft in result.findings:
            sequence += 1
            findings.append(_seal(draft, module.name, module.version, sequence, stamp))
        artifacts.extend(result.artifacts)
        errors.extend(result.errors)

    return Spectrum(
        analysis_id=analysis_id or uuid4(),
        generated_at=stamp,
        tool=ToolInfo(name="MaaSSpec", version=__version__),
        input=InputInfo(
            type=input_type,  # type: ignore[arg-type]
            filename=path.name,
            sha256=sha256,
            size_bytes=size,
            source_hint="local file",
        ),
        summary=_summarize(findings, family),
        findings=findings,
        artifacts=artifacts,
        errors=errors,
        metadata={"scan_window_truncated": truncated, "strings_truncated": strings_truncated},
    )


def _read_report(path: Path, size: int, window: bytes, truncated: bool) -> dict | None:
    """A CAPE report is usually larger than the scan window, so a JSON object is read whole up to a cap."""
    if not truncated:
        return parse_cape(window)
    if size > MAX_REPORT_BYTES or window.lstrip()[:1] != b"{":
        return None
    return parse_cape(path.read_bytes())


def canonical_record_bytes(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def spectrum_from_feed_record(
    adapter: FeedAdapter,
    record: dict,
) -> Spectrum:
    """One spectrum per feed record. The input is the record, not the sample.

    `input.sha256` covers the canonical JSON of the record, so it can be
    re-derived from the export. The sample the feed describes is a
    `sample_reference` artifact and a `sample_hash` finding: a claim, not a
    fetched file. The analysis id is derived from feed, adapter version, and
    record hash, so importing the same export twice sends the same
    Idempotency-Key.

    The document is byte-stable too: `generated_at` and every finding's
    `first_seen_in_analysis` are the record's own sighting time, or the fixed
    epoch when the record carries none. They are not wall-clock.
    """
    stamp = adapter.sighting_time(record) or FEED_EPOCH
    canonical = canonical_record_bytes(record)
    record_sha = hashlib.sha256(canonical).hexdigest()
    result = _run_guarded(adapter.name, lambda: adapter.run(record))
    findings = [
        _seal(draft, adapter.name, adapter.version, index, stamp)
        for index, draft in enumerate(result.findings, start=1)
    ]
    artifacts = [
        Artifact(
            id="art_record",
            type="feed_record",
            sha256=record_sha,
            size_bytes=len(canonical),
            description=f"{adapter.feed} record as received, canonical JSON, not stored here.",
            produced_by=f"{adapter.name}@{adapter.version}",
        ),
        *result.artifacts,
    ]
    return Spectrum(
        analysis_id=uuid5(NAMESPACE_URL, f"maasspec:{adapter.feed}:{adapter.version}:{record_sha}"),
        generated_at=stamp,
        tool=ToolInfo(name="MaaSSpec", version=__version__),
        input=InputInfo(
            type="feed_record",
            sha256=record_sha,
            size_bytes=len(canonical),
            source_hint=adapter.feed,
        ),
        summary=_summarize(findings, result.family),
        findings=findings,
        artifacts=artifacts,
        errors=result.errors,
        metadata={
            "feed": adapter.feed,
            "feed_record_id": adapter.record_id(record),
            "claimed_sample_sha256": adapter.sample_sha256(record),
            "claims_not_verified": True,
        },
    )


def spectra_from_feed(
    adapter: FeedAdapter,
    data: bytes,
    *,
    limit: int = 1000,
) -> Iterator[Spectrum]:
    for count, record in enumerate(adapter.records(data)):
        if count >= limit:
            return
        yield spectrum_from_feed_record(adapter, record)


def _run_guarded(name: str, call) -> ModuleOutput:
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - a module must never take the spectrum down with it
        return ModuleOutput(
            errors=[
                AnalysisError(
                    severity="error",
                    module=name,
                    message=f"Module failed with {type(exc).__name__}. Its findings are absent.",
                    recoverable=True,
                )
            ]
        )


def _better_family(
    current: FamilySummary | None, candidate: FamilySummary | None
) -> FamilySummary | None:
    if candidate is None:
        return current
    if current is None or candidate.confidence > current.confidence:
        return candidate
    return current


def _summarize(findings: list[Finding], family: FamilySummary | None) -> Summary:
    capabilities = sorted(
        {
            tag.removeprefix("capability:")
            for finding in findings
            for tag in finding.tags
            if tag.startswith("capability:")
        }
    )
    return Summary(
        family=family,
        primary_capabilities=capabilities,
        c2_count=sum(1 for finding in findings if finding.type == "c2"),
        config_extracted=any(finding.type == "config" for finding in findings),
        encryption_observed=any("encrypted_config" in finding.tags for finding in findings),
        risk_signals=sorted(
            {tag for finding in findings for tag in finding.tags if tag.startswith("risk:")}
        ),
    )


def _seal(
    draft: DraftFinding,
    module: str,
    version: str,
    sequence: int,
    stamp: datetime,
) -> Finding:
    return Finding(
        id=f"fnd_{sequence:04d}",
        type=draft.type,
        subtype=draft.subtype,
        value=draft.value,
        normalized=draft.normalized,
        confidence=draft.confidence,
        confidence_method=draft.confidence_method,
        extracted_by=ExtractedBy(module=module, version=version, technique=draft.technique),
        source=draft.source,
        context=draft.context,
        selectors=draft.selectors,
        proposed_grade=draft.proposed_grade,
        tags=draft.tags,
        first_seen_in_analysis=stamp,
        family_data=draft.family_data,
    )
