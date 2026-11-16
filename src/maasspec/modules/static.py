"""Generic static pass: magic, entropy, selectors, zip member names."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from maasspec.context import AnalysisContext
from maasspec.models import AnalysisError, Artifact, DraftFinding, SourceRef
from maasspec.modules.base import Module, ModuleOutput
from maasspec.scan import shannon_entropy
from maasspec.selectors import selector_findings

MAX_ZIP_MEMBERS = 200
_DRIVE = re.compile(r"[A-Za-z]:")
MAX_ZIP_UNCOMPRESSED = 64 * 1024 * 1024


class StaticModule(Module):
    name = "static"
    version = "0.1.0"

    def accepts(self, ctx: AnalysisContext) -> bool:
        return ctx.input_type != "cape_report"

    def run(self, ctx: AnalysisContext) -> ModuleOutput:
        out = ModuleOutput()
        out.findings.append(_magic(ctx))
        entropy = shannon_entropy(ctx.data_for_scan)
        if len(ctx.data_for_scan) >= 256 and entropy >= 7.2:
            out.findings.append(
                DraftFinding(
                    type="other",
                    subtype="entropy",
                    value=round(entropy, 3),
                    confidence=0.8,
                    confidence_method="shannon_on_scan_window",
                    technique="entropy",
                    tags=["static", "high_entropy"],
                    context={"note": "High entropy on the scanned window. Often a packer, not proof of one."},
                )
            )
        if ctx.data_for_scan.startswith(b"PK\x03\x04"):
            members, errors = _zip_members(ctx.path)
            out.findings.extend(members)
            out.errors.extend(errors)
        drafts, truncated = selector_findings(ctx.strings)
        out.findings.extend(drafts)
        if truncated:
            out.errors.append(
                AnalysisError(
                    severity="warning",
                    module=self.name,
                    message="Selector scan hit its cap. Later strings were not emitted.",
                    recoverable=True,
                )
            )
        if ctx.truncated:
            out.errors.append(
                AnalysisError(
                    severity="warning",
                    module=self.name,
                    message="File exceeded the scan window. Hash covers the whole file; inspection does not.",
                    recoverable=True,
                )
            )
        out.artifacts.append(
            Artifact(
                id="art_input",
                type="input",
                sha256=ctx.sha256,
                size_bytes=ctx.size_bytes,
                description="Original input, hashed, not stored in the spectrum.",
                produced_by=f"{self.name}@{self.version}",
            )
        )
        return out


def _magic(ctx: AnalysisContext) -> DraftFinding:
    data = ctx.data_for_scan
    if data.startswith(b"MZ"):
        kind, label = "pe", "PE (MZ)"
    elif data.startswith(b"\x7fELF"):
        kind, label = "elf", "ELF"
    elif data.startswith(b"PK\x03\x04"):
        kind, label = "zip", "ZIP archive"
    elif data[:4] in {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}:
        kind, label = "macho", "Mach-O"
    else:
        kind, label = "unknown", "unrecognized"
    return DraftFinding(
        type="other",
        subtype="file_magic",
        value=label,
        normalized=kind,
        confidence=0.95 if kind != "unknown" else 0.4,
        confidence_method="magic_bytes",
        technique="magic",
        source=SourceRef(method="static", offset="0x0"),
        tags=["static"],
    )


def _unsafe_member_name(name: str) -> bool:
    """Rooted, drive-lettered, UNC and parent-relative names are skipped."""
    normal = name.replace("\\", "/")
    return normal.startswith("/") or _DRIVE.match(normal) is not None or ".." in normal.split("/")


def _zip_members(path: Path) -> tuple[list[DraftFinding], list[AnalysisError]]:
    findings: list[DraftFinding] = []
    errors: list[AnalysisError] = []
    try:
        archive = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        errors.append(
            AnalysisError(
                severity="warning",
                module="static",
                message="ZIP magic present but the archive did not parse. Members were not listed.",
                recoverable=True,
            )
        )
        return findings, errors

    infos = archive.infolist()
    archive.close()
    total_uncompressed = sum(info.file_size for info in infos)
    if len(infos) > MAX_ZIP_MEMBERS or total_uncompressed > MAX_ZIP_UNCOMPRESSED:
        errors.append(
            AnalysisError(
                severity="error",
                module="static",
                message="Archive refused: too many members or declared uncompressed size is too large.",
                recoverable=False,
            )
        )
        return findings, errors

    for info in infos[:50]:
        name = info.filename
        if _unsafe_member_name(name):
            errors.append(
                AnalysisError(
                    severity="warning",
                    module="static",
                    message=f"Skipped archive member with an unsafe name: {name!r}",
                    recoverable=True,
                )
            )
            continue
        findings.append(
            DraftFinding(
                type="embedded_artifact",
                subtype="archive_member",
                value=name,
                confidence=0.9,
                confidence_method="zip_central_directory",
                technique="archive_list",
                tags=["static", "archive"],
                context={
                    "compressed_size": info.compress_size,
                    "file_size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                    "note": "Name only. Contents were not extracted or executed.",
                },
            )
        )
    if len(infos) > 50:
        errors.append(
            AnalysisError(
                severity="info",
                module="static",
                message=f"Listed 50 of {len(infos)} archive members.",
                recoverable=True,
            )
        )
    return findings, errors

