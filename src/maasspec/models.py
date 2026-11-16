"""Spectrum document. The JSON Schema in schema/ is generated from these models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "0.1.0"
SCHEMA_ID = "maasspec/spectrum.schema.json"

FindingType = Literal[
    "c2",
    "config",
    "credential_pattern",
    "crypto_material",
    "embedded_artifact",
    "family_indicator",
    "behavior",
    "wallet",
    "panel",
    "other",
]
InputType = Literal[
    "sample", "cape_report", "memory_dump", "config_dump", "archive", "feed_record"
]
SourceReliability = Literal["A", "B", "C", "D", "E", "F"]
InformationCredibility = Literal["1", "2", "3", "4", "5", "6"]


def _without_nul(value: Any) -> Any:
    """A NUL character is replaced by U+FFFD in a string, in a dict key and in nested lists and dicts. A report
    is hostile input, and NocTORnal's store cannot hold a NUL, so it refuses a spectrum that carries one."""
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, dict):
        return {(_without_nul(k) if isinstance(k, str) else k): _without_nul(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_without_nul(v) for v in value]
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def _no_nul(cls, value: Any) -> Any:
        return _without_nul(value)


class ToolInfo(_Strict):
    name: str
    version: str
    commit: str | None = None


class InputInfo(_Strict):
    type: InputType
    filename: str | None = None
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    source_hint: str | None = None


class FamilySummary(_Strict):
    name: str
    confidence: float = Field(ge=0, le=1)
    method: str | None = None


class Summary(_Strict):
    family: FamilySummary | None = None
    primary_capabilities: list[str] = Field(default_factory=list)
    c2_count: int = Field(default=0, ge=0)
    config_extracted: bool = False
    encryption_observed: bool = False
    risk_signals: list[str] = Field(default_factory=list)


class ExtractedBy(_Strict):
    module: str
    version: str | None = None
    technique: str | None = None


class SourceRef(_Strict):
    artifact_id: str | None = None
    offset: str | None = None
    section: str | None = None
    method: str | None = None


class Selector(_Strict):
    kind: str
    value: str
    normalized: str | None = None


class ProposedGrade(_Strict):
    source_reliability: SourceReliability | None = None
    information_credibility: InformationCredibility | None = None
    rationale: str | None = None


class Finding(_Strict):
    id: str
    type: FindingType
    subtype: str | None = None
    value: Any = None
    normalized: Any = None
    confidence: float = Field(ge=0, le=1)
    confidence_method: str | None = None
    extracted_by: ExtractedBy
    source: SourceRef | None = None
    context: dict[str, Any] | None = None
    selectors: list[Selector] = Field(default_factory=list)
    proposed_grade: ProposedGrade | None = None
    tags: list[str] = Field(default_factory=list)
    first_seen_in_analysis: datetime | None = None
    family_data: dict[str, Any] | None = None


class Artifact(_Strict):
    id: str
    type: str
    sha256: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    description: str | None = None
    produced_by: str | None = None
    parent_artifact_id: str | None = None


class AnalysisError(_Strict):
    severity: Literal["info", "warning", "error"]
    module: str | None = None
    message: str
    recoverable: bool | None = None


class Spectrum(_Strict):
    maasspec_version: Literal["0.1.0"] = SCHEMA_VERSION
    analysis_id: UUID
    generated_at: datetime
    tool: ToolInfo
    input: InputInfo
    summary: Summary | None = None
    findings: list[Finding]
    artifacts: list[Artifact] = Field(default_factory=list)
    errors: list[AnalysisError] = Field(default_factory=list)
    metadata: dict[str, Any] | None = None


class DraftFinding(_Strict):
    """What a module returns. The engine assigns id, module, and timestamp."""

    type: FindingType
    subtype: str | None = None
    value: Any = None
    normalized: Any = None
    confidence: float = Field(ge=0, le=1)
    confidence_method: str | None = None
    technique: str | None = None
    source: SourceRef | None = None
    context: dict[str, Any] | None = None
    selectors: list[Selector] = Field(default_factory=list)
    proposed_grade: ProposedGrade | None = None
    tags: list[str] = Field(default_factory=list)
    family_data: dict[str, Any] | None = None


def spectrum_json_schema() -> dict[str, Any]:
    schema = Spectrum.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_ID
    return schema
