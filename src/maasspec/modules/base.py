"""Module contract."""

from __future__ import annotations

from dataclasses import dataclass, field

from maasspec.context import AnalysisContext
from maasspec.models import AnalysisError, Artifact, DraftFinding, FamilySummary


@dataclass
class ModuleOutput:
    findings: list[DraftFinding] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[AnalysisError] = field(default_factory=list)
    family: FamilySummary | None = None


class Module:
    name = "module"
    version = "0.1.0"

    def accepts(self, ctx: AnalysisContext) -> bool:
        return True

    def run(self, ctx: AnalysisContext) -> ModuleOutput:
        raise NotImplementedError
