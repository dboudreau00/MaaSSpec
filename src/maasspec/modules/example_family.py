"""Fixture family plugin.

This is the pattern a real extractor implements. It matches a documented
marker that exists only in tests and examples. It does not identify a
real malware family.
"""

from __future__ import annotations

from maasspec.context import AnalysisContext
from maasspec.models import DraftFinding, FamilySummary
from maasspec.modules.base import Module, ModuleOutput

MARKER = "MAASSPEC_FAMILY_EXAMPLE"


class ExampleFamilyModule(Module):
    name = "family.example"
    version = "0.3.1"

    def accepts(self, ctx: AnalysisContext) -> bool:
        return ctx.input_type != "cape_report"

    def run(self, ctx: AnalysisContext) -> ModuleOutput:
        if not any(MARKER in item for item in ctx.strings):
            return ModuleOutput()
        return ModuleOutput(
            family=FamilySummary(name="example", confidence=0.99, method="fixture_marker"),
            findings=[
                DraftFinding(
                    type="family_indicator",
                    subtype="fixture_marker",
                    value=MARKER,
                    confidence=0.99,
                    confidence_method="exact_marker",
                    technique="fixture_match",
                    tags=["fixture", "capability:example"],
                    family_data={"replace_this_module": True},
                    context={
                        "note": "Synthetic marker for the plugin contract. Not a malware family."
                    },
                )
            ],
        )
