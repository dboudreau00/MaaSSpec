"""Shared view of one analysis input. Modules must not execute it."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AnalysisContext:
    path: Path
    filename: str
    data_for_scan: bytes
    sha256: str
    size_bytes: int
    input_type: str
    truncated: bool = False
    strings: list[str] = field(default_factory=list)
    parsed_json: dict | list | None = None
