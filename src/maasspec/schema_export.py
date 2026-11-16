"""Regenerate schema/spectrum.schema.json from the pydantic models."""

from __future__ import annotations

import json
from pathlib import Path

from maasspec.models import spectrum_json_schema


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    path = root / "schema" / "spectrum.schema.json"
    path.write_text(json.dumps(spectrum_json_schema(), indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
