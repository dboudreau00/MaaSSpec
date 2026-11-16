"""Bounded input and spectrum streams for the command line.

A stream is JSON Lines: one compact `Spectrum` per line. A single
pretty-printed spectrum file is accepted wherever a stream is.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO

from pydantic import ValidationError

from maasspec.feeds.base import MAX_IMPORT_BYTES
from maasspec.models import Spectrum


def read_input(source: str | Path | None, stdin: BinaryIO) -> bytes:
    """A path, or stdin for None and "-". Refuses anything over the import cap."""
    if source is None or str(source) == "-":
        data = stdin.read(MAX_IMPORT_BYTES + 1)
    else:
        with Path(source).open("rb") as handle:
            data = handle.read(MAX_IMPORT_BYTES + 1)
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError("Input exceeds the import size cap.")
    return data


def parse_spectra(data: bytes) -> Iterator[Spectrum]:
    text = data.decode("utf-8-sig").strip()
    if not text:
        return
    try:
        single = Spectrum.model_validate_json(text)
    except ValidationError:
        single = None
    if single is not None:
        yield single
        return
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            yield Spectrum.model_validate_json(line)
        except ValidationError as exc:
            raise ValueError(f"Line {number} is not a valid spectrum.") from exc


def spectra_jsonl(spectra: Iterable[Spectrum]) -> Iterator[bytes]:
    for spectrum in spectra:
        yield spectrum.model_dump_json().encode("utf-8") + b"\n"
