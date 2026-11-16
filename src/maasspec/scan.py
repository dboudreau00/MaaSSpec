"""Bounded reads. Hash the whole file; only a capped window is inspected."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

MAX_SCAN_BYTES = 8 * 1024 * 1024
STRING_MIN = 6
STRING_LIMIT = 4000
_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % STRING_MIN)


def hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def read_scan_window(path: Path, size: int) -> tuple[bytes, bool]:
    with path.open("rb") as handle:
        if size <= MAX_SCAN_BYTES:
            return handle.read(), False
        head = handle.read(MAX_SCAN_BYTES // 2)
        handle.seek(max(0, size - MAX_SCAN_BYTES // 2))
        tail = handle.read(MAX_SCAN_BYTES // 2)
        return head + tail, True


def extract_strings(data: bytes) -> tuple[list[str], bool]:
    found: list[str] = []
    truncated = False
    for match in _PRINTABLE.finditer(data):
        found.append(match.group().decode("ascii"))
        if len(found) >= STRING_LIMIT:
            truncated = True
            break
    return found, truncated


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * _log2(p)
    return entropy


def _log2(value: float) -> float:
    # math.log2 is fine; kept local so the entropy function stays obvious.
    import math

    return math.log2(value)
