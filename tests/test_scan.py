import struct
import zipfile
from pathlib import Path

from maasspec.engine import analyze_path
from maasspec.scan import MAX_SCAN_BYTES

HALF = MAX_SCAN_BYTES // 2


def _values(spectrum) -> set[str]:
    return {str(finding.value) for finding in spectrum.findings}


def test_a_selector_that_exists_only_on_the_seam_is_not_emitted(tmp_path: Path) -> None:
    middle = b"\x00" * (MAX_SCAN_BYTES // 2)
    head = b"\x00" * (HALF - 11) + b"http://exam"
    tail = b"ple.test/x" + b"\x00" * (HALF - 10)
    sample = tmp_path / "big.bin"
    sample.write_bytes(head + middle + tail)
    spectrum = analyze_path(sample)
    assert spectrum.metadata["scan_window_truncated"] is True
    assert not any("example.test" in value for value in _values(spectrum))
    assert not any(value.startswith("http://exam") for value in _values(spectrum))


def test_a_selector_wholly_inside_one_half_is_still_found(tmp_path: Path) -> None:
    head = b"\x00" * 64 + b"http://inside.example.test/a" + b"\x00" * (HALF - 64 - 28)
    sample = tmp_path / "big.bin"
    sample.write_bytes(head + b"\x00" * HALF + b"\x00" * HALF)
    assert "http://inside.example.test/a" in _values(analyze_path(sample))


def test_a_valid_zip_larger_than_the_scan_window_has_its_members_listed(tmp_path: Path) -> None:
    # 150 members with 40 KB extra fields in both headers: a central directory of about 6 MB,
    # larger than the 4 MiB tail of the scan window, so a spliced buffer cannot hold it.
    extra = struct.pack("<HH", 0xCAFE, 40000) + bytes(40000)
    path = tmp_path / "big.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        for index in range(150):
            info = zipfile.ZipInfo(f"member_{index:03d}.txt")
            info.extra = extra
            archive.writestr(info, b"x")
    assert path.stat().st_size > MAX_SCAN_BYTES
    spectrum = analyze_path(path)
    members = [f.value for f in spectrum.findings if f.subtype == "archive_member"]
    assert len(members) == 50
    assert members[0] == "member_000.txt"
    assert not [e for e in spectrum.errors if "did not parse" in e.message]
    assert [e for e in spectrum.errors if "Listed 50 of 150" in e.message]


def test_zip_members_with_drive_or_unc_names_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "names.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name in ("ok.txt", "C:/Windows/x.dll", "d:evil.dll", r"\\srv\share\x","//srv/share/y", "a/../b"):
            archive.writestr(zipfile.ZipInfo(name), b"x")
    spectrum = analyze_path(path)
    assert [f.value for f in spectrum.findings if f.subtype == "archive_member"] == ["ok.txt"]
    assert len([e for e in spectrum.errors if "unsafe name" in e.message]) == 5
