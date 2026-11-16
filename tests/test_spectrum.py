import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from maasspec.engine import analyze_path
from maasspec.ingest.noctornal import IngestClient, spectrum_ndjson
from maasspec.models import InputInfo, Spectrum, ToolInfo, spectrum_json_schema
from maasspec.modules.base import Module
from maasspec.modules.cape import CapeModule
from maasspec.modules.example_family import ExampleFamilyModule
from maasspec.modules.static import StaticModule

KEY = "noct_sk_live_" + "A1b2C3d4" * 4
STAMP = datetime(2026, 11, 16, tzinfo=UTC)
FIXTURE = b"""MAASSPEC_FAMILY_EXAMPLE
panel https://panel.example.test/gate.php
operator@example.test
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
127.0.0.1
"""


def _empty_spectrum(analysis_id: str, sha: str) -> Spectrum:
    return Spectrum(
        analysis_id=UUID(analysis_id),
        generated_at=STAMP,
        tool=ToolInfo(name="MaaSSpec", version="0.1.0"),
        input=InputInfo(type="sample", sha256=sha, size_bytes=1),
        findings=[],
    )


def test_sample_spectrum(tmp_path: Path) -> None:
    sample = tmp_path / "fixture.txt"
    sample.write_bytes(FIXTURE)
    analysis_id = UUID("11111111-1111-4111-8111-111111111111")
    spectrum = analyze_path(
        sample,
        analysis_id=analysis_id,
        now=STAMP,
        modules=[StaticModule(), CapeModule(), ExampleFamilyModule()],
    )

    Spectrum.model_validate(spectrum.model_dump())
    assert spectrum.input.sha256 == hashlib.sha256(FIXTURE).hexdigest()
    assert spectrum.summary is not None
    assert spectrum.summary.family is not None
    assert spectrum.summary.family.name == "example"
    assert "example" in spectrum.summary.primary_capabilities
    kinds = {(item.type, item.subtype) for item in spectrum.findings}
    assert ("c2", "url") in kinds
    assert ("credential_pattern", "email") in kinds
    assert ("wallet", "bitcoin") in kinds
    assert ("family_indicator", "fixture_marker") in kinds
    private = next(item for item in spectrum.findings if item.value == "127.0.0.1")
    assert private.confidence < 0.5
    assert "scope:private" in private.tags
    assert private.proposed_grade.information_credibility == "4"
    public = next(item for item in spectrum.findings if item.subtype == "url")
    assert public.proposed_grade.information_credibility == "2"
    assert all(item.extracted_by.module for item in spectrum.findings)


def test_cape_report_is_lower_confidence(tmp_path: Path) -> None:
    report = {
        "malfamily": "lumma",
        "network": {
            "hosts": [{"ip": "203.0.113.10", "hostname": "panel.example.test"}],
            "http": [{"uri": "https://panel.example.test/gate"}],
            "dns": [{"request": "panel.example.test"}],
        },
        "signatures": [{"name": "infostealer_behavior"}],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    spectrum = analyze_path(path)
    assert spectrum.input.type == "cape_report"
    assert spectrum.summary is not None
    assert spectrum.summary.family is not None
    assert spectrum.summary.family.method == "cape_malfamily"
    assert spectrum.summary.family.confidence == 0.5
    network = [item for item in spectrum.findings if "cape" in item.tags and item.type == "c2"]
    assert network
    assert all(item.confidence <= 0.45 for item in network)
    assert all(item.extracted_by.module != "family.example" for item in spectrum.findings)


def test_zip_lists_names_and_skips_traversal(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", b"hello")
        archive.writestr("../escape.txt", b"no")
    path = tmp_path / "bundle.zip"
    path.write_bytes(buffer.getvalue())
    spectrum = analyze_path(path)
    assert spectrum.input.type == "archive"
    names = [item.value for item in spectrum.findings if item.subtype == "archive_member"]
    assert names == ["readme.txt"]
    assert any("unsafe name" in error.message for error in spectrum.errors)


def test_a_failing_module_becomes_an_error_not_a_crash(tmp_path: Path) -> None:
    class Boom(Module):
        name = "boom"

        def run(self, ctx):
            raise RuntimeError("secret detail that must not be copied")

    sample = tmp_path / "fixture.txt"
    sample.write_bytes(FIXTURE)
    spectrum = analyze_path(sample, modules=[Boom()])
    Spectrum.model_validate(spectrum.model_dump())
    assert spectrum.findings == []
    failure = next(error for error in spectrum.errors if error.module == "boom")
    assert failure.severity == "error"
    assert "RuntimeError" in failure.message
    assert "secret detail" not in failure.message


def test_ndjson_has_no_graph_verbs() -> None:
    spectrum = _empty_spectrum("22222222-2222-4222-8222-222222222222", "ab" * 32)
    text = spectrum_ndjson(spectrum).decode()
    assert "maasspec.spectrum" in text
    assert "/attach" not in text
    assert "graph" not in text


def test_ingest_refuses_a_bad_key() -> None:
    with pytest.raises(ValueError, match="noct_sk_"):
        IngestClient("https://case.example.test", "not-a-key")
    with pytest.raises(ValueError, match="noct_sk_"):
        IngestClient("https://case.example.test", "noct_sk_live_example")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1.evil.example",
        "http://case.example.test",
        "https://user:pw@case.example.test",
        "https://case.example.test/?x=1",
        "ftp://case.example.test",
    ],
)
def test_ingest_refuses_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        IngestClient(url, KEY)


def test_ingest_allows_plain_http_on_loopback() -> None:
    assert IngestClient("http://127.0.0.1:8000", KEY).host == "127.0.0.1"


def test_ingest_posts_raw_bytes_only() -> None:
    spectrum = _empty_spectrum("33333333-3333-4333-8333-333333333333", "cd" * 32)
    captured = {}

    class _Response:
        def read(self, n=-1) -> bytes:
            return b'{"batch_id":"b1"}'

        def close(self) -> None:
            return None

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.method
        captured["auth"] = request.get_header("Authorization")
        captured["idem"] = request.get_header("Idempotency-key")
        captured["body"] = request.data
        captured["timeout"] = timeout
        return _Response()

    body = IngestClient("https://case.example.test", KEY).submit_spectrum(spectrum, opener=opener)
    assert body == b'{"batch_id":"b1"}'
    assert captured["url"] == "https://case.example.test/api/v1/ingest"
    assert captured["method"] == "POST"
    assert captured["auth"] == f"Bearer {KEY}"
    assert captured["idem"] == str(spectrum.analysis_id)
    assert b"maasspec_version" in captured["body"]
    assert b"\n" not in captured["body"]
    assert b"/attach" not in captured["body"]


def test_schema_file_matches_models() -> None:
    path = Path(__file__).resolve().parents[1] / "schema" / "spectrum.schema.json"
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk == spectrum_json_schema()


def _cape_findings(tmp_path: Path, report: dict) -> Spectrum:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return analyze_path(path)


def test_cape_network_to_a_private_address_is_scored_as_private(tmp_path: Path) -> None:
    spectrum = _cape_findings(
        tmp_path,
        {
            "network": {
                "hosts": [{"ip": "10.0.0.1"}, {"ip": "198.51.100.7"}, {"ip": "203.0.114.9"}],
                "http": [{"uri": "http://192.168.1.5/gate"}],
            }
        },
    )
    by_value = {item.value: item for item in spectrum.findings}
    for value in ("10.0.0.1", "http://192.168.1.5/gate"):
        row = by_value[value]
        assert row.confidence == 0.35
        assert "scope:private" in row.tags
        assert (row.proposed_grade.source_reliability, row.proposed_grade.information_credibility) == ("C", "4")
    public = by_value["203.0.114.9"]
    assert public.confidence == 0.45
    assert "scope:private" not in public.tags


def test_cape_network_rows_are_capped_per_kind_with_an_error_row(tmp_path: Path) -> None:
    hosts = [{"ip": f"203.0.{i // 250 + 114}.{i % 250 + 1}"} for i in range(450)]
    dns = [{"request": f"d{i}.example.test"} for i in range(5)]
    spectrum = _cape_findings(tmp_path, {"network": {"hosts": hosts, "dns": dns}})
    ips = [f for f in spectrum.findings if f.subtype == "ipv4"]
    assert len(ips) == 200
    assert len([f for f in spectrum.findings if f.subtype == "domain"]) == 5
    assert [e for e in spectrum.errors if e.module == "cape" and "cap" in e.message and "ipv4" in e.message]


def test_a_json_object_with_a_bare_behavior_key_is_not_a_cape_report(tmp_path: Path) -> None:
    for document in (
        {"behavior": "unrelated", "note": "http://example.test/a"},
        {"network": 5},
        {"signatures": [], "behavior": {}},
        {"CAPE": "x"},
    ):
        assert _cape_findings(tmp_path, document).input.type == "sample"
    shaped = _cape_findings(tmp_path, {"behavior": {"processes": [{"pid": 1}]}})
    assert shaped.input.type == "cape_report"


def test_the_example_family_is_not_on_the_default_pipeline(tmp_path: Path) -> None:
    from maasspec.engine import default_modules

    assert "family.example" not in {module.name for module in default_modules()}
    sample = tmp_path / "fixture.txt"
    sample.write_bytes(FIXTURE)
    spectrum = analyze_path(sample)
    assert spectrum.summary is not None
    assert spectrum.summary.family is None
    assert not [f for f in spectrum.findings if f.subtype == "fixture_marker"]


def test_the_example_family_still_runs_when_passed_explicitly(tmp_path: Path) -> None:
    sample = tmp_path / "fixture.txt"
    sample.write_bytes(FIXTURE)
    spectrum = analyze_path(sample, modules=[StaticModule(), ExampleFamilyModule()])
    assert spectrum.summary.family is not None and spectrum.summary.family.name == "example"
